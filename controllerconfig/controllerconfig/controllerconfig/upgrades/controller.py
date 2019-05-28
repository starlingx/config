#
# Copyright (c) 2016-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

#
# This file contains functions used to upgrade controller-1
#

import copy
import glob
import json
import psycopg2
import os
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import yaml


from sysinv.common import constants as sysinv_constants


# WARNING: The controller-1 upgrade is done before any puppet manifests
# have been applied, so only the static entries from tsconfig can be used
# (the platform.conf file will not have been updated with dynamic values).
from tsconfig.tsconfig import SW_VERSION
from tsconfig.tsconfig import PLATFORM_PATH
from tsconfig.tsconfig import KEYRING_PATH
from tsconfig.tsconfig import PLATFORM_CONF_FILE
from tsconfig.tsconfig import CGCS_PATH
from tsconfig.tsconfig import CONFIG_PATH
from tsconfig.tsconfig import CONTROLLER_UPGRADE_FLAG
from tsconfig.tsconfig import CONTROLLER_UPGRADE_COMPLETE_FLAG
from tsconfig.tsconfig import CONTROLLER_UPGRADE_FAIL_FLAG
from tsconfig.tsconfig import CONTROLLER_UPGRADE_STARTED_FLAG
from tsconfig.tsconfig import RESTORE_IN_PROGRESS_FLAG

from controllerconfig.common import constants
from controllerconfig.common import log
from controllerconfig import utils as cutils
from controllerconfig import backup_restore

from controllerconfig.upgrades import utils

LOG = log.get_logger(__name__)

POSTGRES_MOUNT_PATH = '/mnt/postgresql'
POSTGRES_DUMP_MOUNT_PATH = '/mnt/db_dump'
DB_CONNECTION_FORMAT = "connection=postgresql://%s:%s@127.0.0.1/%s\n"

restore_patching_complete = '/etc/platform/.restore_patching_complete'
restore_compute_ready = '/var/run/.restore_compute_ready'
node_is_patched = '/var/run/node_is_patched'
patching_permdir = '/opt/patching'
patching_repo_permdir = '/www/pages/updates'


def gethostaddress(hostname):
    """ Get the IP address for a hostname, supporting IPv4 and IPv6. """
    return socket.getaddrinfo(hostname, None)[0][4][0]


def get_db_credentials(shared_services, from_release):
    """
    Returns the database credentials using the provided shared services.
    """
    db_credential_keys = \
        {'barbican': {'hiera_user_key': 'barbican::db::postgresql::user',
                      'keyring_password_key': 'barbican',
                      },
         'ceilometer': {'hiera_user_key': 'ceilometer::db::postgresql::user',
                        'keyring_password_key': 'ceilometer',
                        },
         'heat': {'hiera_user_key': 'heat::db::postgresql::user',
                  'keyring_password_key': 'heat',
                  },
         'neutron': {'hiera_user_key': 'neutron::db::postgresql::user',
                     'keyring_password_key': 'neutron',
                     },
         'nova': {'hiera_user_key': 'nova::db::postgresql::user',
                  'keyring_password_key': 'nova',
                  },
         'nova_api': {'hiera_user_key': 'nova::db::postgresql_api::user',
                      'keyring_password_key': 'nova-api',
                      },
         'sysinv': {'hiera_user_key': 'sysinv::db::postgresql::user',
                    'keyring_password_key': 'sysinv',
                    },
         'magnum': {'hiera_user_key': 'magnum::db::postgresql::user',
                    'keyring_password_key': 'magnum',
                    },
         'ironic': {'hiera_user_key': 'ironic::db::postgresql::user',
                    'keyring_password_key': 'ironic',
                    },
         }

    if sysinv_constants.SERVICE_TYPE_VOLUME not in shared_services:
        db_credential_keys.update(
            {'cinder': {'hiera_user_key': 'cinder::db::postgresql::user',
                        'keyring_password_key': 'cinder',
                        }})

    if sysinv_constants.SERVICE_TYPE_IMAGE not in shared_services:
        db_credential_keys.update(
            {'glance': {'hiera_user_key': 'glance::db::postgresql::user',
                        'keyring_password_key': 'glance',
                        }})

    if sysinv_constants.SERVICE_TYPE_IDENTITY not in shared_services:
        db_credential_keys.update(
            {'keystone': {'hiera_user_key':
                          'keystone::db::postgresql::user',
                          'keyring_password_key': 'keystone',
                          }})

    # Get the hiera data for the from release
    hiera_path = os.path.join(PLATFORM_PATH, "puppet", from_release,
                              "hieradata")
    static_file = os.path.join(hiera_path, "static.yaml")
    with open(static_file, 'r') as file:
        static_config = yaml.load(file)

    db_credentials = dict()
    for database, values in db_credential_keys.items():
        username = static_config[values['hiera_user_key']]
        password = utils.get_password_from_keyring(
            values['keyring_password_key'], "database")
        db_credentials[database] = {'username': username, 'password': password}

    return db_credentials


def get_shared_services():
    """ Get the list of shared services from the sysinv database """
    shared_services = []
    DEFAULT_SHARED_SERVICES = []

    conn = psycopg2.connect("dbname=sysinv user=postgres")
    cur = conn.cursor()
    cur.execute("select capabilities from i_system;")
    row = cur.fetchone()
    if row is None:
        LOG.error("Failed to fetch i_system data")
        raise psycopg2.ProgrammingError("Failed to fetch i_system data")
    cap_obj = json.loads(row[0])
    region_config = cap_obj.get('region_config', None)
    if region_config:
        shared_services = cap_obj.get('shared_services',
                                      DEFAULT_SHARED_SERVICES)

    return shared_services


def get_connection_string(db_credentials, database):
    """ Generates a connection string for a given database"""
    username = db_credentials[database]['username']
    password = db_credentials[database]['password']
    return DB_CONNECTION_FORMAT % (username, password, database)


def create_temp_filesystem(vgname, lvname, mountpoint, size):
    """ Creates and mounts a logical volume for temporary use. """
    devnull = open(os.devnull, 'w')

    try:
        subprocess.check_call(
            ["lvcreate",
             "--size",
             size,
             "-n",
             lvname,
             vgname],
            close_fds=True,
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to create %s" % lvname)
        raise

    devname = '/dev/%s/%s' % (vgname, lvname)
    try:
        subprocess.check_call(
            ["mkfs.ext4",
             devname],
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to format %s" % devname)
        raise

    try:
        subprocess.check_call(
            ["mount",
             devname,
             mountpoint,
             "-t",
             "ext4"],
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to mount %s at %s" % (devname, mountpoint))
        raise


def remove_temp_filesystem(vgname, lvname, mountpoint):
    """ Unmounts and removes a logical volume. """
    devnull = open(os.devnull, 'w')

    try:
        subprocess.check_call(
            ["umount",
             mountpoint],
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to umount %s" % mountpoint)

    try:
        subprocess.check_call(
            ["lvremove",
             "-f",
             "%s/%s" % (vgname, lvname)],
            close_fds=True,
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to remove %s" % lvname)


def nfs_mount_filesystem(filesystem, mountdir=None):
    """ Mounts a remote nfs filesystem. """
    devnull = open(os.devnull, 'w')
    if not mountdir:
        mountdir = filesystem
    try:
        subprocess.check_call(
            ["nfs-mount",
             "controller-platform-nfs:%s" % filesystem,
             mountdir],
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to nfs-mount %s at %s" % (filesystem, mountdir))
        raise


def unmount_filesystem(filesystem):
    """ Unmounts a remote nfs filesystem. """
    devnull = open(os.devnull, 'w')
    try:
        subprocess.check_call(
            ["umount",
             filesystem],
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to umount %s" % filesystem)


def migrate_keyring_data(from_release, to_release):
    """ Migrates keyring data. """

    LOG.info("Migrating keyring data")
    # First delete any keyring files for the to_release - they can be created
    # if release N+1 nodes are incorrectly left powered up when the release N
    # load is installed.
    shutil.rmtree(os.path.join(PLATFORM_PATH, ".keyring", to_release),
                  ignore_errors=True)
    shutil.copytree(os.path.join(PLATFORM_PATH, ".keyring", from_release),
                    os.path.join(PLATFORM_PATH, ".keyring", to_release))


def migrate_pxeboot_config(from_release, to_release):
    """ Migrates pxeboot configuration. """
    devnull = open(os.devnull, 'w')

    LOG.info("Migrating pxeboot config")

    # Copy the entire pxelinux.cfg directory to pick up any changes made
    # after the data was migrated (i.e. updates to the controller-1 load).
    source_pxelinux = os.path.join(PLATFORM_PATH, "config", from_release,
                                   "pxelinux.cfg")
    dest_pxelinux = os.path.join(PLATFORM_PATH, "config", to_release,
                                 "pxelinux.cfg")
    shutil.rmtree(dest_pxelinux)
    try:
        subprocess.check_call(
            ["cp",
             "-a",
             os.path.join(source_pxelinux),
             os.path.join(dest_pxelinux)],
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to migrate %s" % source_pxelinux)
        raise


def migrate_sysinv_data(from_release, to_release):
    """ Migrates sysinv data. """
    devnull = open(os.devnull, 'w')

    LOG.info("Migrating sysinv data")

    # If the /opt/platform/sysinv/<release>/sysinv.conf.default file has
    # changed between releases it must be modified at this point.
    try:
        subprocess.check_call(
            ["cp",
             "-R",
             "--preserve",
             os.path.join(PLATFORM_PATH, "sysinv", from_release),
             os.path.join(PLATFORM_PATH, "sysinv", to_release)],
            stdout=devnull)

    except subprocess.CalledProcessError:
        LOG.exception("Failed to copy sysinv platform dir to new version")
        raise

    # Get the hiera data for the from release
    hiera_path = os.path.join(PLATFORM_PATH, "puppet", from_release,
                              "hieradata")
    static_file = os.path.join(hiera_path, "static.yaml")
    with open(static_file, 'r') as file:
        static_config = yaml.load(file)

    username = static_config["sysinv::db::postgresql::user"]
    password = utils.get_password_from_keyring("sysinv", "database")

    # We need a bare bones /etc/sysinv/sysinv.conf file in order to do the
    # sysinv database migration and then generate the upgrades manifests.
    with open("/etc/sysinv/sysinv.conf", "w") as f:
        f.write("[DEFAULT]\n")
        f.write("logging_context_format_string=sysinv %(asctime)s.%"
                "(msecs)03d %(process)d %(levelname)s %"
                "(name)s [%(request_id)s %(user)s %"
                "(tenant)s] %(instance)s%(message)s\n")
        f.write("verbose=True\n")
        f.write("syslog_log_facility=local6\n")
        f.write("use_syslog=True\n")
        f.write("logging_default_format_string=sysinv %(asctime)s.%"
                "(msecs)03d %(process)d %(levelname)s %(name)s [-] %"
                "(instance)s%(message)s\n")
        f.write("debug=False\n")
        f.write('sql_connection=postgresql://%s:%s@127.0.0.1/%s\n' %
                (username, password, 'sysinv'))


def prepare_postgres_filesystems():
    """ Prepares postgres filesystems for migration. """
    devnull = open(os.devnull, 'w')

    LOG.info("Preparing postgres filesystems")

    # In order to avoid the speed penalty for doing database operations on an
    # nfs mounted filesystem, we create the databases locally and then copy
    # them to the nfs mounted filesystem after data migration.

    # Create a temporary filesystem for the dumped database
    from_dir = os.path.join(POSTGRES_MOUNT_PATH, "upgrade")
    stat = os.statvfs(from_dir)
    db_dump_filesystem_size = str(stat.f_frsize * stat.f_blocks) + "B"

    # Move the dumped files to a temporary filesystem.
    os.mkdir(POSTGRES_DUMP_MOUNT_PATH)
    create_temp_filesystem("cgts-vg", "dbdump-temp-lv",
                           POSTGRES_DUMP_MOUNT_PATH,
                           db_dump_filesystem_size)
    shutil.move(from_dir, POSTGRES_DUMP_MOUNT_PATH)

    # Create a temporary filesystem for the migrated database
    stat = os.statvfs(POSTGRES_MOUNT_PATH)
    db_filesystem_size = str(stat.f_frsize * stat.f_blocks) + "B"
    os.mkdir(utils.POSTGRES_PATH)
    create_temp_filesystem("cgts-vg", "postgres-temp-lv", utils.POSTGRES_PATH,
                           db_filesystem_size)
    subprocess.check_call(['chown', 'postgres:postgres', utils.POSTGRES_PATH],
                          stdout=devnull)


def create_database():
    """ Creates empty postgres database. """

    devnull = open(os.devnull, 'w')

    LOG.info("Creating postgres database")

    db_create_commands = [
        # Configure new data directory for postgres
        'sudo -u postgres initdb -D ' + utils.POSTGRES_DATA_DIR,
        'chmod -R 700 ' + utils.POSTGRES_DATA_DIR,
        'chown -R postgres ' + utils.POSTGRES_DATA_DIR,
    ]

    # Execute db creation commands
    for cmd in db_create_commands:
        try:
            LOG.info("Executing db create command: %s" % cmd)
            subprocess.check_call([cmd],
                                  shell=True, stdout=devnull, stderr=devnull)
        except subprocess.CalledProcessError as ex:
            LOG.exception("Failed to execute command: '%s' during upgrade "
                          "processing, return code: %d" % (cmd, ex.returncode))
            raise


def import_databases(from_release, to_release, from_path=None, simplex=False):
    """ Imports databases. """

    devnull = open(os.devnull, 'w')
    if not from_path:
        from_path = POSTGRES_DUMP_MOUNT_PATH
    from_dir = os.path.join(from_path, "upgrade")

    LOG.info("Importing databases")

    try:
        # Do postgres schema import (suppress stderr due to noise)
        subprocess.check_call(['sudo -u postgres psql -f ' + from_dir +
                               '/postgres.sql.config postgres'],
                              shell=True,
                              stdout=devnull,
                              stderr=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to import schemas.")
        raise

    import_commands = []

    # Do postgres data import
    for data in glob.glob(from_dir + '/*.sql.data'):
        db_elem = data.split('/')[-1].split('.')[0]
        import_commands.append((db_elem,
                                "sudo -u postgres psql -f " + data +
                                " " + db_elem))

    # Import VIM data
    if not simplex:
        import_commands.append(
            ("nfv-vim",
             "nfv-vim-manage db-load-data -d %s -f %s" %
             (os.path.join(PLATFORM_PATH, 'nfv/vim', SW_VERSION),
              os.path.join(from_dir, 'vim.data'))))

    # Execute import commands
    for cmd in import_commands:
        try:
            print("Importing %s" % cmd[0])
            LOG.info("Executing import command: %s" % cmd[1])
            subprocess.check_call([cmd[1]],
                                  shell=True, stdout=devnull)

        except subprocess.CalledProcessError as ex:
            LOG.exception("Failed to execute command: '%s' during upgrade "
                          "processing, return code: %d" %
                          (cmd[1], ex.returncode))
            raise


def create_databases(from_release, to_release, db_credentials):
    """ Creates databases. """
    LOG.info("Creating new databases")

    if from_release == '18.03':
        # Create databases that are new in this release

        conn = psycopg2.connect('dbname=postgres user=postgres')

        # Postgres won't allow transactions around database create operations
        # so we set the connection to autocommit
        conn.set_isolation_level(
            psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)

        databases_to_create = []
        if not databases_to_create:
            return

        with conn:
            with conn.cursor() as cur:
                for database in databases_to_create:
                    print("Creating %s database" % database)
                    username = psycopg2.extensions.AsIs(
                        '\"%s\"' % db_credentials[database]['username'])
                    db_name = psycopg2.extensions.AsIs('\"%s\"' % database)
                    password = db_credentials[database]['password']

                    try:
                        # Here we create the new database and the role for it
                        # The role will be used by the dbsync command to
                        # connect to the database. This ensures any new tables
                        # are added with the correct owner
                        cur.execute('CREATE DATABASE %s', (db_name,))
                        cur.execute('CREATE ROLE %s', (username,))
                        cur.execute('ALTER ROLE %s LOGIN PASSWORD %s',
                                    (username, password))
                        cur.execute('GRANT ALL ON DATABASE %s TO %s',
                                    (db_name, username))
                    except Exception as ex:
                        LOG.exception("Failed to create database and role. " +
                                      "(%s : %s) Exception: %s" %
                                      (database, username, ex))
                        raise


def migrate_sysinv_database():
    """ Migrates the sysinv database. """
    devnull = open(os.devnull, 'w')

    sysinv_cmd = 'sysinv-dbsync'
    try:
        print("Migrating sysinv")
        LOG.info("Executing migrate command: %s" % sysinv_cmd)
        subprocess.check_call([sysinv_cmd],
                              shell=True, stdout=devnull, stderr=devnull)

    except subprocess.CalledProcessError as ex:
        LOG.exception("Failed to execute command: '%s' during upgrade "
                      "processing, return code: %d"
                      % (sysinv_cmd, ex.returncode))
        raise


def migrate_databases(from_release, shared_services, db_credentials,
                      simplex=False):
    """ Migrates databases. """

    devnull = open(os.devnull, 'w')

    # Create minimal config files for each OpenStack service so they can
    # run their database migration.
    with open("/etc/ceilometer/ceilometer-dbsync.conf", "w") as f:
        f.write("[database]\n")
        f.write(get_connection_string(db_credentials, 'ceilometer'))

    with open("/etc/heat/heat-dbsync.conf", "w") as f:
        f.write("[database]\n")
        f.write(get_connection_string(db_credentials, 'heat'))

    with open("/etc/neutron/neutron-dbsync.conf", "w") as f:
        f.write("[database]\n")
        f.write(get_connection_string(db_credentials, 'neutron'))

    with open("/etc/nova/nova-dbsync.conf", "w") as f:
        f.write("[database]\n")
        f.write(get_connection_string(db_credentials, 'nova'))
        f.write("[api_database]\n")
        f.write(get_connection_string(db_credentials, 'nova_api'))

    with open("/etc/magnum/magnum-dbsync.conf", "w") as f:
        f.write("[database]\n")
        f.write(get_connection_string(db_credentials, 'magnum'))

    with open("/etc/ironic/ironic-dbsync.conf", "w") as f:
        f.write("[database]\n")
        f.write(get_connection_string(db_credentials, 'ironic'))

    if sysinv_constants.SERVICE_TYPE_VOLUME not in shared_services:
        with open("/etc/cinder/cinder-dbsync.conf", "w") as f:
            f.write("[database]\n")
            f.write(get_connection_string(db_credentials, 'cinder'))

    if sysinv_constants.SERVICE_TYPE_IMAGE not in shared_services:
        with open("/etc/glance/glance-dbsync.conf", "w") as f:
            f.write("[database]\n")
            f.write(get_connection_string(db_credentials, 'glance'))

    if sysinv_constants.SERVICE_TYPE_IDENTITY not in shared_services:
        with open("/etc/keystone/keystone-dbsync.conf", "w") as f:
            f.write("[database]\n")
            f.write(get_connection_string(db_credentials, 'keystone'))

    with open("/etc/barbican/barbican-dbsync.conf", "w") as f:
        f.write("[database]\n")
        f.write(get_connection_string(db_credentials, 'barbican'))

    migrate_commands = [
        # Migrate barbican
        ('barbican',
         'barbican-manage --config-file /etc/barbican/barbican-dbsync.conf ' +
         'db upgrade'),
        # Migrate ceilometer
        ('ceilometer',
         'ceilometer-upgrade --skip-gnocchi-resource-types --config-file ' +
         '/etc/ceilometer/ceilometer-dbsync.conf'),
        # Migrate heat
        ('heat',
         'heat-manage --config-file /etc/heat/heat-dbsync.conf db_sync'),
        # Migrate neutron
        ('neutron',
         'neutron-db-manage --config-file /etc/neutron/neutron-dbsync.conf ' +
         'upgrade heads'),
        # Migrate nova
        ('nova',
         'nova-manage --config-file /etc/nova/nova-dbsync.conf db sync'),
        # Migrate nova_api (new in R3)
        ('nova',
         'nova-manage --config-file /etc/nova/nova-dbsync.conf api_db sync'),
        # Migrate magnum (new in R5)
        ('magnum',
         'magnum-db-manage --config-file /etc/magnum/magnum-dbsync.conf ' +
         'upgrade'),
        # Migrate ironic (new in R5)
        ('ironic',
         'ironic-dbsync --config-file /etc/ironic/ironic-dbsync.conf ' +
         'upgrade'),

    ]

    if sysinv_constants.SERVICE_TYPE_VOLUME not in shared_services:
        migrate_commands += [
            # Migrate cinder to latest version
            ('cinder',
             'cinder-manage --config-file /etc/cinder/cinder-dbsync.conf ' +
             'db sync'),
        ]

    if sysinv_constants.SERVICE_TYPE_IMAGE not in shared_services:
        migrate_commands += [
            # Migrate glance database and metadata
            ('glance',
             'glance-manage --config-file /etc/glance/glance-dbsync.conf ' +
             'db sync'),
            ('glance',
             'glance-manage --config-file /etc/glance/glance-dbsync.conf ' +
             'db_load_metadefs'),
        ]

    if sysinv_constants.SERVICE_TYPE_IDENTITY not in shared_services:
        # To avoid a deadlock during keystone contract we will use offline
        # migration for simplex upgrades. Other upgrades will have to use
        # another method to resolve the deadlock
        if not simplex:
            migrate_commands += [
                # Migrate keystone
                #
                # EXPAND - we will first expand the database scheme to a
                # superset of what both the previous and next release can
                # utilize, and create triggers to facilitate the live
                # migration process.
                #
                # MIGRATE - will perform the data migration, while still]
                # preserving the old schema
                ('keystone',
                 'keystone-manage --config-file ' +
                 '/etc/keystone/keystone-dbsync.conf db_sync --expand'),
                ('keystone',
                 'keystone-manage --config-file ' +
                 '/etc/keystone/keystone-dbsync.conf db_sync --migrate'),
            ]
        else:
            migrate_commands += [
                # In simplex we're the only node so we can do an offline
                # migration
                ('keystone',
                 'keystone-manage --config-file ' +
                 '/etc/keystone/keystone-dbsync.conf db_sync')
            ]

    # Execute migrate commands
    for cmd in migrate_commands:
        try:
            print("Migrating %s" % cmd[0])
            LOG.info("Executing migrate command: %s" % cmd[1])
            subprocess.check_call([cmd[1]],
                                  shell=True, stdout=devnull, stderr=devnull)

        except subprocess.CalledProcessError as ex:
            LOG.exception("Failed to execute command: '%s' during upgrade "
                          "processing, return code: %d" %
                          (cmd[1], ex.returncode))
            raise

    # We need to run nova's online DB migrations to complete any DB changes.
    # This needs to be done before the computes are upgraded. In other words
    # as controller-1 is being upgraded
    try:
        output = subprocess.check_output(
            ['nova-manage', '--config-file', '/etc/nova/nova-dbsync.conf',
             'db', 'online_data_migrations'])
        if 'Error' in output:
            LOG.exception("Error detected running nova "
                          "online_data_migrations. Output %s", output)
            raise Exception("Error detected running nova "
                            "online_data_migrations.")
        else:
            LOG.info(
                "Done running nova online_data_migrations. Output: %s", output)
    except subprocess.CalledProcessError as e:
        LOG.exception("Nonzero return value running nova "
                      "online_data_migrations.  Output: %s", e.output)
        raise

    # The database entry for controller-1 will be set to whatever it was when
    # the sysinv database was dumped on controller-0. Update the state and
    # from/to load to what it should be when it becomes active.
    try:
        subprocess.check_call(
            ["/usr/bin/sysinv-upgrade",
             "update_controller_state"],
            stdout=devnull, stderr=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to update state of %s" %
                      utils.CONTROLLER_1_HOSTNAME)
        raise


def get_controller_1_uuid():
    """ Read in the uuid from the sysinv db"""
    conn = psycopg2.connect("dbname=sysinv user=postgres")
    with conn:
        with conn.cursor() as cur:
            cur.execute("select uuid from i_host where hostname="
                        "'controller-1';")
            row = cur.fetchone()
            if row is None:
                LOG.error("Failed to fetch controller-1 uuid")
                raise Exception("Error reading controller UUID")

            return row[0]


def update_platform_conf_file(uuid):
    """ Update the platform conf file with the uuid
        This is needed for the compute_huge script to update the CPU
        allocations
    """
    if os.path.isfile(PLATFORM_CONF_FILE):
        # read the platform config file and check for UUID
        with open(PLATFORM_CONF_FILE, "r") as fd:
            for line in fd:
                if line.find("UUID=") == 0:
                    LOG.info("Found UUID in platform.conf: %s" % line)
                    return

        # the UUID is not found, append it
        LOG.info("Appending UUID to platform.conf. UUID: %s" % uuid)
        with open(PLATFORM_CONF_FILE, "a") as fd:
            fd.write("UUID=" + uuid + "\n")


def migrate_hiera_data(from_release, to_release):
    """ Migrate hiera data. """

    LOG.info("Migrating hiera data")
    from_hiera_path = os.path.join(PLATFORM_PATH, "puppet", from_release,
                                   "hieradata")
    to_hiera_path = constants.HIERADATA_PERMDIR
    os.makedirs(to_hiera_path)

    # Copy only the static yaml files. The other yaml files will be generated
    # when required.
    for f in ['secure_static.yaml', 'static.yaml']:
        shutil.copy(os.path.join(from_hiera_path, f), to_hiera_path)

    # Make any necessary updates to the static yaml files.
    if from_release == "18.03":
        # Update the static.yaml file
        static_file = os.path.join(constants.HIERADATA_PERMDIR, "static.yaml")
        with open(static_file, 'r') as yaml_file:
            static_config = yaml.load(yaml_file)
        static_config.update({
            'platform::params::software_version': SW_VERSION,
            'platform::client::credentials::params::keyring_directory':
                KEYRING_PATH,
            'platform::client::credentials::params::keyring_file':
                os.path.join(KEYRING_PATH, '.CREDENTIAL'),
        })
        with open(static_file, 'w') as yaml_file:
            yaml.dump(static_config, yaml_file, default_flow_style=False)


def upgrade_controller(from_release, to_release):
    """ Executed on the release N+1 side upgrade controller-1. """

    if from_release == to_release:
        raise Exception("Cannot upgrade from release %s to the same "
                        "release %s." % (from_release, to_release))

    devnull = open(os.devnull, 'w')

    LOG.info("Upgrading controller from %s to %s" % (from_release, to_release))

    # Stop sysinv-agent so it doesn't interfere
    LOG.info("Stopping sysinv-agent")
    try:
        subprocess.check_call(["systemctl", "stop", "sysinv-agent"],
                              stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.error("Failed to stop %s service" % "sysinv-agent")
        raise

    # Mount required filesystems from mate controller
    LOG.info("Mounting filesystems")
    nfs_mount_filesystem(PLATFORM_PATH)
    os.mkdir(CGCS_PATH)
    nfs_mount_filesystem(CGCS_PATH)
    nfs_mount_filesystem(utils.RABBIT_PATH)
    os.mkdir(POSTGRES_MOUNT_PATH)
    nfs_mount_filesystem(utils.POSTGRES_PATH, POSTGRES_MOUNT_PATH)

    # Migrate keyring data
    print("Migrating keyring data...")
    migrate_keyring_data(from_release, to_release)

    # Migrate pxeboot config
    print("Migrating pxeboot configuration...")
    migrate_pxeboot_config(from_release, to_release)

    # Migrate sysinv data.
    print("Migrating sysinv configuration...")
    migrate_sysinv_data(from_release, to_release)

    # Prepare for database migration
    print("Preparing for database migration...")
    prepare_postgres_filesystems()

    # Create the postgres database
    create_database()

    # Start the postgres server
    try:
        subprocess.check_call(['sudo',
                               '-u',
                               'postgres',
                               'pg_ctl',
                               '-D',
                               utils.POSTGRES_DATA_DIR,
                               'start'],
                              stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to start postgres service")
        raise

    # Wait for postgres to start
    # TODO: Make this deterministic (use wait_service?)
    time.sleep(5)

    # Import databases
    print("Importing databases...")
    import_databases(from_release, to_release)

    shared_services = get_shared_services()

    # Create /tmp/python_keyring - used by keystone manifest.
    shutil.copytree(os.path.join(PLATFORM_PATH, ".keyring", to_release,
                                 "python_keyring"),
                    "/tmp/python_keyring")

    # Migrate hiera data
    migrate_hiera_data(from_release, to_release)
    utils.add_upgrade_entries_to_hiera_data(from_release)

    # Get database credentials
    db_credentials = get_db_credentials(shared_services, from_release)

    # Create any new databases
    print("Creating new databases...")
    create_databases(from_release, to_release, db_credentials)

    print("Migrating databases...")
    # Migrate sysinv database
    migrate_sysinv_database()

    # Migrate databases
    migrate_databases(from_release, shared_services, db_credentials)

    print("Applying configuration...")

    # Execute migration scripts
    utils.execute_migration_scripts(
        from_release, to_release, utils.ACTION_MIGRATE)

    uuid = get_controller_1_uuid()

    update_platform_conf_file(uuid)

    # Stop postgres server
    try:
        subprocess.check_call(['sudo',
                               '-u',
                               'postgres',
                               'pg_ctl',
                               '-D',
                               utils.POSTGRES_DATA_DIR,
                               'stop'],
                              stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to stop postgres service")
        raise

    # Apply "upgrades" manifest
    LOG.info("Applying upgrades manifest")
    myip = gethostaddress(utils.CONTROLLER_1_HOSTNAME)
    utils.apply_upgrade_manifest(myip)

    # Remove manifest and keyring files
    shutil.rmtree("/tmp/puppet")
    shutil.rmtree("/tmp/python_keyring")

    # Generate config to be used by "regular" manifest
    LOG.info("Generating config for %s" % utils.CONTROLLER_1_HOSTNAME)
    try:
        cutils.create_system_config()
        cutils.create_host_config(utils.CONTROLLER_1_HOSTNAME)
    except Exception as e:
        LOG.exception(e)
        LOG.info("Failed to update hiera configuration")
        raise

    print("Shutting down upgrade processes...")

    # Stop postgres service
    LOG.info("Stopping postgresql service")
    try:
        subprocess.check_call(["systemctl", "stop", "postgresql"],
                              stdout=devnull)

    except subprocess.CalledProcessError:
        LOG.exception("Failed to stop postgresql service")
        raise

    # Stop rabbitmq-server service
    LOG.info("Stopping rabbitmq-server service")
    try:
        subprocess.check_call(["systemctl", "stop", "rabbitmq-server"],
                              stdout=devnull)

    except subprocess.CalledProcessError:
        LOG.exception("Failed to stop rabbitmq-server service")
        raise

    # Copy upgraded database back to controller-0
    print("Writing upgraded databases...")
    LOG.info("Copying upgraded database to controller-0")
    try:
        subprocess.check_call(
            ["cp",
             "-a",
             os.path.join(utils.POSTGRES_PATH, to_release),
             os.path.join(POSTGRES_MOUNT_PATH, to_release)],
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception(
            "Failed to copy migrated postgres database to controller-0")
        raise

    # Remove temporary filesystems
    remove_temp_filesystem("cgts-vg", "dbdump-temp-lv",
                           POSTGRES_DUMP_MOUNT_PATH)
    remove_temp_filesystem("cgts-vg", "postgres-temp-lv", utils.POSTGRES_PATH)

    # Remove mounts
    LOG.info("Removing mounts")
    unmount_filesystem(PLATFORM_PATH)
    unmount_filesystem(CGCS_PATH)
    unmount_filesystem(utils.RABBIT_PATH)
    unmount_filesystem(POSTGRES_MOUNT_PATH)
    os.rmdir(POSTGRES_MOUNT_PATH)

    # Set upgrade flags on mate controller
    LOG.info("Setting upgrade flags on mate controller")
    os.mkdir("/tmp/etc_platform")
    nfs_mount_filesystem("/etc/platform", "/tmp/etc_platform")
    upgrade_complete_flag_file = os.path.join(
        "/tmp/etc_platform",
        os.path.basename(CONTROLLER_UPGRADE_COMPLETE_FLAG))
    open(upgrade_complete_flag_file, "w").close()
    upgrade_flag_file = os.path.join(
        "/tmp/etc_platform", os.path.basename(CONTROLLER_UPGRADE_FLAG))
    os.remove(upgrade_flag_file)

    upgrade_complete_flag_file = os.path.join(
        "/tmp/etc_platform", os.path.basename(CONTROLLER_UPGRADE_STARTED_FLAG))
    os.remove(upgrade_complete_flag_file)

    unmount_filesystem("/tmp/etc_platform")
    os.rmdir("/tmp/etc_platform")

    print("Controller-1 upgrade complete")
    LOG.info("Controller-1 upgrade complete!!!")


def show_help():
    print("Usage: %s <FROM_RELEASE> <TO_RELEASE>" % sys.argv[0])
    print("Upgrade controller-1. For internal use only.")


def main():

    from_release = None
    to_release = None
    arg = 1
    while arg < len(sys.argv):
        if sys.argv[arg] in ['--help', '-h', '-?']:
            show_help()
            exit(1)
        elif arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        else:
            print("Invalid option %s. Use --help for more information." %
                  sys.argv[arg])
            exit(1)
        arg += 1

    log.configure()

    if not from_release or not to_release:
        print("Both the FROM_RELEASE and TO_RELEASE must be specified")
        exit(1)

    try:
        upgrade_controller(from_release, to_release)
    except Exception as e:
        LOG.exception(e)
        print("Upgrade failed: {}".format(e))

        # Set upgrade fail flag on mate controller
        LOG.info("Set upgrade fail flag on mate controller")
        os.mkdir("/tmp/etc_platform")
        nfs_mount_filesystem("/etc/platform", "/tmp/etc_platform")
        upgrade_fail_flag_file = os.path.join(
            "/tmp/etc_platform",
            os.path.basename(CONTROLLER_UPGRADE_FAIL_FLAG))
        open(upgrade_fail_flag_file, "w").close()
        unmount_filesystem("/tmp/etc_platform")
        os.rmdir("/tmp/etc_platform")

        exit(1)


def extract_relative_directory(archive, member_path, dest_dir):
    """ Extracts all members from the archive that match the path specified
        Will strip the specified path from the member before copying to the
        destination
    """
    if not member_path.endswith('/'):
        member_path += '/'

    offset = len(member_path)
    filtered_members = [copy.copy(member) for member in archive.getmembers()
                        if member.name.startswith(member_path)]
    for member in filtered_members:
        member.name = member.name[offset:]

    archive.extractall(dest_dir, filtered_members)


def extract_relative_file(archive, member_name, dest_dir):
    """ Extracts the specified member to destination using only the filename
        with no preceding paths
    """
    member = archive.getmember(member_name)
    temp_member = copy.copy(member)
    temp_member.name = os.path.basename(temp_member.name)
    archive.extract(temp_member, dest_dir)


def extract_data_from_archive(archive, staging_dir, from_release, to_release):
    """Extracts the data from the archive to the staging directory"""
    tmp_platform_path = os.path.join(staging_dir, "opt", "platform")
    tmp_puppet_path = os.path.join(tmp_platform_path, "puppet",
                                   from_release, "hieradata")
    tmp_sysinv_path = os.path.join(tmp_platform_path, "sysinv", from_release)
    tmp_keyring_path = os.path.join(tmp_platform_path, ".keyring",
                                    from_release)
    tmp_pxelinux_path = os.path.join(tmp_platform_path, "config",
                                     from_release, "pxelinux.cfg")
    # We don't modify the config files so copy them to the to_release folder
    tmp_config_path = os.path.join(tmp_platform_path, "config", to_release)

    # 0755 permissions
    dir_options = stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | \
        stat.S_IROTH | stat.S_IXOTH

    os.makedirs(tmp_puppet_path, dir_options)
    os.makedirs(tmp_config_path, dir_options)
    os.makedirs(tmp_sysinv_path, dir_options)
    os.makedirs(tmp_keyring_path, dir_options)

    os.symlink(tmp_platform_path, PLATFORM_PATH)

    extract_relative_directory(archive, "hieradata", tmp_puppet_path)
    extract_relative_directory(archive, ".keyring", tmp_keyring_path)
    extract_relative_directory(archive, "config/pxelinux.cfg",
                               tmp_pxelinux_path)

    os.makedirs(
        os.path.join(PLATFORM_PATH, "config", to_release, "pxelinux.cfg"),
        dir_options)

    # Restore ssh configuration
    extract_relative_directory(archive, 'config/ssh_config',
                               tmp_config_path + '/ssh_config')

    # Restore certificate files if they are in the archive
    backup_restore.restore_etc_ssl_dir(archive,
                                       configpath=tmp_config_path)

    # Extract etc files
    archive.extract('etc/hostname', '/')
    archive.extract('etc/hosts', '/')
    extract_relative_file(archive, 'etc/hosts', tmp_config_path)
    extract_relative_file(archive, 'etc/platform/platform.conf', staging_dir)

    extract_relative_file(archive, 'etc/sysinv/sysinv.conf', tmp_sysinv_path)

    # Restore permanent config files
    perm_files = ['cgcs_config', 'hosts', 'resolv.conf',
                  'dnsmasq.hosts', 'dnsmasq.leases',
                  'dnsmasq.addn_hosts']
    for file in perm_files:
        path = 'config/' + file
        extract_relative_file(archive, path, tmp_config_path)

    # Extract distributed cloud addn_hosts file if present in archive.
    if backup_restore.file_exists_in_archive(
            archive, 'config/dnsmasq.addn_hosts_dc'):
        extract_relative_file(
            archive, 'config/dnsmasq.addn_hosts_dc', tmp_config_path)


def extract_postgres_data(archive):
    """ Extract postgres data to temp directory """
    postgres_data_dir = os.path.join(utils.POSTGRES_PATH, "upgrade")

    extract_relative_directory(archive, "postgres", postgres_data_dir)


def migrate_platform_conf(staging_dir):
    """ Migrate platform.conf """
    temp_platform_conf_path = os.path.join(staging_dir, 'platform.conf')
    options = []
    with open(temp_platform_conf_path, 'r') as temp_file:
        for line in temp_file:
            option = line.split('=', 1)
            skip_options = ['nodetype',
                            'subfunction',
                            'management_interface',
                            'oam_interface',
                            'sw_version',
                            'INSTALL_UUID',
                            'system_type',
                            'UUID']
            if option[0] not in skip_options:
                options.append(line)

    with open(PLATFORM_CONF_FILE, 'aw') as conf_file:
        for option in options:
            conf_file.write(option)


def get_backup_fs_size():
    """ Get the backup fs size from the sysinv database """
    conn = psycopg2.connect("dbname=sysinv user=postgres")
    cur = conn.cursor()
    cur.execute("select size from controller_fs where name='backup';")
    row = cur.fetchone()
    if row is None:
        LOG.error("Failed to fetch controller_fs data")
        raise psycopg2.ProgrammingError("Failed to fetch controller_fs data")

    return row[0]


def persist_platform_data(staging_dir):
    """ Copies the tmp platform data to the drbd filesystem"""
    devnull = open(os.devnull, 'w')

    tmp_platform_path = staging_dir + PLATFORM_PATH + "/"

    try:
        subprocess.check_call(
            ["rsync",
             "-a",
             tmp_platform_path,
             PLATFORM_PATH],
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to copy tmp platform dir to %s" % PLATFORM_PATH)
        raise


def update_cinder_state():
    """ The backing store for cinder volumes and snapshots is not
        restored, so their status must be set to error.
    """
    conn = psycopg2.connect("dbname=cinder user=postgres")
    with conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE VOLUMES SET STATUS='error';")
            cur.execute("UPDATE SNAPSHOTS SET STATUS='error';")


def get_simplex_metadata(archive, staging_dir):
    """Gets the metadata from the archive"""

    extract_relative_file(archive, 'config/upgrades/metadata', staging_dir)
    metadata_filename = os.path.join(staging_dir, 'metadata')
    with open(metadata_filename, 'r') as metadata_file:
        metadata_contents = metadata_file.read()
    metadata = json.loads(metadata_contents)

    return metadata


def check_load_version(to_release):
    """Ensure that the running release matches the archive metadata"""
    if to_release != SW_VERSION:
        raise Exception("Incorrect software load installed. Found: %s "
                        "expecting: %s" % (SW_VERSION, to_release))


def upgrade_controller_simplex(backup_file):
    """ Performs the upgrade on controller-0.
        Broadly this is system restore combined with the upgrade data migration
        We extract the data from the archive, restore the database to a
        temporary filesystem, migrate the data and generate the N+1 manifests.
        The migrated database is dumped to /opt/backups.
        We apply the N+1 manifests as INITIAL_CONFIG_PRIMARY and then restore
        the migrated database. Finally we apply any necessary upgrade manifests
        and restore the rest of the system data.
    """

    if (os.path.exists(constants.CGCS_CONFIG_FILE) or
            os.path.exists(CONFIG_PATH) or
            os.path.exists(constants.INITIAL_CONFIG_COMPLETE_FILE)):
        print_log_info("Configuration has already been done. "
                       "An upgrade operation can only be done "
                       "immediately after the load has been installed.")

        raise Exception("System configuration already completed")

    if not os.path.isfile(backup_file):
        raise Exception("Backup file (%s) not found." % backup_file)

    if not os.path.isabs(backup_file):
        backup_file = os.path.abspath(backup_file)

    if os.path.isfile(RESTORE_IN_PROGRESS_FLAG):
        raise Exception("Upgrade already in progress.")
    else:
        open(RESTORE_IN_PROGRESS_FLAG, 'w')

    devnull = open(os.devnull, 'w')

    print_log_info("Starting controller upgrade")

    staging_dir = tempfile.mkdtemp(dir='/tmp')
    # Permission change required or postgres restore fails
    subprocess.call(['chmod', 'a+rx', staging_dir], stdout=devnull)
    os.chdir('/')

    try:
        archive = tarfile.open(backup_file)
    except tarfile.TarError as e:
        LOG.exception(e)
        raise Exception("Error opening backup file. Invalid backup file.")

    metadata = get_simplex_metadata(archive, staging_dir)

    from_release = metadata['upgrade']['from_release']
    to_release = metadata['upgrade']['to_release']

    check_load_version(to_release)
    backup_restore.check_load_subfunctions(archive, staging_dir)

    # Patching is potentially a multi-phase step.
    # If the controller is impacted by patches from the backup,
    # it must be rebooted before continuing the restore.
    # If this is the second pass through, we can skip over this.
    if not os.path.isfile(restore_patching_complete):
        print("Restoring Patches")
        extract_relative_directory(archive, "patching", patching_permdir)
        extract_relative_directory(archive, "updates", patching_repo_permdir)

        print("Applying Patches")
        try:
            subprocess.check_output(["sw-patch", "install-local"])
        except subprocess.CalledProcessError:
            LOG.error("Failed to install patches")
            raise Exception("Failed to install patches")

        open(restore_patching_complete, 'w')

        # If the controller was impacted by patches, we need to reboot.
        if os.path.isfile(node_is_patched):
            LOG.info("This controller has been patched. Rebooting now")
            print("\nThis controller has been patched. Rebooting now\n\n")
            time.sleep(5)
            os.remove(RESTORE_IN_PROGRESS_FLAG)
            if staging_dir:
                shutil.rmtree(staging_dir, ignore_errors=True)
            subprocess.call("reboot")

        else:
            # We need to restart the patch controller and agent, since
            # we setup the repo and patch store outside its control
            subprocess.call(
                ["systemctl",
                 "restart",
                 "sw-patch-controller-daemon.service"],
                stdout=devnull, stderr=devnull)
            subprocess.call(
                ["systemctl",
                 "restart",
                 "sw-patch-agent.service"],
                stdout=devnull, stderr=devnull)

    if os.path.isfile(node_is_patched):
        # If we get here, it means the node was patched by the user
        # AFTER the restore applied patches and rebooted, but didn't
        # reboot.
        # This means the patch lineup no longer matches what's in the
        # backup, but we can't (and probably shouldn't) prevent that.
        # However, since this will ultimately cause the node to fail
        # the goenabled step, we can fail immediately and force the
        # user to reboot.
        print_log_info("\nThis controller has been patched, but not rebooted.")
        print_log_info("Please reboot before continuing the restore process.")
        raise Exception("Controller node patched without rebooting")

    # Flag can now be cleared
    os.remove(restore_patching_complete)

    if from_release == to_release:
        raise Exception("Cannot upgrade from release %s to the same "
                        "release %s." % (from_release, to_release))

    # TODO Use db_fs_size from yaml data and add to runtime parameters
    # during the bootstrap manifest
    # db_size = metadata['filesystem']['database_gib']
    # db_bytes = db_size * 1024 * 1024 * 1024
    # db_filesystem_size = str(db_bytes) + "B"

    # Stop sysinv-agent so it doesn't interfere
    LOG.info("Stopping sysinv-agent")
    try:
        subprocess.check_call(["systemctl", "stop", "sysinv-agent"],
                              stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.error("Failed to stop %s service" % "sysinv-agent")
        raise

    print_log_info("Extracting data from archive")
    extract_data_from_archive(archive, staging_dir, from_release, to_release)

    migrate_platform_conf(staging_dir)

    # Migrate keyring data
    print_log_info("Migrating keyring data...")
    migrate_keyring_data(from_release, to_release)

    # Migrate pxeboot config
    print_log_info("Migrating pxeboot configuration...")
    migrate_pxeboot_config(from_release, to_release)

    # Migrate sysinv data.
    print_log_info("Migrating sysinv configuration...")
    migrate_sysinv_data(from_release, to_release)

    # Simplex configurations can not have shared services
    shared_services = []

    # Migrate hiera data
    migrate_hiera_data(from_release, to_release)
    db_credentials = get_db_credentials(shared_services, from_release)

    os.unlink(PLATFORM_PATH)

    # Write the simplex flag
    cutils.write_simplex_flag()

    cutils.configure_hostname('controller-0')

    controller_0_address = cutils.get_address_from_hosts_file(
        'controller-0')

    hieradata_tmpdir = os.path.join(staging_dir,
                                    constants.HIERADATA_PERMDIR.strip('/'))
    print_log_info("Applying Bootstrap manifest...")
    cutils.apply_manifest(controller_0_address,
                          sysinv_constants.CONTROLLER,
                          'bootstrap',
                          hieradata_tmpdir)

    persist_platform_data(staging_dir)

    cutils.stop_service("sysinv-agent")
    cutils.stop_service("sysinv-api")
    cutils.stop_service("sysinv-conductor")
    cutils.stop_service("openstack-keystone")

    extract_postgres_data(archive)

    # Import databases
    print_log_info("Importing databases...")
    import_databases(from_release, to_release, utils.POSTGRES_PATH,
                     simplex=True)

    # Create any new databases
    print_log_info("Creating new databases...")
    create_databases(from_release, to_release, db_credentials)

    print_log_info("Migrating databases...")
    # Migrate sysinv database
    migrate_sysinv_database()

    # Migrate databases
    migrate_databases(from_release, shared_services, db_credentials,
                      simplex=True)

    print_log_info("Applying configuration...")

    # Execute migration scripts
    utils.execute_migration_scripts(
        from_release, to_release, utils.ACTION_MIGRATE)

    update_cinder_state()

    # Generate "regular" manifests
    LOG.info("Generating manifests for %s" %
             sysinv_constants.CONTROLLER_0_HOSTNAME)

    backup_restore.configure_loopback_interface(archive)

    print_log_info("Creating configs...")
    cutils.create_system_config()
    cutils.create_host_config()

    print_log_info("Persisting Data")

    cutils.start_service("openstack-keystone")
    cutils.start_service("sysinv-conductor")
    cutils.start_service("sysinv-api")
    cutils.start_service("sysinv-agent")

    runtime_filename = os.path.join(staging_dir, 'runtime.yaml')
    utils.create_simplex_runtime_config(runtime_filename)
    if not os.path.isfile(runtime_filename):
        # There is no runtime yaml file to apply
        runtime_filename = None

    print_log_info("Applying manifest...")
    cutils.apply_manifest(controller_0_address,
                          sysinv_constants.CONTROLLER,
                          'controller',
                          constants.HIERADATA_PERMDIR,
                          runtime_filename=runtime_filename)

    cutils.persist_config()

    cutils.apply_banner_customization()

    backup_restore.restore_ldap(archive, backup_restore.ldap_permdir,
                                staging_dir)

    backup_restore.restore_std_dir(archive, backup_restore.home_permdir)

    archive.close()
    shutil.rmtree(staging_dir, ignore_errors=True)

    cutils.mtce_restart()
    cutils.mark_config_complete()

    print_log_info("Waiting for services to start")

    for service in ['sysinv-conductor', 'sysinv-inv']:
        if not cutils.wait_sm_service(service):
            raise Exception("Services have failed to initialize.")

    os.remove(RESTORE_IN_PROGRESS_FLAG)

    # Create the flag file that permits the
    # restore_compute command option.
    cutils.touch(restore_compute_ready)

    print_log_info("Data restore complete")


def print_log_info(string):
    print(string)
    LOG.info(string)


def show_help_simplex():
    print("Usage: %s <BACKUP_FILE>" % sys.argv[0])
    print("Upgrade controller-0 simplex. For internal use only.")


def simplex_main():
    backup_file = None
    arg = 1
    while arg < len(sys.argv):
        if sys.argv[arg] in ['--help', '-h', '-?']:
            show_help()
            exit(1)
        elif arg == 1:
            backup_file = sys.argv[arg]
        else:
            print("Invalid option %s. Use --help for more information." %
                  sys.argv[arg])
            exit(1)
        arg += 1

    log.configure()

    # Enforce that the command is being run from the console
    if cutils.is_ssh_parent():
        print (
            "Error attempting upgrade. Ensure this command is run from the"
            " console.")
        exit(1)

    if not backup_file:
        print("The BACKUP_FILE must be specified")
        exit(1)

    try:
        upgrade_controller_simplex(backup_file)
    except Exception as e:
        LOG.exception(e)
        print("Upgrade failed: {}".format(e))
        # TODO SET Upgrade fail flag
        # Set upgrade fail flag on mate controller
        exit(1)
