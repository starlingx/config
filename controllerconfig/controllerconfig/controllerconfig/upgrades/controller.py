#
# Copyright (c) 2016-2022 Wind River Systems, Inc.
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
from sysinv.puppet import common as puppet_common


# WARNING: The controller-1 upgrade is done before any puppet manifests
# have been applied, so only the static entries from tsconfig can be used
# (the platform.conf file will not have been updated with dynamic values).
from tsconfig.tsconfig import SW_VERSION
from tsconfig.tsconfig import PLATFORM_PATH
from tsconfig.tsconfig import VOLATILE_PXEBOOT_PATH
from tsconfig.tsconfig import KEYRING_PATH
from tsconfig.tsconfig import PLATFORM_CONF_FILE
from tsconfig.tsconfig import CONTROLLER_UPGRADE_FLAG
from tsconfig.tsconfig import CONTROLLER_UPGRADE_COMPLETE_FLAG
from tsconfig.tsconfig import CONTROLLER_UPGRADE_FAIL_FLAG
from tsconfig.tsconfig import CONTROLLER_UPGRADE_STARTED_FLAG

from controllerconfig.common import constants
from controllerconfig import utils as cutils
from controllerconfig.upgrades import utils

from controllerconfig.common import oslolog as log
from oslo_log import log as logging

LOG = logging.getLogger(__name__)

POSTGRES_BIN = utils.get_postgres_bin()
POSTGRES_MOUNT_PATH = '/mnt/postgresql'
POSTGRES_DUMP_MOUNT_PATH = '/mnt/db_dump'
DB_CONNECTION_FORMAT = "connection=postgresql://%s:%s@127.0.0.1/%s\n"
DB_BARBICAN_CONNECTION_FORMAT = "postgresql://%s:%s@127.0.0.1/%s"

restore_patching_complete = '/etc/platform/.restore_patching_complete'
restore_compute_ready = '/var/run/.restore_compute_ready'
node_is_patched = '/var/run/node_is_patched'
patching_permdir = '/opt/patching'
patching_repo_permdir = '/var/www/pages/updates'


def gethostaddress(hostname):
    """ Get the IP address for a hostname, supporting IPv4 and IPv6. """
    return socket.getaddrinfo(hostname, None)[0][4][0]


def get_db_credentials(shared_services, from_release, role=None):
    """
    Returns the database credentials using the provided shared services,
    from_release and role.
    """
    db_credential_keys = \
        {'barbican': {'hiera_user_key': 'barbican::db::postgresql::user',
                      'keyring_password_key': 'barbican',
                      },
         'sysinv': {'hiera_user_key': 'sysinv::db::postgresql::user',
                    'keyring_password_key': 'sysinv',
                    },
         'fm': {'hiera_user_key': 'fm::db::postgresql::user',
                'keyring_password_key': 'fm',
                },
         }

    if sysinv_constants.SERVICE_TYPE_IDENTITY not in shared_services:
        db_credential_keys.update(
            {'keystone': {'hiera_user_key':
                          'keystone::db::postgresql::user',
                          'keyring_password_key': 'keystone',
                          }})

    if role == sysinv_constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
        db_credential_keys.update(
            {'dcmanager': {'hiera_user_key': 'dcmanager::db::postgresql::user',
                           'keyring_password_key': 'dcmanager',
                           },
             'dcorch': {'hiera_user_key': 'dcorch::db::postgresql::user',
                        'keyring_password_key': 'dcorch',
                        },
             })

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


def get_system_role():
    """ Get the system role from the sysinv database"""

    conn = psycopg2.connect("dbname=sysinv user=postgres")
    cur = conn.cursor()
    cur.execute("select distributed_cloud_role from i_system;")
    row = cur.fetchone()
    if row is None:
        LOG.error("Failed to fetch i_system data")
        raise psycopg2.ProgrammingError("Failed to fetch i_system data")

    role = row[0]

    return role


def get_shared_services():
    """ Get the list of shared services from the sysinv database"""

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
    if database == 'barbican':
        return DB_BARBICAN_CONNECTION_FORMAT % (username, password, database)
    else:
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
                                   "pxelinux.cfg", "")
    dest_pxelinux = os.path.join(PLATFORM_PATH, "config", to_release,
                                 "pxelinux.cfg")

    try:
        subprocess.check_call(
            ["rsync",
             "-a",
             os.path.join(source_pxelinux),
             os.path.join(dest_pxelinux)],
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to migrate %s" % source_pxelinux)
        raise

    to_release_symlink_target = os.path.join(VOLATILE_PXEBOOT_PATH,
                                             "pxelinux.cfg.files", "grub.cfg")

    dest_symlink_exists = os.path.islink(dest_pxelinux + "/grub.cfg")
    if dest_symlink_exists:
        os.unlink(dest_pxelinux + "/grub.cfg")
    os.symlink(to_release_symlink_target, dest_pxelinux + "/grub.cfg")


def migrate_armada_config(from_release, to_release):
    """ Migrates armada configuration. """

    # Check if the folder exist before migration
    if not os.path.exists(os.path.join(PLATFORM_PATH, "armada")):
        LOG.info("Skipping armada migration, the directory doesn't exist")
        return

    LOG.info("Migrating armada config")
    devnull = open(os.devnull, 'w')

    # Copy the entire armada.cfg directory to pick up any changes made
    # after the data was migrated (i.e. updates to the controller-1 load).
    source_armada = os.path.join(PLATFORM_PATH, "armada", from_release, "")
    dest_armada = os.path.join(PLATFORM_PATH, "armada", to_release)
    try:
        subprocess.check_call(
            ["rsync",
             "-a",
             os.path.join(source_armada),
             os.path.join(dest_armada)],
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to migrate %s" % source_armada)
        raise


def migrate_fluxcd_config(from_release, to_release):
    """ Migrates fluxcd configuration. """

    # Check if the folder exists before migration
    if not os.path.exists(os.path.join(PLATFORM_PATH, "fluxcd")):
        LOG.info("Skipping fluxcd migration, the directory doesn't exist")
        return

    LOG.info("Migrating fluxcd config")
    devnull = open(os.devnull, 'w')

    # Copy the entire fluxcd.cfg directory to pick up any changes made
    # after the data was migrated.
    source_fluxcd = os.path.join(PLATFORM_PATH, "fluxcd", from_release, "")
    dest_fluxcd = os.path.join(PLATFORM_PATH, "fluxcd", to_release)
    try:
        subprocess.check_call(
            ["rsync",
             "-a",
             os.path.join(source_fluxcd),
             os.path.join(dest_fluxcd)],
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to migrate %s" % source_fluxcd)
        raise


def migrate_helm_config(from_release, to_release):
    """ Migrates helm configuration. """

    LOG.info("Migrating helm config")
    devnull = open(os.devnull, 'w')

    # Copy the entire helm.cfg directory to pick up any changes made
    # after the data was migrated (i.e. updates to the controller-1 load).
    source_helm = os.path.join(PLATFORM_PATH, "helm", from_release, "")
    dest_helm = os.path.join(PLATFORM_PATH, "helm", to_release)
    try:
        subprocess.check_call(
            ["rsync",
             "-a",
             os.path.join(source_helm),
             os.path.join(dest_helm)],
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to migrate %s" % source_helm)
        raise


def migrate_sysinv_data(from_release, to_release):
    """ Migrates sysinv data. """
    devnull = open(os.devnull, 'w')

    LOG.info("Migrating sysinv data")

    # If the /opt/platform/sysinv/<release>/sysinv.conf.default file has
    # changed between releases it must be modified at this point.
    try:
        subprocess.check_call(
            ["rsync",
             "-a",
             os.path.join(PLATFORM_PATH, "sysinv", from_release, ""),
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
        'sudo -u postgres {} -D {}'.format(
            os.path.join(POSTGRES_BIN, 'initdb'),
            utils.POSTGRES_DATA_DIR),
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
        postgres_config_path = os.path.join(
            from_dir, 'postgres.postgreSql.config')
        # Do postgres schema import (suppress stderr due to noise)
        subprocess.check_call(['sudo -u postgres psql -f ' +
                               postgres_config_path + ' postgres'],
                              shell=True,
                              stdout=devnull,
                              stderr=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to import schemas.")
        raise

    import_commands = []

    # Do postgres data import
    for data in glob.glob(from_dir + '/*.*Sql.data'):
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
        subprocess.check_call(sysinv_cmd,
                              shell=True, stdout=devnull, stderr=devnull)

    except subprocess.CalledProcessError as ex:
        LOG.exception("Failed to execute command: '%s' during upgrade "
                      "processing, return code: %d"
                      % (sysinv_cmd, ex.returncode))
        raise


def migrate_databases(from_release, shared_services, db_credentials,
                      simplex=False, role=None):
    """ Migrates databases. """

    devnull = open(os.devnull, 'w')

    # Create minimal config files for each OpenStack service so they can
    # run their database migration.
    if sysinv_constants.SERVICE_TYPE_IDENTITY not in shared_services:
        with open("/etc/keystone/keystone-dbsync.conf", "w") as f:
            f.write("[database]\n")
            f.write(get_connection_string(db_credentials, 'keystone'))

    migrate_commands = [
        # Migrate barbican
        ('barbican',
         'barbican-manage db upgrade ' +
         '--db-url %s' % get_connection_string(db_credentials, 'barbican')),
    ]

    # Migrate fm
    # append the migrate command for dcmanager db
    with open("/etc/fm/fm.conf", "w") as f:
        f.write("[database]\n")
        f.write(get_connection_string(db_credentials, 'fm'))

    migrate_commands += [
        ('fm',
         'fm-dbsync')
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

    if role == sysinv_constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
        # append the migrate command for dcmanager db
        with open("/etc/dcmanager/dcmanager.conf", "w") as f:
            f.write("[database]\n")
            f.write(get_connection_string(db_credentials, 'dcmanager'))

        migrate_commands += [
            ('dcmanager',
             'dcmanager-manage db_sync')
        ]

        # append the migrate command for dcorch db
        with open("/etc/dcorch/dcorch.conf", "w") as f:
            f.write("[database]\n")
            f.write(get_connection_string(db_credentials, 'dcorch'))

        migrate_commands += [
            ('dcorch',
             'dcorch-manage db_sync')
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


def migrate_hiera_data(from_release, to_release, role=None):
    """ Migrate hiera data. """

    LOG.info("Migrating hiera data")
    from_hiera_path = os.path.join(PLATFORM_PATH, "puppet", from_release,
                                   "hieradata")
    to_hiera_path = constants.HIERADATA_PERMDIR

    shutil.rmtree(to_hiera_path, ignore_errors=True)
    os.makedirs(to_hiera_path)

    # Copy only the static yaml files. The other yaml files will be generated
    # when required.
    for f in ['secure_static.yaml', 'static.yaml']:
        shutil.copy(os.path.join(from_hiera_path, f), to_hiera_path)

    # Make any necessary updates to the static yaml files.
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

    secure_static_file = os.path.join(
        constants.HIERADATA_PERMDIR, "secure_static.yaml")
    with open(secure_static_file, 'r') as yaml_file:
        secure_static_config = yaml.load(yaml_file)

    # This code can be removed in the release that follows StX 6.0
    sysinv_pass = utils.get_password_from_keyring('sysinv', 'services')
    secure_static_config.update({
        'sysinv::certalarm::local_keystone_password': sysinv_pass
    })

    with open(secure_static_file, 'w') as yaml_file:
        yaml.dump(secure_static_config, yaml_file, default_flow_style=False)


def apply_sriov_config(db_credentials, hostname):
    # If controller-1 has any FEC devices or sriov vfs configured, apply the
    # sriov runtime manifest. We can't apply it from controller-0 during the
    # host-unlock process as controller-1 is running the new release.
    database = 'sysinv'
    username = db_credentials[database]['username']
    password = db_credentials[database]['password']
    # psycopg2 can connect with the barbican string eg postgresql:// ...
    connection_string = DB_BARBICAN_CONNECTION_FORMAT % (
        username, password, database)
    conn = psycopg2.connect(connection_string)
    cur = conn.cursor()
    cur.execute(
        "select id, mgmt_ip from i_host where hostname=%s;", (hostname,))
    host = cur.fetchone()
    host_id = host[0]
    mgmt_ip = host[1]
    cur.execute("select id from pci_devices "
                "where sriov_numvfs > 0 and host_id=%s",
                (host_id,))
    fec_device = cur.fetchone()
    cur.execute("select id from interfaces "
                "where forihostid=%s and iftype='ethernet' "
                "and sriov_numvfs>0;",
                (host_id,))
    interface = cur.fetchone()
    if interface or fec_device:
        # There are FEC devices/sriov vfs configured, apply the sriov manifest
        LOG.info("Applying sriov/fec manifest")
        personality = sysinv_constants.WORKER
        classes = [
            'platform::network::interfaces::sriov::runtime',
            'platform::devices::fpga::fec::runtime'
        ]
        config = {'classes': classes}
        # create a temporary file to hold the runtime configuration values
        fd, tmpfile = tempfile.mkstemp(suffix='.yaml')
        with open(tmpfile, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        puppet_common.puppet_apply_manifest(
            mgmt_ip, personality, manifest='runtime', runtime=tmpfile)
        os.close(fd)
        os.remove(tmpfile)


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
    nfs_mount_filesystem(utils.RABBIT_PATH)
    os.mkdir(POSTGRES_MOUNT_PATH)
    nfs_mount_filesystem(utils.POSTGRES_PATH, POSTGRES_MOUNT_PATH)

    # Migrate keyring data
    print("Migrating keyring data...")
    migrate_keyring_data(from_release, to_release)

    # Migrate pxeboot config
    print("Migrating pxeboot configuration...")
    migrate_pxeboot_config(from_release, to_release)

    # Migrate armada config
    print("Migrating armada configuration...")
    migrate_armada_config(from_release, to_release)

    # Migrate fluxcd config
    print("Migrating fluxcd configuration...")
    migrate_fluxcd_config(from_release, to_release)

    # Migrate helm config
    print("Migrating helm configuration...")
    migrate_helm_config(from_release, to_release)

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
        subprocess.check_call([
            'sudo',
            '-u',
            'postgres',
            os.path.join(POSTGRES_BIN, 'pg_ctl'),
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

    role = get_system_role()
    shared_services = get_shared_services()

    # Create /tmp/python_keyring - used by keystone manifest.
    shutil.copytree(os.path.join(PLATFORM_PATH, ".keyring", to_release,
                                 "python_keyring"),
                    "/tmp/python_keyring")

    # Copy admin.conf file from /opt/platform to /etc/kubernetes/admin.conf
    # during upgrade
    try:
        subprocess.check_call(
            ["cp",
             os.path.join(PLATFORM_PATH, "config", to_release,
                          "kubernetes", utils.KUBERNETES_ADMIN_CONF_FILE),
             os.path.join(utils.KUBERNETES_CONF_PATH,
                          utils.KUBERNETES_ADMIN_CONF_FILE)],
            stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to copy %s" %
                      os.path.join(utils.KUBERNETES_CONF_PATH,
                                   utils.KUBERNETES_ADMIN_CONF_FILE))
        raise

    # Migrate hiera data
    migrate_hiera_data(from_release, to_release, role=role)
    utils.add_upgrade_entries_to_hiera_data(from_release)

    # Get database credentials
    db_credentials = get_db_credentials(
        shared_services, from_release, role=role)

    # Create any new databases
    print("Creating new databases...")
    create_databases(from_release, to_release, db_credentials)

    print("Migrating databases...")
    # Migrate sysinv database
    migrate_sysinv_database()

    # Migrate databases
    migrate_databases(from_release, shared_services, db_credentials, role=role)

    print("Applying configuration...")

    # Execute migration scripts
    utils.execute_migration_scripts(
        from_release, to_release, utils.ACTION_MIGRATE)

    uuid = get_controller_1_uuid()

    update_platform_conf_file(uuid)

    # Stop postgres server
    try:
        subprocess.check_call([
            'sudo',
            '-u',
            'postgres',
            os.path.join(POSTGRES_BIN, 'pg_ctl'),
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

    apply_sriov_config(db_credentials, utils.CONTROLLER_1_HOSTNAME)

    # Remove /etc/kubernetes/admin.conf after it is used to generate
    # the hiera data
    admin_conf = os.path.join(utils.KUBERNETES_CONF_PATH,
                              utils.KUBERNETES_ADMIN_CONF_FILE)
    try:
        subprocess.check_call(["rm -f %s" % admin_conf], shell=True,
                              stdout=devnull)
    except subprocess.CalledProcessError:
        LOG.exception("Failed to remove file %s" % admin_conf)

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

    # Restart the sysinv agent to report the inventory status
    # The sysinv.conf contains temporary parameters that are used for
    # data-migration. By removing that sysinv.conf we trigger the sysinv-agent
    # to load the correct conf from the drbd filesystem
    os.remove("/etc/sysinv/sysinv.conf")
    LOG.info("Starting sysinv-agent")
    cutils.start_service("sysinv-agent")

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

    # Remove leading /. Allows us to pass filesystem constants if needed
    if member_path.startswith('/'):
        member_path = member_path[1:]

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
    # Remove leading /. Allows us to pass filesystem constants if needed
    if member_name.startswith('/'):
        member_name = member_name[1:]

    member = archive.getmember(member_name)
    temp_member = copy.copy(member)
    temp_member.name = os.path.basename(temp_member.name)
    archive.extract(temp_member, dest_dir)


def extract_data_from_archive(archive, staging_dir, from_release, to_release):
    """Extracts the data from the archive to the staging directory"""
    from_puppet_path = os.path.join(PLATFORM_PATH, "puppet",
                                    from_release, "hieradata")
    from_sysinv_path = os.path.join(PLATFORM_PATH, "sysinv", from_release)
    from_keyring_path = os.path.join(PLATFORM_PATH, ".keyring",
                                     from_release)
    from_pxelinux_path = os.path.join(PLATFORM_PATH, "config",
                                      from_release, "pxelinux.cfg")

    # 0755 permissions
    dir_options = stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | \
        stat.S_IROTH | stat.S_IXOTH

    shutil.rmtree(from_puppet_path, ignore_errors=True)
    shutil.rmtree(from_sysinv_path, ignore_errors=True)
    shutil.rmtree(from_keyring_path, ignore_errors=True)
    shutil.rmtree(
        os.path.join(PLATFORM_PATH, "config", to_release, "pxelinux.cfg"),
        ignore_errors=True)

    os.makedirs(from_puppet_path, dir_options)
    os.makedirs(from_sysinv_path, dir_options)
    os.makedirs(from_keyring_path, dir_options)

    extract_relative_directory(archive, from_puppet_path, from_puppet_path)
    extract_relative_directory(archive, from_keyring_path, from_keyring_path)
    extract_relative_directory(archive, from_pxelinux_path, from_pxelinux_path)

    os.makedirs(
        os.path.join(PLATFORM_PATH, "config", to_release, "pxelinux.cfg"),
        dir_options)

    # Extract etc files
    archive.extract('etc/hostname', '/')
    extract_relative_file(archive, PLATFORM_CONF_FILE, staging_dir)

    extract_relative_file(
        archive, sysinv_constants.SYSINV_CONFIG_FILE_LOCAL, from_sysinv_path)


def extract_postgres_data(archive):
    """ Extract postgres data to temp directory """
    postgres_data_dir = os.path.join(utils.POSTGRES_PATH, "upgrade")
    ansible_start_path = 'opt/platform-backup/ansible'
    ansible_path = ''
    offset = len(ansible_start_path)
    for member in archive.getmembers():
        if member.name.startswith(ansible_start_path):
            ansible_path = member.name[:member.name.index('/', offset)]
            break
    extract_relative_directory(
        archive, ansible_path + "/postgres", postgres_data_dir)


def read_config_file_kvp(config_file):
    """ A Generic method to read the .conf file.

    param config_file: Absolute path of the target file.
    result: A dictionary with key value pairs retrieved from the target file.
    """
    result = dict()

    with open(config_file, 'r') as temp_file:
        for line in temp_file:
            key, value = line.split('=', 1)
            result.update({key: value})
    return result


def migrate_platform_conf(staging_dir):
    """ Migrate platform.conf """
    backup_platform_conf_path = os.path.join(staging_dir, 'platform.conf')
    temp_platform_conf_file = os.path.join(staging_dir, 'platform-temp.conf')
    backup_platform_conf_values = read_config_file_kvp(
        backup_platform_conf_path)
    new_platform_conf_values = read_config_file_kvp(PLATFORM_CONF_FILE)

    # The following values are expected to preserve in the newly
    # generated platform.conf file
    skip_options = ['nodetype',
                    'subfunction',
                    'management_interface',
                    'oam_interface',
                    'sw_version',
                    'INSTALL_UUID',
                    'system_type']
    for key in skip_options:
        if key in backup_platform_conf_values:
            del backup_platform_conf_values[key]
    new_platform_conf_values.update(backup_platform_conf_values)
    with open(temp_platform_conf_file, 'w') as f:
        for key, value in new_platform_conf_values.items():
            line = key + "=" + value
            f.write(line)
    shutil.move(temp_platform_conf_file, PLATFORM_CONF_FILE)


def get_simplex_metadata(archive, staging_dir):
    """Gets the metadata from the archive"""
    # Get the metadate path from the archive
    metadata_filename = 'upgrades/metadata'
    metadata_path = ''
    for member in archive.getmembers():
        if member.name.endswith(metadata_filename):
            metadata_path = member.name
            break

    extract_relative_file(archive, metadata_path, staging_dir)
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
    """ Performs the data migration on controller-0.
        We extract the data from the archive, restore the database, migrate
        the databases and restore/migrate the rest of the platform data.
        The ansible playbook takes care of bootstrapping the system and
        restoring other data (eg ceph/etcd).
    """

    if not os.path.isfile(backup_file):
        raise Exception("Backup file (%s) not found." % backup_file)

    if not os.path.isabs(backup_file):
        backup_file = os.path.abspath(backup_file)

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

    if from_release == to_release:
        raise Exception("Cannot upgrade from release %s to the same "
                        "release %s." % (from_release, to_release))

    print_log_info("Extracting data from archive")
    extract_data_from_archive(archive, staging_dir, from_release, to_release)

    # Backup sysinv.conf
    shutil.move("/etc/sysinv/sysinv.conf", "/etc/sysinv/sysinv-temp.conf")
    # Backup fm.conf
    shutil.move("/etc/fm/fm.conf", "/etc/fm/fm-temp.conf")

    migrate_platform_conf(staging_dir)

    # Migrate pxeboot config
    print_log_info("Migrating pxeboot configuration...")
    migrate_pxeboot_config(from_release, to_release)

    # Migrate armada config
    print("Migrating armada configuration...")
    migrate_armada_config(from_release, to_release)

    # Migrate fluxcd config
    print("Migrating fluxcd configuration...")
    migrate_fluxcd_config(from_release, to_release)

    # Migrate helm config
    print("Migrating helm configuration...")
    migrate_helm_config(from_release, to_release)

    # Migrate sysinv data.
    print_log_info("Migrating sysinv configuration...")
    migrate_sysinv_data(from_release, to_release)

    # Simplex configurations can not have shared services
    shared_services = []

    role = get_system_role()
    # Migrate hiera data
    migrate_hiera_data(from_release, to_release, role=role)
    db_credentials = get_db_credentials(shared_services, from_release)

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

    hostname = 'controller-0'
    LOG.info("Generating config for %s" % hostname)
    try:
        cutils.create_system_config()
        cutils.create_host_config(hostname)
    except Exception as e:
        LOG.exception(e)
        LOG.info("Failed to update hiera configuration")
        raise

    # Runtime manifests may modify platform.conf, so we'll back it up
    temp_platform_conf = PLATFORM_CONF_FILE + ".backup"
    shutil.copy(PLATFORM_CONF_FILE, temp_platform_conf)
    apply_sriov_config(db_credentials, hostname)

    archive.close()
    shutil.rmtree(staging_dir, ignore_errors=True)

    # Restore platform.conf
    shutil.move(temp_platform_conf, PLATFORM_CONF_FILE)
    # Restore sysinv.conf
    shutil.move("/etc/sysinv/sysinv-temp.conf", "/etc/sysinv/sysinv.conf")
    # Restore fm.conf
    shutil.move("/etc/fm/fm-temp.conf", "/etc/fm/fm.conf")

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
            show_help_simplex()
            exit(1)
        elif arg == 1:
            backup_file = sys.argv[arg]
        else:
            print("Invalid option %s. Use --help for more information." %
                  sys.argv[arg])
            exit(1)
        arg += 1

    log.configure()

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
