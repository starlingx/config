#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

#
# This file contains common upgrades functions that can be used by both sysinv
# and during the upgrade of controller-1.
#

import keyring
import os
import subprocess
import tempfile
import yaml

# WARNING: The controller-1 upgrade is done before any puppet manifests
# have been applied, so only the static entries from tsconfig can be used.
# (the platform.conf file will not have been updated with dynamic values).
from tsconfig.tsconfig import SW_VERSION, PLATFORM_PATH

from configutilities import DEFAULT_DOMAIN_NAME
from controllerconfig import utils as cutils
from controllerconfig.common import log, constants
from sysinv.common import constants as sysinv_constants


LOG = log.get_logger(__name__)

POSTGRES_PATH = '/var/lib/postgresql'
POSTGRES_DATA_DIR = os.path.join(POSTGRES_PATH, SW_VERSION)
RABBIT_PATH = '/var/lib/rabbitmq'
MURANO_RABBIT_PATH = '/var/lib/rabbitmq/murano'
CONTROLLER_1_HOSTNAME = "controller-1"
DB_CONNECTION = "postgresql://%s:%s@127.0.0.1/%s\n"

# Migration script actions
ACTION_START = "start"
ACTION_MIGRATE = "migrate"
ACTION_ACTIVATE = "activate"


def execute_migration_scripts(from_release, to_release, action):
    """ Execute migration scripts with an action:
          start: Prepare for upgrade on release N side. Called during
                 "system upgrade-start".
          migrate: Perform data migration on release N+1 side. Called while
                   controller-1 is performing its upgrade.
    """

    devnull = open(os.devnull, 'w')

    migration_script_dir = "/etc/upgrade.d"

    LOG.info("Executing migration scripts with from_release: %s, "
             "to_release: %s, action: %s" % (from_release, to_release, action))

    # Get a sorted list of all the migration scripts
    # Exclude any files that can not be executed, including .pyc and .pyo files
    files = [f for f in os.listdir(migration_script_dir)
             if os.path.isfile(os.path.join(migration_script_dir, f)) and
             os.access(os.path.join(migration_script_dir, f), os.X_OK)]
    files.sort()

    # Execute each migration script
    for f in files:
        migration_script = os.path.join(migration_script_dir, f)
        try:
            LOG.info("Executing migration script %s" % migration_script)
            subprocess.check_call([migration_script,
                                   from_release,
                                   to_release,
                                   action],
                                  stdout=devnull, stderr=devnull)
        except subprocess.CalledProcessError as e:
            LOG.exception("Migration script %s failed with returncode %d" %
                          (migration_script, e.returncode))
            # Abort when a migration script fails
            raise e


def get_db_connection(hiera_db_records, database):
    username = hiera_db_records[database]['username']
    password = hiera_db_records[database]['password']
    return "postgresql://%s:%s@%s/%s" % (
        username, password, 'localhost', database)


def get_password_from_keyring(service, username):
    """Retrieve password from keyring"""
    password = ""
    os.environ["XDG_DATA_HOME"] = constants.KEYRING_PERMDIR
    try:
        password = keyring.get_password(service, username)
    except Exception as e:
        LOG.exception("Received exception when attempting to get password "
                      "for service %s, username %s: %s" %
                      (service, username, e))
        raise
    finally:
        del os.environ["XDG_DATA_HOME"]
    return password


def get_upgrade_token(from_release,
                      config,
                      secure_config):

    # Get the system hiera data from the from release
    from_hiera_path = os.path.join(PLATFORM_PATH, "puppet", from_release,
                                   "hieradata")
    system_file = os.path.join(from_hiera_path, "system.yaml")
    with open(system_file, 'r') as file:
        system_config = yaml.load(file)

    # during a controller-1 upgrade, keystone is running
    # on the controller UNIT IP, however the service catalog
    # that was migrated from controller-0 since lists the
    # floating controller IP. Keystone operations that use
    # the AUTH URL will hit this service URL and fail,
    # therefore we have to issue an Upgrade token for
    # all Keystone operations during an Upgrade. This token
    # will allow us to circumvent the service catalog entry, by
    # providing a bypass endpoint.
    keystone_upgrade_url = "http://{}:5000/{}".format(
        '127.0.0.1',
        system_config['openstack::keystone::params::api_version'])

    admin_user_domain = system_config.get(
        'openstack::client::params::admin_user_domain')
    if admin_user_domain is None:
        # This value wasn't present in R2. So may be missing in upgrades from
        # that release
        LOG.info("openstack::client::params::admin_user_domain key not found. "
                 "Using Default.")
        admin_user_domain = DEFAULT_DOMAIN_NAME

    admin_project_domain = system_config.get(
        'openstack::client::params::admin_project_domain')
    if admin_project_domain is None:
        # This value wasn't present in R2. So may be missing in upgrades from
        # that release
        LOG.info("openstack::client::params::admin_project_domain key not "
                 "found. Using Default.")
        admin_project_domain = DEFAULT_DOMAIN_NAME

    admin_password = get_password_from_keyring("CGCS", "admin")
    admin_username = system_config.get(
        'openstack::client::params::admin_username')

    # the upgrade token command
    keystone_upgrade_token = (
        "openstack "
        "--os-username {} "
        "--os-password {} "
        "--os-auth-url {} "
        "--os-project-name admin "
        "--os-user-domain-name {} "
        "--os-project-domain-name {} "
        "--os-interface internal "
        "--os-identity-api-version 3 "
        "token issue -c id -f value".format(
            admin_username,
            admin_password,
            keystone_upgrade_url,
            admin_user_domain,
            admin_project_domain
        ))

    config.update({
        'openstack::keystone::upgrade::upgrade_token_file':
            '/etc/keystone/upgrade_token',
        'openstack::keystone::upgrade::url': keystone_upgrade_url
    })

    secure_config.update({
        'openstack::keystone::upgrade::upgrade_token_cmd':
            keystone_upgrade_token,
    })


def add_upgrade_entries_to_hiera_data(from_release):
    """ Adds upgrade entries to the hiera data """

    filename = 'static.yaml'
    secure_filename = 'secure_static.yaml'
    path = constants.HIERADATA_PERMDIR

    # Get the hiera data for this release
    filepath = os.path.join(path, filename)
    with open(filepath, 'r') as file:
        config = yaml.load(file)
    secure_filepath = os.path.join(path, secure_filename)
    with open(secure_filepath, 'r') as file:
        secure_config = yaml.load(file)

    # Get a token and update the config
    get_upgrade_token(from_release, config, secure_config)

    # Update the hiera data on disk
    try:
        fd, tmppath = tempfile.mkstemp(dir=path, prefix=filename,
                                       text=True)
        with open(tmppath, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        os.close(fd)
        os.rename(tmppath, filepath)
    except Exception:
        LOG.exception("failed to write config file: %s" % filepath)
        raise

    try:
        fd, tmppath = tempfile.mkstemp(dir=path, prefix=secure_filename,
                                       text=True)
        with open(tmppath, 'w') as f:
            yaml.dump(secure_config, f, default_flow_style=False)
        os.close(fd)
        os.rename(tmppath, secure_filepath)
    except Exception:
        LOG.exception("failed to write secure config: %s" % secure_filepath)
        raise


def create_simplex_runtime_config(filename):
    """ Create any runtime parameters needed for simplex upgrades"""
    config = {}
    # Here is an example from a previous release...
    # config.update({'nova::db::sync_api::cellv2_setup': False})
    cutils.create_manifest_runtime_config(filename, config)


def apply_upgrade_manifest(controller_address):
    """Apply puppet upgrade manifest files."""

    cmd = [
        "/usr/local/bin/puppet-manifest-apply.sh",
        constants.HIERADATA_PERMDIR,
        str(controller_address),
        sysinv_constants.CONTROLLER,
        'upgrade'
    ]

    logfile = "/tmp/apply_manifest.log"
    try:
        with open(logfile, "w") as flog:
            subprocess.check_call(cmd, stdout=flog, stderr=flog)
    except subprocess.CalledProcessError:
        msg = "Failed to execute upgrade manifest"
        print msg
        raise Exception(msg)
