#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

#
# This file contains common upgrades functions that can be used by both sysinv
# and during the upgrade of controller-1.
#

import os
import subprocess
import tempfile
import uuid
import yaml
import ConfigParser

# WARNING: The controller-1 upgrade is done before any packstack manifests
# have been applied, so only the static entries from tsconfig can be used.
# (the platform.conf file will not have been updated with dynamic values).
from tsconfig.tsconfig import (SW_VERSION, PLATFORM_PATH,
                               KEYRING_PATH, CONFIG_PATH)

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


def get_upgrade_token(hiera_db_records,
                      packstack_config,
                      config,
                      secure_config):
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
        packstack_config.get('general', 'CONFIG_KEYSTONE_API_VERSION'))

    try:
        admin_user_domain = packstack_config.get(
            'general', 'CONFIG_ADMIN_USER_DOMAIN_NAME')
    except ConfigParser.NoOptionError:
        # This value wasn't present in R2. So may be missing in upgrades from
        # that release
        LOG.info("CONFIG_ADMIN_USER_DOMAIN_NAME key not found. Using Default.")
        admin_user_domain = DEFAULT_DOMAIN_NAME

    try:
        admin_project_domain = packstack_config.get(
            'general', 'CONFIG_ADMIN_PROJECT_DOMAIN_NAME')
    except ConfigParser.NoOptionError:
        # This value wasn't present in R2. So may be missing in upgrades from
        # that release
        LOG.info("CONFIG_ADMIN_PROJECT_DOMAIN_NAME key not found. Using "
                 "Default.")
        admin_project_domain = DEFAULT_DOMAIN_NAME

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
            packstack_config.get('general', 'CONFIG_KEYSTONE_ADMIN_USERNAME'),
            hiera_db_records['keystone']['ks_password'],
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


def get_platform_config(packstack_config,
                        to_release,
                        config,
                        secure_config):
    # TODO(TLIU): for now set the hiera option for puppet-keystone
    # Not sure whether it is better to use env instead
    config.update({
        'platform::params::software_version': to_release
    })

    amqp_passwd = packstack_config.get('general', 'CONFIG_AMQP_AUTH_PASSWORD')
    postgres_password = packstack_config.get('general', 'CONFIG_POSTGRESQL_PW')
    secure_config.update({
        'platform::amqp::params::auth_password': amqp_passwd,
        'platform::postgresql::params::password': postgres_password})

    wrsroot_password = packstack_config.get('general', 'CONFIG_WRSROOT_PW')
    try:
        wrsroot_password_age = packstack_config.get('general',
                                                    'CONFIG_WRSROOT_PW_AGE')
    except ConfigParser.NoOptionError:
        # This value wasn't present in R2. So may be missing in upgrades from
        # that release
        LOG.info("CONFIG_WRSROOT_PW_AGE key not found. Setting value to 45")
        wrsroot_password_age = constants.WRSROOT_MAX_PASSWORD_AGE

    secure_config.update({
        'platform::users::params::wrsroot_password': wrsroot_password,
        'platform::users::params::wrsroot_password_max_age':
            wrsroot_password_age
    })

    ceph_cluster_id = packstack_config.get('general',
                                           'CONFIG_CEPH_CLUSTER_UUID')
    config.update({
        'platform::ceph::params::cluster_uuid': ceph_cluster_id
    })

    try:
        ceph_pwd = packstack_config.get('general',
                                        'CONFIG_CEPH_OBJECT_GATEWAY_KS_PW')
    except ConfigParser.NoOptionError:
        # This value wasn't present in R2. So may be missing in upgrades from
        # that release
        LOG.info("CONFIG_CEPH_OBJECT_GATEWAY_KS_PW key not found. Generating "
                 "a new value")
        ceph_pwd = uuid.uuid4().hex[:10] + "TiC1*"

    secure_config.update({
        'platform::ceph::params::rgw_admin_password': ceph_pwd
    })

    ldap_hash = packstack_config.get('general',
                                     'CONFIG_LDAPADMIN_HASHED_PASSWORD')
    ldap_pwd = packstack_config.get('general',
                                    'CONFIG_LDAPADMIN_PASSWORD')
    secure_config.update({
        'platform::ldap::params::admin_hashed_pw': ldap_hash,
        'platform::ldap::params::admin_pw': ldap_pwd
    })


def get_service_user_config(hiera_db_records,
                            packstack_config,
                            config,
                            secure_config):
    # aodh user
    config.update({
        'aodh::db::postgresql::user': hiera_db_records['aodh']['username']
    })
    secure_config.update({
        'aodh::auth::auth_password': hiera_db_records['aodh']['ks_password'],
        'aodh::db::postgresql::password': hiera_db_records['aodh']['password'],
        'aodh::keystone::auth::password':
            hiera_db_records['aodh']['ks_password'],
        'aodh::keystone::authtoken::password':
            hiera_db_records['aodh']['ks_password']
    })

    # ceilometer user
    config.update({
        'ceilometer::db::postgresql::user':
            hiera_db_records['ceilometer']['username'],
    })
    secure_config.update({
        'ceilometer::agent::auth::auth_password':
            hiera_db_records['ceilometer']['ks_password'],
        'ceilometer::db::postgresql::password':
            hiera_db_records['ceilometer']['password'],
        'ceilometer::keystone::auth::password':
            hiera_db_records['ceilometer']['ks_password'],
        'ceilometer::keystone::authtoken::password':
            hiera_db_records['ceilometer']['ks_password']
    })

    # keystone user
    secure_config.update({
        'keystone::admin_password':
            hiera_db_records['keystone']['ks_password'],
        'keystone::admin_token':
            hiera_db_records['keystone']['admin_token'],
        'keystone::roles::admin::password':
            hiera_db_records['keystone']['ks_password']
    })
    if 'keystone' in hiera_db_records:
        config.update({
            'CONFIG_KEYSTONE_ADMIN_USERNAME':
                hiera_db_records['keystone']['ks_username'],
            'keystone::db::postgresql::user':
                hiera_db_records['keystone']['username']
        })
        secure_config.update({
            'CONFIG_KEYSTONE_ADMIN_PW':
                hiera_db_records['keystone']['ks_password'],
            'keystone::database_connection':
                get_db_connection(hiera_db_records, 'keystone'),
            'keystone::db::postgresql::password':
                hiera_db_records['keystone']['password']
        })

    if 'cinder' in hiera_db_records:
        # cinder user
        config.update({
            'cinder::db::postgresql::user':
                hiera_db_records['cinder']['username']
        })
        secure_config.update({
            'cinder::db::postgresql::password':
                hiera_db_records['cinder']['password'],
            'cinder::keystone::auth::password':
                hiera_db_records['cinder']['ks_password'],
            'cinder::keystone::authtoken::password':
                hiera_db_records['cinder']['ks_password']
        })

    if 'glance' in hiera_db_records:
        # glance user
        config.update({
            'glance::api::authtoken::username':
                hiera_db_records['glance']['ks_username'],
            'glance::db::postgresql::user':
                hiera_db_records['glance']['username'],
            'glance::registry::authtoken::username':
                hiera_db_records['glance']['ks_username']
        })
        secure_config.update({
            'glance::api::authtoken::password':
                hiera_db_records['glance']['ks_password'],
            'glance::db::postgresql::password':
                hiera_db_records['glance']['password'],
            'glance::keystone::auth::password':
                hiera_db_records['glance']['ks_password'],
            'glance::keystone::authtoken::password':
                hiera_db_records['glance']['ks_password'],
            'glance::registry::authtoken::password':
                hiera_db_records['glance']['ks_password']
        })

    # heat user
    config.update({
        'heat::db::postgresql::user':
            hiera_db_records['heat']['username']
    })
    secure_config.update({
        'heat::db::postgresql::password':
            hiera_db_records['heat']['password'],
        'heat::engine::auth_encryption_key':
            hiera_db_records['heat']['auth_key'],
        'heat::keystone::auth::password':
            hiera_db_records['heat']['ks_password'],
        'heat::keystone::auth_cfn::password':
            hiera_db_records['heat']['ks_password'],
        'heat::keystone::authtoken::password':
            hiera_db_records['heat']['ks_password'],
        'heat::keystone::domain::domain_password':
            hiera_db_records['heat']['domain_password']
    })

    # neutron
    config.update({
        'neutron::db::postgresql::user':
            hiera_db_records['neutron']['username']
    })
    secure_config.update({
        'neutron::agents::metadata::shared_secret':
            hiera_db_records['neutron']['metadata_passwd'],
        'neutron::db::postgresql::password':
            hiera_db_records['neutron']['password'],
        'neutron::keystone::auth::password':
            hiera_db_records['neutron']['ks_password'],
        'neutron::keystone::authtoken::password':
            hiera_db_records['neutron']['ks_password'],
        'neutron::server::notifications::password':
            hiera_db_records['nova']['ks_password']
    })

    # nova
    # in 18.xx placement user is new so have to add additional
    # config to setup endpoint urls in keystone.  This currently does
    # not suppport region mode.
    auth_region = packstack_config.get('general',
                                       'CONFIG_KEYSTONE_REGION')
    config.update({
        'nova::db::postgresql::user':
            hiera_db_records['nova']['username'],
        'nova::db::postgresql_api::user':
            hiera_db_records['nova_api']['username'],
        'nova::keystone::auth_placement::auth_name':
            hiera_db_records['placement']['ks_username'],
        'nova::keystone::auth_placement::admin_url':
            hiera_db_records['placement']['ks_admin_url'],
        'nova::keystone::auth_placement::internal_url':
            hiera_db_records['placement']['ks_internal_url'],
        'nova::keystone::auth_placement::public_url':
            hiera_db_records['placement']['ks_public_url'],
        'nova::keystone::auth_placement::region': auth_region
    })
    secure_config.update({
        'nova::api::neutron_metadata_proxy_shared_secret':
            hiera_db_records['neutron']['metadata_passwd'],
        'nova::db::postgresql::password':
            hiera_db_records['nova']['password'],
        'nova::db::postgresql_api::password':
            hiera_db_records['nova_api']['password'],
        'nova::keystone::auth::password':
            hiera_db_records['nova']['ks_password'],
        'nova::keystone::authtoken::password':
            hiera_db_records['nova']['ks_password'],
        'nova::network::neutron::neutron_password':
            hiera_db_records['neutron']['ks_password'],
        'nova_api_proxy::config::admin_password':
            hiera_db_records['nova']['ks_password'],
        'nova::keystone::auth_placement::password':
            hiera_db_records['placement']['ks_password'],
        'nova::placement::password':
            hiera_db_records['placement']['ks_password']
    })

    # patching user
    config.update({
        'patching::api::keystone_user':
            hiera_db_records['patching']['ks_username']
    })
    secure_config.update({
        'patching::api::keystone_password':
            hiera_db_records['patching']['ks_password'],
        'patching::keystone::auth::password':
            hiera_db_records['patching']['ks_password'],
        'patching::keystone::authtoken::password':
            hiera_db_records['patching']['ks_password']
    })

    # sysinv
    sysinv_database_connection = "postgresql://%s:%s@%s/%s" % (
        hiera_db_records['sysinv']['username'],
        hiera_db_records['sysinv']['password'],
        'localhost',
        'sysinv'
    )
    config.update({
        'sysinv::db::postgresql::user':
            hiera_db_records['sysinv']['username']
    })
    secure_config.update({
        'sysinv::api::keystone_password':
            hiera_db_records['sysinv']['ks_password'],
        'sysinv::database_connection': sysinv_database_connection,
        'sysinv::db::postgresql::password':
            hiera_db_records['sysinv']['password'],
        'sysinv::keystone::auth::password':
            hiera_db_records['sysinv']['ks_password']
    })

    # murano
    config.update({
        'murano::db::postgresql::user':
            hiera_db_records['murano']['username']
    })
    config.update({
        'murano::db::postgresql::password':
            hiera_db_records['murano']['password'],
        'murano::keystone::auth::password':
            hiera_db_records['murano']['ks_password'],
        'murano::keystone::authtoken::password':
            hiera_db_records['murano']['ks_password'],
        'murano::admin_password':
            hiera_db_records['murano']['ks_password']
    })

    try:
        admin_user_domain = packstack_config.get(
            'general', 'CONFIG_ADMIN_USER_DOMAIN_NAME')
    except ConfigParser.NoOptionError:
        # This value wasn't present in R2. So may be missing in upgrades from
        # that release
        LOG.info("CONFIG_ADMIN_USER_DOMAIN_NAME key not found. Using Default.")
        admin_user_domain = DEFAULT_DOMAIN_NAME

    try:
        admin_project_domain = packstack_config.get(
            'general', 'CONFIG_ADMIN_PROJECT_DOMAIN_NAME')
    except ConfigParser.NoOptionError:
        # This value wasn't present in R2. So may be missing in upgrades from
        # that release
        LOG.info("CONFIG_ADMIN_PROJECT_DOMAIN_NAME key not found. Using "
                 "Default.")
        admin_project_domain = DEFAULT_DOMAIN_NAME

    config.update({
        'openstack::client::params::admin_username':
            hiera_db_records['keystone']['ks_username'],
        'openstack::client::params::admin_user_domain':
            admin_user_domain,
        'openstack::client::params::admin_project_domain':
            admin_project_domain,
    })
    secure_config.update({
        'openstack::murano::params::auth_password':
            hiera_db_records['murano']['ks_password']
    })

    # magnum
    config.update({
        'magnum::db::postgresql::user':
            hiera_db_records['magnum']['username']
    })
    secure_config.update({
        'magnum::db::postgresql::password':
            hiera_db_records['magnum']['password'],
        'magnum::keystone::auth::password':
            hiera_db_records['magnum']['ks_password'],
        'magnum::keystone::authtoken::password':
            hiera_db_records['magnum']['ks_password'],
        'magnum::keystone::domain::domain_password':
            hiera_db_records['magnum-domain']['ks_password']
    })

    # mtc
    # project and domains are also required for manifest to create the user
    auth_project = packstack_config.get('general',
                                        'CONFIG_SERVICE_TENANT_NAME')
    try:
        auth_user_domain = packstack_config.get(
            'general', 'CONFIG_SERVICE_USER_DOMAIN_NAME')
    except ConfigParser.NoOptionError:
        # This value wasn't present in R2. So may be missing in upgrades from
        # that release
        LOG.info("CONFIG_SERVICE_USER_DOMAIN_NAME key not found. Using "
                 "Default.")
        auth_user_domain = DEFAULT_DOMAIN_NAME

    try:
        auth_project_domain = packstack_config.get(
            'general', 'CONFIG_SERVICE_PROJECT_DOMAIN_NAME')
    except ConfigParser.NoOptionError:
        # This value wasn't present in R2. So may be missing in upgrades from
        # that release
        LOG.info("CONFIG_SERVICE_PROJECT_DOMAIN_NAME key not found. Using "
                 "Default.")
        auth_project_domain = DEFAULT_DOMAIN_NAME

    config.update({
        'platform::mtce::params::auth_username':
            hiera_db_records['mtce']['ks_username'],
        'platform::mtce::params::auth_project': auth_project,
        'platform::mtce::params::auth_user_domain': auth_user_domain,
        'platform::mtce::params::auth_project_domain': auth_project_domain
    })
    secure_config.update({
        'platform::mtce::params::auth_pw':
            hiera_db_records['mtce']['ks_password'],
    })

    # nfv
    secure_config.update({
        'nfv::keystone::auth::password':
            hiera_db_records['vim']['ks_password']
    })

    # ironic
    config.update({
        'ironic::db::postgresql::user':
            hiera_db_records['ironic']['username'],
    })
    secure_config.update({
        'ironic::db::postgresql::password':
            hiera_db_records['ironic']['password'],
        'ironic::keystone::auth::password':
            hiera_db_records['ironic']['ks_password'],
        'ironic::keystone::authtoken::password':
            hiera_db_records['ironic']['ks_password'],
        'ironic::api::authtoken::password':
            hiera_db_records['ironic']['ks_password']
    })

    # panko
    config.update({
        'panko::db::postgresql::user':
            hiera_db_records['panko']['username']
    })
    secure_config.update({
        'panko::db::postgresql::password':
            hiera_db_records['panko']['password'],
        'panko::keystone::auth::password':
            hiera_db_records['panko']['ks_password'],
        'panko::keystone::authtoken::password':
            hiera_db_records['panko']['ks_password']
    })


def get_nova_ssh_keys(config, secure_config):
    # retrieve the nova ssh keys
    ssh_config_dir = os.path.join(CONFIG_PATH, 'ssh_config')
    migration_key = os.path.join(ssh_config_dir, 'nova_migration_key')
    system_host_key = os.path.join(ssh_config_dir, 'system_host_key')
    if not os.path.isdir(ssh_config_dir):
        LOG.error("ssh_config directory %s not found" % ssh_config_dir)
        return config

    # Read the public/private migration keys
    with open(migration_key) as fp:
        migration_private = fp.read().strip()
    with open('%s.pub' % migration_key) as fp:
        migration_public = fp.read().strip().split()[1]

    # Read the public/private host keys
    with open(system_host_key) as fp:
        host_private = fp.read().strip()
    with open('%s.pub' % system_host_key) as fp:
        host_header, host_public, _ = fp.read().strip().split()

    # Add our pre-generated system host key to /etc/ssh/ssh_known_hosts
    ssh_keys = {
        'system_host_key': {
            'ensure': 'present',
            'name': '*',
            'host_aliases': [],
            'type': host_header,
            'key': host_public
        }
    }
    migration_key_type = 'ssh-rsa'
    host_key_type = 'ssh-ecdsa'
    secure_config.update({
        'openstack::nova::compute::ssh_keys': ssh_keys,
        'openstack::nova::compute::host_key_type': host_key_type,
        'openstack::nova::compute::host_private_key': host_private,
        'openstack::nova::compute::host_public_key': host_public,
        'openstack::nova::compute::host_public_header': host_header,
        'openstack::nova::compute::migration_key_type': migration_key_type,
        'openstack::nova::compute::migration_private_key':
            migration_private,
        'openstack::nova::compute::migration_public_key':
            migration_public,
    })


def get_openstack_config(packstack_config, config, secure_config):
    horizon_key = packstack_config.get('general',
                                       'CONFIG_HORIZON_SECRET_KEY')
    config.update({
        'openstack::client::credentials::params::keyring_base':
            os.path.dirname(KEYRING_PATH),
        'openstack::client::credentials::params::keyring_directory':
            KEYRING_PATH,
        'openstack::client::credentials::params::keyring_file':
            os.path.join(KEYRING_PATH, '.CREDENTIAL'),
    })
    secure_config.update({
        'openstack::horizon::params::secret_key': horizon_key
    })

    get_nova_ssh_keys(config, secure_config)


def write_hieradata(config, secure_config):
    filename = 'static.yaml'
    secure_filename = 'secure_static.yaml'
    path = constants.HIERADATA_PERMDIR
    try:
        os.makedirs(path)
        filepath = os.path.join(path, filename)
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
        secure_filepath = os.path.join(path, secure_filename)
        fd, tmppath = tempfile.mkstemp(dir=path, prefix=secure_filename,
                                       text=True)
        with open(tmppath, 'w') as f:
            yaml.dump(secure_config, f, default_flow_style=False)
        os.close(fd)
        os.rename(tmppath, secure_filepath)
    except Exception:
        LOG.exception("failed to write secure config: %s" % secure_filepath)
        raise


def generate_simplex_upgrade_hiera_record(to_release, hiera_db_records,
                                          packstack_config):
    """ generate static records from the packstack config. """
    LOG.info("Migrating packstack answer file to hiera data")

    config = {}
    secure_config = {}
    get_platform_config(packstack_config,
                        to_release,
                        config,
                        secure_config)
    get_service_user_config(hiera_db_records,
                            packstack_config,
                            config,
                            secure_config)
    get_openstack_config(packstack_config,
                         config,
                         secure_config)

    write_hieradata(config, secure_config)


def generate_upgrade_hiera_record(to_release, hiera_db_records,
                                  packstack_config):
    """ generate static records from the packstack config. """
    LOG.info("Migrating packstack answer file to hiera data")

    config = {}
    secure_config = {}
    config.update({'platform::params::controller_upgrade': True})
    get_platform_config(packstack_config,
                        to_release,
                        config,
                        secure_config)
    get_service_user_config(hiera_db_records,
                            packstack_config,
                            config,
                            secure_config)
    get_openstack_config(packstack_config,
                         config,
                         secure_config)
    get_upgrade_token(hiera_db_records,
                      packstack_config,
                      config,
                      secure_config)

    write_hieradata(config, secure_config)


def create_simplex_runtime_config(filename):
    """ Create any runtime parameters needed for simplex upgrades"""
    config = {}
    # We need to disable nova cellv2 setup as this was done during the data
    # migration
    config.update({'nova::db::sync_api::cellv2_setup': False})
    cutils.create_manifest_runtime_config(filename, config)


def get_packstack_config(software_release):
    from_config = os.path.join(PLATFORM_PATH, "packstack", software_release,
                               "config")
    answer_file = os.path.join(from_config, "packstack-answers.txt")

    packstack_config = ConfigParser.RawConfigParser()
    # Preserve the case in the answer file
    packstack_config.optionxform = lambda option: option
    try:
        packstack_config.read(answer_file)
    except Exception:
        LOG.exception("Error parsing answer file %s" % answer_file)
        raise
    return packstack_config


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
