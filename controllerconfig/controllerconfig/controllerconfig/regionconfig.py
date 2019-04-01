"""
Copyright (c) 2015-2019 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from __future__ import print_function
from six.moves import configparser
import os
import subprocess
import sys
import textwrap
import time
from controllerconfig import utils
import uuid

from controllerconfig.common import constants
from controllerconfig.common import log
from controllerconfig.common import rest_api_utils as rutils
from controllerconfig.common.exceptions import KeystoneFail
from controllerconfig.common.configobjects import REGION_CONFIG
from controllerconfig.common.configobjects import SUBCLOUD_CONFIG
from controllerconfig import ConfigFail
from controllerconfig.configassistant import ConfigAssistant
from netaddr import IPAddress
from controllerconfig.systemconfig import parse_system_config
from controllerconfig.systemconfig import configure_management_interface
from controllerconfig.systemconfig import create_cgcs_config_file
from controllerconfig import DEFAULT_DOMAIN_NAME

# Temporary file for building cgcs_config
TEMP_CGCS_CONFIG_FILE = "/tmp/cgcs_config"

# For region mode, this is the list of users that we expect to find configured
# in the region config file as <USER>_USER_KEY and <USER>_PASSWORD.
# For distributed cloud, this is the list of users that we expect to find
# configured in keystone. The password for each user will be retrieved from
# the DC Manager in the system controller and added to the region config file.
# The format is:
#   REGION_NAME = key in region config file for this user's region
#   USER_KEY = key in region config file for this user's name
#   USER_NAME = user name in keystone

REGION_NAME = 0
USER_KEY = 1
USER_NAME = 2

EXPECTED_USERS = [
    ('REGION_2_SERVICES', 'SYSINV', 'sysinv'),
    ('REGION_2_SERVICES', 'PATCHING', 'patching'),
    ('REGION_2_SERVICES', 'NFV', 'vim'),
    ('REGION_2_SERVICES', 'MTCE', 'mtce'),
    ('REGION_2_SERVICES', 'FM', 'fm'),
    ('REGION_2_SERVICES', 'BARBICAN', 'barbican')]

# This a description of the region 2 endpoints that we expect to configure or
# find configured in keystone. The format is as follows:
#   SERVICE_NAME = key in region config file for this service's name
#   SERVICE_TYPE = key in region config file for this service's type
#   PUBLIC_URL = required publicurl - {} is replaced with CAM floating IP
#   INTERNAL_URL = required internalurl - {} is replaced with CLM floating IP
#   ADMIN_URL = required adminurl - {} is replaced with CLM floating IP
#   DESCRIPTION = Description of the service (for automatic configuration)

SERVICE_NAME = 0
SERVICE_TYPE = 1
PUBLIC_URL = 2
INTERNAL_URL = 3
ADMIN_URL = 4
DESCRIPTION = 5

EXPECTED_REGION2_ENDPOINTS = [
    ('SYSINV_SERVICE_NAME', 'SYSINV_SERVICE_TYPE',
     'http://{}:6385/v1',
     'http://{}:6385/v1',
     'http://{}:6385/v1',
     'SysInv Service'),
    ('PATCHING_SERVICE_NAME', 'PATCHING_SERVICE_TYPE',
     'http://{}:15491',
     'http://{}:5491',
     'http://{}:5491',
     'Patching Service'),
    ('NFV_SERVICE_NAME', 'NFV_SERVICE_TYPE',
     'http://{}:4545',
     'http://{}:4545',
     'http://{}:4545',
     'Virtual Infrastructure Manager'),
    ('FM_SERVICE_NAME', 'FM_SERVICE_TYPE',
     'http://{}:18002',
     'http://{}:18002',
     'http://{}:18002',
     'Fault Management Service'),
    ('BARBICAN_SERVICE_NAME', 'BARBICAN_SERVICE_TYPE',
     'http://{}:9311',
     'http://{}:9311',
     'http://{}:9311',
     'OpenStack Key Manager Service'),
]

EXPECTED_KEYSTONE_ENDPOINT = (
    'KEYSTONE_SERVICE_NAME', 'KEYSTONE_SERVICE_TYPE',
    'http://{}:8081/keystone/main/v2.0',
    'http://{}:8081/keystone/main/v2.0',
    'http://{}:8081/keystone/admin/v2.0',
    'OpenStack Identity')


LOG = log.get_logger(__name__)


def validate_region_one_keystone_config(region_config, token, api_url, users,
                                        services, endpoints, create=False,
                                        config_type=REGION_CONFIG,
                                        user_config=None):
    """ Validate that the required region one configuration are in place,
        if create is True, any missing entries will be set up to be added
        to keystone later on by puppet.
    """

    region_1_name = region_config.get('SHARED_SERVICES', 'REGION_NAME')
    region_2_name = region_config.get('REGION_2_SERVICES', 'REGION_NAME')

    # Determine what keystone entries are expected
    expected_users = EXPECTED_USERS
    expected_region_2_endpoints = EXPECTED_REGION2_ENDPOINTS
    # Keystone is always in region 1
    expected_region_1_endpoints = [EXPECTED_KEYSTONE_ENDPOINT]

    domains = rutils.get_domains(token, api_url)
    # Verify service project domain, creating if necessary
    if region_config.has_option('REGION_2_SERVICES', 'PROJECT_DOMAIN_NAME'):
        project_domain = region_config.get('REGION_2_SERVICES',
                                           'PROJECT_DOMAIN_NAME')
    else:
        project_domain = DEFAULT_DOMAIN_NAME
    project_domain_id = domains.get_domain_id(project_domain)
    if not project_domain_id:
        if create and config_type == REGION_CONFIG:
            region_config.set('REGION_2_SERVICES', 'PROJECT_DOMAIN_NAME',
                              project_domain)
        else:
            raise ConfigFail(
                "Keystone configuration error: service project domain '%s' is "
                "not configured." % project_domain)

    # Verify service project, creating if necessary
    if region_config.has_option('SHARED_SERVICES',
                                'SERVICE_PROJECT_NAME'):
        service_project = region_config.get('SHARED_SERVICES',
                                            'SERVICE_PROJECT_NAME')
    else:
        service_project = region_config.get('SHARED_SERVICES',
                                            'SERVICE_TENANT_NAME')
    projects = rutils.get_projects(token, api_url)
    project_id = projects.get_project_id(service_project)
    if not project_id:
        if create and config_type == REGION_CONFIG:
            region_config.set('SHARED_SERVICES', 'SERVICE_TENANT_NAME',
                              service_project)
        else:
            raise ConfigFail(
                "Keystone configuration error: service project '%s' is not "
                "configured." % service_project)

    # Verify and retrieve the id of the admin role (only needed when creating)
    roles = rutils.get_roles(token, api_url)
    role_id = roles.get_role_id('admin')
    if not role_id and create:
        raise ConfigFail("Keystone configuration error: No admin role present")

    # verify that the service user domain is configured, creating if necessary
    if region_config.has_option('REGION_2_SERVICES', 'USER_DOMAIN_NAME'):
        user_domain = region_config.get('REGION_2_SERVICES',
                                        'USER_DOMAIN_NAME')
    else:
        user_domain = DEFAULT_DOMAIN_NAME
    domains = rutils.get_domains(token, api_url)
    user_domain_id = domains.get_domain_id(user_domain)
    if not user_domain_id:
        if create and config_type == REGION_CONFIG:
            region_config.set('REGION_2_SERVICES',
                              'USER_DOMAIN_NAME')
        else:
            raise ConfigFail(
                "Unable to obtain id for for %s domain. Please ensure "
                "keystone configuration is correct." % user_domain)

    auth_url = region_config.get('SHARED_SERVICES', 'KEYSTONE_ADMINURL')
    if config_type == REGION_CONFIG:
        # Verify that all users are configured and can retrieve a token,
        # Optionally set up to create missing users + their admin role
        for user in expected_users:
            auth_user = region_config.get(user[REGION_NAME],
                                          user[USER_KEY] + '_USER_NAME')
            user_id = users.get_user_id(auth_user)
            auth_password = None
            if not user_id and create:
                if not region_config.has_option(
                        user[REGION_NAME], user[USER_KEY] + '_PASSWORD'):
                    # Generate random password for new user via
                    # /dev/urandom if necessary
                    try:
                        region_config.set(
                            user[REGION_NAME], user[USER_KEY] + '_PASSWORD',
                            uuid.uuid4().hex[:10] + "TiC2*")
                    except Exception as e:
                        raise ConfigFail("Failed to generate random user "
                                         "password: %s" % e)
            elif user_id and user_domain_id and\
                    project_id and project_domain_id:
                # If there is a user_id existing then we cannot use
                # a randomized password as it was either created by
                # a previous run of regionconfig or was created as
                # part of Titanium Cloud Primary region config
                if not region_config.has_option(
                        user[REGION_NAME], user[USER_KEY] + '_PASSWORD'):
                    raise ConfigFail("Failed to find configured password "
                                     "for pre-defined user %s" % auth_user)
                auth_password = region_config.get(user[REGION_NAME],
                                                  user[USER_KEY] + '_PASSWORD')
                # Verify that the existing user can seek an auth token
                user_token = rutils.get_token(auth_url, service_project,
                                              auth_user,
                                              auth_password, user_domain,
                                              project_domain)
                if not user_token:
                    raise ConfigFail(
                        "Unable to obtain keystone token for %s user. "
                        "Please ensure keystone configuration is correct."
                        % auth_user)
    else:
        # For subcloud configs we re-use the users from the system controller
        # (the primary region).
        for user in expected_users:
            auth_user = user[USER_NAME]
            user_id = users.get_user_id(auth_user)
            auth_password = None

            if user_id:
                # Add the password to the region config so it will be used when
                # configuring services.
                auth_password = user_config.get_password(user[USER_NAME])
                region_config.set(user[REGION_NAME],
                                  user[USER_KEY] + '_PASSWORD',
                                  auth_password)
            else:
                raise ConfigFail(
                    "Unable to obtain user (%s). Please ensure "
                    "keystone configuration is correct." % user[USER_NAME])

            # Verify that the existing user can seek an auth token
            user_token = rutils.get_token(auth_url, service_project, auth_user,
                                          auth_password, user_domain,
                                          project_domain)
            if not user_token:
                raise ConfigFail(
                    "Unable to obtain keystone token for %s user. "
                    "Please ensure keystone configuration is correct." %
                    auth_user)

    # Verify that region two endpoints & services for shared services
    # match our requirements, optionally creating missing entries
    for endpoint in expected_region_1_endpoints:
        service_name = region_config.get('SHARED_SERVICES',
                                         endpoint[SERVICE_NAME])
        service_type = region_config.get('SHARED_SERVICES',
                                         endpoint[SERVICE_TYPE])

        try:
            service_id = services.get_service_id(service_name, service_type)
        except KeystoneFail as ex:
            # No option to create services for region one, if those are not
            # present, something is seriously wrong
            raise ex

        # Extract region one url information from the existing endpoint entry:
        try:
            endpoints.get_service_url(
                region_1_name, service_id, "public")
            endpoints.get_service_url(
                region_1_name, service_id, "internal")
            endpoints.get_service_url(
                region_1_name, service_id, "admin")
        except KeystoneFail as ex:
                # Fail since shared services endpoints are not found
                raise ConfigFail("Endpoint for shared service %s "
                                 "is not configured" % service_name)

    # Verify that region two endpoints & services match our requirements,
    # optionally creating missing entries
    public_address = utils.get_optional(region_config, 'CAN_NETWORK',
                                        'CAN_IP_START_ADDRESS')
    if not public_address:
        public_address = utils.get_optional(region_config, 'CAN_NETWORK',
                                            'CAN_IP_FLOATING_ADDRESS')
    if not public_address:
        public_address = utils.get_optional(region_config, 'OAM_NETWORK',
                                            'IP_START_ADDRESS')
    if not public_address:
        # AIO-SX configuration
        public_address = utils.get_optional(region_config, 'OAM_NETWORK',
                                            'IP_ADDRESS')
    if not public_address:
        public_address = region_config.get('OAM_NETWORK',
                                           'IP_FLOATING_ADDRESS')

    if region_config.has_section('CLM_NETWORK'):
        internal_address = region_config.get('CLM_NETWORK',
                                             'CLM_IP_START_ADDRESS')
    else:
        internal_address = region_config.get('MGMT_NETWORK',
                                             'IP_START_ADDRESS')

    internal_infra_address = utils.get_optional(
        region_config, 'BLS_NETWORK', 'BLS_IP_START_ADDRESS')
    if not internal_infra_address:
        internal_infra_address = utils.get_optional(
            region_config, 'INFRA_NETWORK', 'IP_START_ADDRESS')

    for endpoint in expected_region_2_endpoints:
        service_name = utils.get_service(region_config, 'REGION_2_SERVICES',
                                         endpoint[SERVICE_NAME])
        service_type = utils.get_service(region_config, 'REGION_2_SERVICES',
                                         endpoint[SERVICE_TYPE])
        service_id = services.get_service_id(service_name, service_type)

        expected_public_url = endpoint[PUBLIC_URL].format(public_address)

        if internal_infra_address and service_type == 'image':
            nfs_address = IPAddress(internal_infra_address) + 3
            expected_internal_url = endpoint[INTERNAL_URL].format(nfs_address)
            expected_admin_url = endpoint[ADMIN_URL].format(nfs_address)
        else:
            expected_internal_url = endpoint[INTERNAL_URL].format(
                internal_address)
            expected_admin_url = endpoint[ADMIN_URL].format(internal_address)

        try:
            public_url = endpoints.get_service_url(region_2_name, service_id,
                                                   "public")
            internal_url = endpoints.get_service_url(region_2_name, service_id,
                                                     "internal")
            admin_url = endpoints.get_service_url(region_2_name, service_id,
                                                  "admin")
        except KeystoneFail as ex:
            # The endpoint will be created optionally
            if not create:
                raise ConfigFail("Keystone configuration error: Unable to "
                                 "find endpoints for service %s"
                                 % service_name)
            continue

        # Validate the existing endpoints
        for endpointtype, found, expected in [
                ('public', public_url, expected_public_url),
                ('internal', internal_url, expected_internal_url),
                ('admin', admin_url, expected_admin_url)]:
            if found != expected:
                raise ConfigFail(
                    "Keystone configuration error for:\nregion ({}), "
                    "service name ({}), service type ({})\n"
                    "expected {}: {}\nconfigured {}: {}".format(
                        region_2_name, service_name, service_type,
                        endpointtype, expected, endpointtype, found))


def validate_region_one_ldap_config(region_config):
    """Validate ldap on region one by a ldap search"""

    ldapserver_uri = region_config.get('SHARED_SERVICES', 'LDAP_SERVICE_URL')
    cmd = ["ldapsearch", "-xH", ldapserver_uri,
           "-b", "dc=cgcs,dc=local", "(objectclass=*)"]
    try:
        with open(os.devnull, "w") as fnull:
            subprocess.check_call(cmd, stdout=fnull, stderr=fnull)
    except subprocess.CalledProcessError:
        raise ConfigFail("LDAP configuration error: not accessible")


def set_subcloud_config_defaults(region_config):
    """Set defaults in region_config for subclouds"""

    # We always create endpoints for subclouds
    region_config.set('REGION_2_SERVICES', 'CREATE', 'Y')

    # We use the default service project
    region_config.set('SHARED_SERVICES', 'SERVICE_PROJECT_NAME',
                      constants.DEFAULT_SERVICE_PROJECT_NAME)

    # Add the necessary users to the region config, which will allow the
    # validation code to run and will later result in services being
    # configured to use the users from the system controller.
    expected_users = EXPECTED_USERS

    for user in expected_users:
        # Add the user to the region config so to allow validation.
        region_config.set(user[REGION_NAME], user[USER_KEY] + '_USER_NAME',
                          user[USER_NAME])


def configure_region(config_file, config_type=REGION_CONFIG):
    """Configure the region"""

    # Parse the region/subcloud config file
    print("Parsing configuration file... ", end=' ')
    region_config = parse_system_config(config_file)
    print("DONE")

    if config_type == SUBCLOUD_CONFIG:
        # Set defaults in region_config for subclouds
        set_subcloud_config_defaults(region_config)

    # Validate the region/subcloud config file
    print("Validating configuration file... ", end=' ')
    try:
        create_cgcs_config_file(None, region_config, None, None, None,
                                config_type=config_type,
                                validate_only=True)
    except configparser.Error as e:
        raise ConfigFail("Error parsing configuration file %s: %s" %
                         (config_file, e))
    print("DONE")

    # Bring up management interface to allow us to reach Region 1
    print("Configuring management interface... ", end=' ')
    configure_management_interface(region_config, config_type=config_type)
    print("DONE")

    # Get token from keystone
    print("Retrieving keystone token...", end=' ')
    sys.stdout.flush()
    auth_url = region_config.get('SHARED_SERVICES', 'KEYSTONE_ADMINURL')
    if region_config.has_option('SHARED_SERVICES', 'ADMIN_TENANT_NAME'):
        auth_project = region_config.get('SHARED_SERVICES',
                                         'ADMIN_TENANT_NAME')
    else:
        auth_project = region_config.get('SHARED_SERVICES',
                                         'ADMIN_PROJECT_NAME')
    auth_user = region_config.get('SHARED_SERVICES', 'ADMIN_USER_NAME')
    auth_password = region_config.get('SHARED_SERVICES', 'ADMIN_PASSWORD')
    if region_config.has_option('SHARED_SERVICES', 'ADMIN_USER_DOMAIN'):
        admin_user_domain = region_config.get('SHARED_SERVICES',
                                              'ADMIN_USER_DOMAIN')
    else:
        admin_user_domain = DEFAULT_DOMAIN_NAME
    if region_config.has_option('SHARED_SERVICES',
                                'ADMIN_PROJECT_DOMAIN'):
        admin_project_domain = region_config.get('SHARED_SERVICES',
                                                 'ADMIN_PROJECT_DOMAIN')
    else:
        admin_project_domain = DEFAULT_DOMAIN_NAME

    attempts = 0
    token = None
    # Wait for connectivity to region one. It can take some time, especially if
    # we have LAG on the management network.
    while not token:
        token = rutils.get_token(auth_url, auth_project, auth_user,
                                 auth_password, admin_user_domain,
                                 admin_project_domain)
        if not token:
            attempts += 1
            if attempts < 10:
                print("\rRetrieving keystone token...{}".format(
                    '.' * attempts), end=' ')
                sys.stdout.flush()
                time.sleep(10)
            else:
                raise ConfigFail(
                    "Unable to obtain keystone token. Please ensure "
                    "networking and keystone configuration is correct.")
    print("DONE")

    # Get services, endpoints, users and domains from keystone
    print("Retrieving services, endpoints and users from keystone... ",
          end=' ')
    region_name = region_config.get('SHARED_SERVICES', 'REGION_NAME')
    service_name = region_config.get('SHARED_SERVICES',
                                     'KEYSTONE_SERVICE_NAME')
    service_type = region_config.get('SHARED_SERVICES',
                                     'KEYSTONE_SERVICE_TYPE')

    api_url = token.get_service_url(
        region_name, service_name, service_type, "admin").replace(
        'v2.0', 'v3')

    services = rutils.get_services(token, api_url)
    endpoints = rutils.get_endpoints(token, api_url)
    users = rutils.get_users(token, api_url)
    domains = rutils.get_domains(token, api_url)
    if not services or not endpoints or not users:
        raise ConfigFail(
            "Unable to retrieve services, endpoints or users from keystone. "
            "Please ensure networking and keystone configuration is correct.")
    print("DONE")

    user_config = None
    if config_type == SUBCLOUD_CONFIG:
        # Retrieve subcloud configuration from dcmanager
        print("Retrieving configuration from dcmanager... ", end=' ')
        dcmanager_url = token.get_service_url(
            'SystemController', 'dcmanager', 'dcmanager', "admin")
        subcloud_name = region_config.get('REGION_2_SERVICES',
                                          'REGION_NAME')
        subcloud_management_subnet = region_config.get('MGMT_NETWORK',
                                                       'CIDR')
        hash_string = subcloud_name + subcloud_management_subnet
        subcloud_config = rutils.get_subcloud_config(token, dcmanager_url,
                                                     subcloud_name,
                                                     hash_string)
        user_config = subcloud_config['users']
        print("DONE")

    try:
        # Configure missing region one keystone entries
        create = True
        # Prepare region configuration for puppet to create keystone identities
        if (region_config.has_option('REGION_2_SERVICES', 'CREATE') and
                region_config.get('REGION_2_SERVICES', 'CREATE') == 'Y'):
            print("Preparing keystone configuration... ", end=' ')
        # If keystone configuration for this region already in place,
        # validate it only
        else:
            # Validate region one keystone config
            create = False
            print("Validating keystone configuration... ", end=' ')

        validate_region_one_keystone_config(region_config, token, api_url,
                                            users, services, endpoints, create,
                                            config_type=config_type,
                                            user_config=user_config)
        print("DONE")

        # validate ldap if it is shared
        if region_config.has_option('SHARED_SERVICES', 'LDAP_SERVICE_URL'):
            print("Validating ldap configuration... ", end=' ')
            validate_region_one_ldap_config(region_config)
            print("DONE")

        # Create cgcs_config file
        print("Creating config apply file... ", end=' ')
        try:
            create_cgcs_config_file(TEMP_CGCS_CONFIG_FILE, region_config,
                                    services, endpoints, domains,
                                    config_type=config_type)
        except configparser.Error as e:
            raise ConfigFail("Error parsing configuration file %s: %s" %
                             (config_file, e))
        print("DONE")

        # Configure controller
        assistant = ConfigAssistant()
        assistant.configure(TEMP_CGCS_CONFIG_FILE, display_config=False)

    except ConfigFail as e:
        print("A configuration failure has occurred.", end=' ')
        raise e


def show_help_region():
    print("Usage: %s [OPTIONS] <CONFIG_FILE>" % sys.argv[0])
    print(textwrap.fill(
        "Perform region configuration using the region "
        "configuration from CONFIG_FILE.", 80))
    print("--allow-ssh              Allow configuration to be executed in "
          "ssh\n")


def show_help_subcloud():
    print("Usage: %s [OPTIONS] <CONFIG_FILE>" % sys.argv[0])
    print(textwrap.fill(
          "Perform subcloud configuration using the subcloud "
          "configuration from CONFIG_FILE.", 80))
    print("--allow-ssh              Allow configuration to be executed in "
          "ssh\n")


def config_main(config_type=REGION_CONFIG):
    allow_ssh = False
    if config_type == REGION_CONFIG:
        config_file = "/home/wrsroot/region_config"
    elif config_type == SUBCLOUD_CONFIG:
        config_file = "/home/wrsroot/subcloud_config"
    else:
        raise ConfigFail("Invalid config_type: %s" % config_type)

    arg = 1
    while arg < len(sys.argv):
        if sys.argv[arg] in ['--help', '-h', '-?']:
            if config_type == REGION_CONFIG:
                show_help_region()
            else:
                show_help_subcloud()
            exit(1)
        elif sys.argv[arg] == "--allow-ssh":
            allow_ssh = True
        elif arg == len(sys.argv) - 1:
            config_file = sys.argv[arg]
        else:
            print("Invalid option. Use --help for more information.")
            exit(1)
        arg += 1

    log.configure()

    # Check if that the command is being run from the console
    if utils.is_ssh_parent():
        if allow_ssh:
            print(textwrap.fill(constants.SSH_WARNING_MESSAGE, 80))
            print('')
        else:
            print(textwrap.fill(constants.SSH_ERROR_MESSAGE, 80))
            exit(1)

    if not os.path.isfile(config_file):
        print("Config file %s does not exist." % config_file)
        exit(1)

    try:
        configure_region(config_file, config_type=config_type)
    except KeyboardInterrupt:
        print("\nAborting configuration")
    except ConfigFail as e:
        LOG.exception(e)
        print("\nConfiguration failed: {}".format(e))
    except Exception as e:
        LOG.exception(e)
        print("\nConfiguration failed: {}".format(e))
    else:
        print("\nConfiguration finished successfully.")
    finally:
        if os.path.isfile(TEMP_CGCS_CONFIG_FILE):
            os.remove(TEMP_CGCS_CONFIG_FILE)


def region_main():
    config_main(REGION_CONFIG)


def subcloud_main():
    config_main(SUBCLOUD_CONFIG)
