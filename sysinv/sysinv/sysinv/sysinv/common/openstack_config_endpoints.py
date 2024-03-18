#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy
import os

from oslo_config import cfg
from oslo_log import log as logging

from sysinv.common import constants
from sysinv.common.retrying import retry
from sysinv.conductor import openstack
from sysinv.db import api as dbapi
from sysinv.puppet import puppet


LOG = logging.getLogger(__name__)

ENDPONTS_RECONFIGURED_FLAG_PATH = '/etc/platform/.service_endpoint_reconfigured'
RC_FILE_PATH = '/etc/platform/openrc'

# Users that should exist in every system independently of its system type
# NOTE: Not the full user list, only the ones necessary for endpoint
# reconfiguration are listed here
BASE_USERS = [
    'patching',
    'usm',
    'vim',
    'smapi',
    'barbican'
]

ADDITIONAL_SYSTEMCONTROLLER_USERS = [
    'dcorch',
    'dcmanager',
    'dcdbsync'
]

ADDITIONAL_SUBCLOUD_USERS = [
    'dcmanager',
    'dcdbsync'
]

# Services that should exist in every system independently of its system type
BASE_SERVICES = [
    {
        'name': 'keystone',
        'description': '',
        'type': 'identity',
    },
    {
        'name': 'barbican',
        'description': 'Key management Service',
        'type': 'key-manager',
    },
    {
        'name': 'sysinv',
        'description': 'SysInvService',
        'type': 'platform',
    },
    {
        'name': 'fm',
        'description': 'Fault Management Service',
        'type': 'faultmanagement',
    },
    {
        'name': 'patching',
        'description': 'Patching Service',
        'type': 'patching',
    },
    {
        'name': 'usm',
        'description': 'USM Service',
        'type': 'usm'
    },
    {
        'name': 'vim',
        'description': 'Virtual Infrastructure Manager',
        'type': 'nfv'
    },
    {
        'name': 'smapi',
        'description': 'sm-api service',
        'type': 'smapi'
    },
]

ADDITIONAL_SYSTEMCONTROLLER_SERVICES = [
    {
        'name': 'dcorch',
        'description': 'DcOrchService',
        'type': 'dcorch'
    },
    {
        'name': 'dcmanager',
        'description': 'DCManagerService',
        'type': 'dcmanager'
    },
    {
        'name': 'dcdbsync',
        'description': 'DCOrch DBsync service',
        'type': 'dcorch-dbsync'
    },
]

ADDITIONAL_SUBCLOUD_SERVICES = [
    {
        'name': 'dcmanager',
        'description': 'DCManagerService',
        'type': 'dcmanager'
    },
    {
        'name': 'dcdbsync',
        'description': 'DCOrch DBsync service',
        'type': 'dcorch-dbsync'
    },
]

# Services that should have endpoints in every system
# independently of its system type
SERVICES_WITH_ENDPOINTS = [
    'keystone',
    'sysinv',
    'fm',
    'barbican',
    'patching',
    'usm',
    'vim',
    'smapi'
]

# Endpoints that will be created with SystemController region
SERVICES_WITH_ADITIONAL_SYSTEMCONTROLLER_ENDPOINTS = [
    'keystone',
    'sysinv',
    'patching',
    'usm',
    'vim',
    'dcmanager'
]

# DC services where endpoints will be created in RegionOne
SERVICES_WITH_ADITIONAL_DC_ENDPOINTS = [
    'dcdbsync'
]

ENDPOINTS_INTERFACES = ['admin', 'internal', 'public']

# Services that have different ports and paths for SystemController region
SERVICES_PORTS_PATHS_MAP = {
    'keystone': {'port': 'IDENTITY_SERVICE_PORT', 'path': 'IDENTITY_SERVICE_PATH'},
    'sysinv': {'port': 'PLATFORM_SERVICE_PORT', 'path': 'PLATFORM_SERVICE_PATH'},
    'patching': {'port': 'PATCHING_SERVICE_PORT', 'path': 'PATCHING_SERVICE_PATH'},
    'usm': {'port': 'USM_SERVICE_PORT', 'path': 'USM_SERVICE_PATH'},
    'vim': {'port': 'NFV_SERVICE_PORT', 'path': 'NFV_SERVICE_PATH'},
}


@retry(stop_max_attempt_number=3, wait_fixed=1000)
def create_users(keystone, users_to_create):
    if not users_to_create:
        LOG.info('No users to create')
        return
    existing_users = keystone.users.list()
    existing_users_list = [user.name for user in existing_users]

    for user_info in users_to_create:
        username = user_info['name']
        if username in existing_users_list:
            LOG.info(f"User {username} already exists")
            continue
        keystone.users.create(
            name=username,
            password=user_info['password'],
            email=user_info['email'],
            domain='default',
            enabled=True
        )
        LOG.info(f"User {username} successfully created")


@retry(stop_max_attempt_number=3, wait_fixed=1000)
def grant_admin_role(keystone, users_to_create, project_name):
    roles_dict = {role.name: role.id for role in keystone.roles.list()}
    users_dict = {user.name: user.id for user in keystone.users.list()}
    project_dict = {project.name: project.id
                    for project in keystone.projects.list()}
    project_id = project_dict[project_name]
    admin_role_id = roles_dict['admin']
    users_with_admin_role = [
        assign_role.user['id'] for assign_role in
        keystone.role_assignments.list() if
        assign_role.role['id'] == admin_role_id
    ]
    for user in users_to_create:
        username = user['name']
        if users_dict[username] in users_with_admin_role:
            LOG.info(f'User {username} already has admin role')
            continue
        try:
            keystone.roles.grant(role=admin_role_id,
                                user=users_dict[username],
                                project=project_id)
        except Exception:
            LOG.warning(f"Error granting admin role for user {username}. Retrying...")
            keystone.roles.grant(role=admin_role_id,
                                 user=users_dict[username],
                                 project=project_id)
        LOG.info(f'Granted admin role for user {username}')


@retry(stop_max_attempt_number=3, wait_fixed=1000)
def create_services(keystone, services_to_create):
    if not services_to_create:
        LOG.info('No services to create')
        return
    existing_services = keystone.services.list()
    existing_services_list = [service.name for service in existing_services]

    for service in services_to_create:
        service_name = service['name']
        if service_name in existing_services_list:
            LOG.info(f"Service {service_name} already exist")
            continue
        keystone.services.create(
            name=service_name,
            service_type=service['type'],
            description=service['description']
        )
        LOG.info(f"Service {service_name} successfully created")


@retry(stop_max_attempt_number=3, wait_fixed=1000)
def create_endpoints(keystone, endpoints_to_create):
    if not endpoints_to_create:
        LOG.info('No endpoints to create')
        return

    existing_endpoints = keystone.endpoints.list()
    existing_services = keystone.services.list()
    services_dict = {service.name: service.id for service in existing_services}

    for endpoint in endpoints_to_create:
        service_name = endpoint['service']
        service_id = services_dict[service_name]
        region = endpoint['region']
        for interface, url in endpoint['endpoints'].items():
            existing_endpoint = None
            for e in existing_endpoints:
                if (e.service_id == service_id and
                        e.region == region and
                        e.interface == interface):
                    existing_endpoint = e
                    break
            if existing_endpoint:
                # Endpoint already exist, just update its url if necessary
                if existing_endpoint.url != url:
                    keystone.endpoints.update(existing_endpoint, url=url)
                    LOG.info(f"Endpoint for {service_name=} {interface=} "
                             f"{region=} successfully updated with {url}")
                else:
                    LOG.info(f"Endpoint for {service_name=} {interface=} "
                             f"{region=} already had {url}, so it was not updated")
                continue
            keystone.endpoints.create(
                service=service_id,
                interface=interface,
                url=url,
                region=region
            )
            LOG.info(f"Endpoint for {service_name=} {interface=} "
                     f"{region=} was successfully created with {url}")


@retry(stop_max_attempt_number=3, wait_fixed=1000)
def delete_regionone_endpoints(keystone):
    existing_endpoints = keystone.endpoints.list()
    existing_services = keystone.services.list()
    services_dict = {service.name: service.id for service in existing_services}
    keystone_service_id = services_dict['keystone']
    keystone_endpoints = []

    for endpoint in existing_endpoints:
        if endpoint.region == constants.REGION_ONE_NAME:
            if endpoint.service_id == keystone_service_id:
                # Register keystone endpoints to delete them at the end
                # so previous authentication still works
                keystone_endpoints.append(endpoint)
                continue
            # Deleting non Keystone endpoints
            keystone.endpoints.delete(endpoint)
            LOG.info(f'Deleted endpoint {endpoint}')

    for endpoint in keystone_endpoints:
        # Deleting Keystone endpoints
        keystone.endpoints.delete(endpoint)
        LOG.info(f'Deleted endpoint {endpoint}')


@retry(stop_max_attempt_number=3, wait_fixed=1000)
def update_region_name_on_rc_file(region_name):
    with open(RC_FILE_PATH, 'r') as file:
        lines = file.readlines()
    with open(RC_FILE_PATH, 'w') as file:
        for line in lines:
            if "export OS_REGION_NAME=" in line:
                line = f"export OS_REGION_NAME={region_name}\n"
            file.write(line)
    LOG.info(f"Region name on {RC_FILE_PATH} was successfully updated "
             f"with {region_name}")


def get_service_url(puppet_plugins, service, interface, region_name):
    if (region_name == constants.SYSTEM_CONTROLLER_REGION and
            service in SERVICES_PORTS_PATHS_MAP):
        # Use dcorch puppet object as it contains all necessary ports
        # for the system controller region
        puppet_object = puppet_plugins['dcorch'].obj
        interface_url_functions = {
            'admin': puppet_object.get_proxy_admin_url,
            'internal': puppet_object.get_proxy_internal_url,
            'public': puppet_object.get_proxy_public_url
        }
        mapping = SERVICES_PORTS_PATHS_MAP[service]
        port = getattr(puppet_object, mapping['port'])
        path = getattr(puppet_object, mapping['path'])
        return interface_url_functions[interface](port, path)
    puppet_object = puppet_plugins[service].obj
    interface_url_functions = {
        'admin': puppet_object.get_admin_url,
        'internal': puppet_object.get_internal_url,
        'public': puppet_object.get_public_url
    }
    return interface_url_functions[interface]()


def get_keystone_client(openstack_operator):
    return openstack_operator._get_keystone_client(
        openstack.OPENSTACK_CONFIG
    )


def build_endpoint_list(services, region_name, puppet_plugins):
    endpoints_to_create = []
    for service in services:
        endpoints = {}
        for interface in ENDPOINTS_INTERFACES:
            if service == 'dcdbsync' and interface == 'public':
                # dcdbsync is a private service only used by dcorch,
                # its API is not exposed for public access.
                continue
            endpoints[interface] = \
                get_service_url(puppet_plugins, service, interface, region_name)
        endpoints_to_create.append({
            'service': service,
            'region': region_name,
            'endpoints': endpoints
        })
    return endpoints_to_create


@puppet.puppet_context
def run_endpoint_config(puppet_operator: puppet.PuppetOperator,
                        openstack_operator: openstack.OpenStackOperator):
    puppet_plugins = puppet_operator.puppet_plugins
    puppet_plugins_dict = {plugin.name[4:]: plugin for plugin in puppet_plugins}

    # Rename 'nfv' service to 'vim' to align with service naming convention
    puppet_plugins_dict['vim'] = puppet_plugins_dict.pop('nfv')

    # Use keystone puppet plugin to get base system info
    keystone_plugin = puppet_plugins_dict['keystone'].obj
    dc_role = keystone_plugin._distributed_cloud_role()
    region_name = keystone_plugin._region_name()
    is_systemcontroller = dc_role == \
        constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER
    is_subcloud = dc_role == \
        constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD
    default_service_project_name = keystone_plugin.DEFAULT_SERVICE_PROJECT_NAME

    usernames = copy.deepcopy(BASE_USERS)
    if is_systemcontroller:
        usernames.extend(ADDITIONAL_SYSTEMCONTROLLER_USERS)
    elif is_subcloud:
        usernames.extend(ADDITIONAL_SUBCLOUD_USERS)

    services_to_create = copy.deepcopy(BASE_SERVICES)
    if is_systemcontroller:
        services_to_create.extend(ADDITIONAL_SYSTEMCONTROLLER_SERVICES)
    elif is_subcloud:
        services_to_create.extend(ADDITIONAL_SUBCLOUD_SERVICES)

    services_with_endpoints = copy.deepcopy(SERVICES_WITH_ENDPOINTS)
    if is_systemcontroller or is_subcloud:
        services_with_endpoints.extend(
            SERVICES_WITH_ADITIONAL_DC_ENDPOINTS
        )

    users_to_create = []
    for username in usernames:
        # Generate users_to_create_list with passwords from puppet plugins
        password = puppet_plugins_dict[username].obj\
            ._get_service_password(username)
        email = f'{username}@localhost'
        user = {'name': username, 'password': password, 'email': email}
        users_to_create.append(user)

    endpoints_to_create = build_endpoint_list(services_with_endpoints,
                                              region_name,
                                              puppet_plugins_dict)
    if is_systemcontroller:
        # This endpoints will be created in a different region,
        # so they need to be added to the endpoints list after
        # the RegionOne endpoints list was created
        endpoints_to_create.extend(
            build_endpoint_list(
                SERVICES_WITH_ADITIONAL_SYSTEMCONTROLLER_ENDPOINTS,
                constants.SYSTEM_CONTROLLER_REGION,
                puppet_plugins_dict
            )
        )

    keystone = get_keystone_client(openstack_operator)

    # Delete endpoint reconfiguration flag from previous run if exist
    if os.path.exists(ENDPONTS_RECONFIGURED_FLAG_PATH):
        os.remove(ENDPONTS_RECONFIGURED_FLAG_PATH)

    create_users(keystone, users_to_create)
    grant_admin_role(keystone,
                     users_to_create,
                     default_service_project_name)
    create_services(keystone, services_to_create)
    create_endpoints(keystone, endpoints_to_create)
    if is_subcloud:
        # Update the rc file with the region name before deleting
        # the endpoints so it's still possible to source credentials
        # if the deletion failed after keystone RegionOne endpoints
        # were deleted
        update_region_name_on_rc_file(region_name)
        try:
            delete_regionone_endpoints(keystone)
        except Exception:
            LOG.warning("Endpoint deletion failed. Generating new "
                        "keystone client and trying again")
            # The keystone service/client is cached in the class object,
            # so we create a new instance to get a new client with
            # updated region_name and keystone uri
            # First we need to set the new region_name and auth_uri in cfg
            auth_uri = keystone_plugin.get_identity_uri()
            cfg.CONF.set_override("auth_uri", auth_uri, group=openstack.OPENSTACK_CONFIG)
            cfg.CONF.set_override("region_name", region_name, group=openstack.OPENSTACK_CONFIG)
            db_instance = dbapi.get_instance()
            openstack_operator = openstack.OpenStackOperator(db_instance)
            keystone = get_keystone_client(openstack_operator)
            delete_regionone_endpoints(keystone)

    # Set new endpoint reconfiguration flag
    with open(ENDPONTS_RECONFIGURED_FLAG_PATH, 'a'):
        os.utime(ENDPONTS_RECONFIGURED_FLAG_PATH, None)
    LOG.info('Finished endpoint reconfiguration')
