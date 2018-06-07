#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import six

from sysinv.common import constants
from sysinv.common import utils

from . import interface
from . import openstack


class NeutronPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for neutron configuration"""

    SERVICE_NAME = 'neutron'
    SERVICE_PORT = 9696

    def get_static_config(self):
        dbuser = self._get_database_username(self.SERVICE_NAME)

        return {
            'neutron::keystone::authtoken::user_domain_name':
                self._get_service_user_domain_name(),
            'neutron::keystone::authtoken::project_domain_name':
                self._get_service_project_domain_name(),
            'neutron::keystone::authtoken::project_name':
                self._get_service_tenant_name(),

            'neutron::server::notifications::user_domain_name':
                self._get_service_user_domain_name(),
            'neutron::server::notifications::project_domain_name':
                self._get_service_project_domain_name(),
            'neutron::server::notifications::project_name':
                self._get_service_tenant_name(),

            'neutron::db::postgresql::user': dbuser,
        }

    def get_secure_static_config(self):
        dbpass = self._get_database_password(self.SERVICE_NAME)
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            'neutron::keystone::auth::password': kspass,

            'neutron::keystone::authtoken::password': kspass,

            'neutron::db::postgresql::password': dbpass,

            'neutron::server::notifications::password':
                self._get_service_password(
                    self._operator.nova.SERVICE_NAME),
            'neutron::agents::metadata::shared_secret':
                self._get_service_password(
                    self._operator.nova.SERVICE_METADATA),
        }

    def get_system_config(self):
        neutron_nova_region_name = \
            self._get_service_region_name(self._operator.nova.SERVICE_NAME)

        ksuser = self._get_service_user_name(self.SERVICE_NAME)

        config = {
            'neutron::server::notifications::auth_url':
                self._keystone_identity_uri(),
            'neutron::server::notifications::tenant_name':
                self._get_service_tenant_name(),
            'neutron::server::notifications::project_name':
                self._get_service_tenant_name(),
            'neutron::server::notifications::region_name':
                neutron_nova_region_name,
            'neutron::server::notifications::username':
                self._get_service_user_name(self._operator.nova.SERVICE_NAME),
            'neutron::server::notifications::project_domain_name':
                self._get_service_project_domain_name(),
            'neutron::server::notifications::user_domain_name':
                self._get_service_user_domain_name(),

            'neutron::agents::metadata::metadata_ip':
                self._get_management_address(),

            'neutron::keystone::authtoken::auth_url':
                self._keystone_identity_uri(),
            'neutron::keystone::authtoken::auth_uri':
                self._keystone_auth_uri(),
            'neutron::keystone::authtoken::username': ksuser,
            'neutron::keystone::authtoken::project_name':
                self._get_service_tenant_name(),
            'neutron::keystone::authtoken::user_domain_name':
                self._get_service_user_domain_name(),
            'neutron::keystone::authtoken::project_domain_name':
                self._get_service_project_domain_name(),
            'neutron::keystone::authtoken::region_name':
                self._keystone_region_name(),

            'neutron::keystone::auth::public_url': self.get_public_url(),
            'neutron::keystone::auth::internal_url': self.get_internal_url(),
            'neutron::keystone::auth::admin_url': self.get_admin_url(),
            'neutron::keystone::auth::region': self._region_name(),
            'neutron::keystone::auth::auth_name': ksuser,
            'neutron::keystone::auth::tenant': self._get_service_tenant_name(),

            'neutron::bind_host': self._get_management_address(),

            'openstack::neutron::params::region_name':
                self.get_region_name(),
            'openstack::neutron::params::service_create':
                self._to_create_services(),
        }

        # no need to configure neutron endpoint as the proxy provides
        # the endpoints in SystemController
        if (self._distributed_cloud_role() ==
                constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER):
            config.update({
                'neutron::keystone::auth::configure_endpoint': False,
                'openstack::neutron::params::configure_endpoint': False,
            })

        config.update(self._get_sdn_controller_config())
        return config

    def get_secure_system_config(self):
        config = {
            'neutron::server::database_connection':
                self._format_database_connection(self.SERVICE_NAME),
        }

        return config

    def _get_sdn_controller_config(self):
        if not self._sdn_enabled():
            return {}

        controller_config = {}
        for controller in self.dbapi.sdn_controller_get_list():
            # skip SDN controllers that are in disabled state
            if controller.state != constants.SDN_CONTROLLER_STATE_ENABLED:
                continue

            # openstack::neutron::sdn::controller puppet resource parameters
            name = 'sdn_controller_%d' % controller.id
            config = {
                'transport': controller.transport.lower(),
                'ip_address': str(controller.ip_address),
                'port': controller.port,
            }
            controller_config.update({name: config})

        return {
            'openstack::neutron::odl::params::controller_config':
                controller_config
        }

    def get_host_config(self, host):
        device_mappings = []
        for iface in self.context['interfaces'].values():
            if (utils.get_primary_network_type(iface) ==
                    constants.NETWORK_TYPE_PCI_SRIOV):
                port = interface.get_interface_port(self.context, iface)
                providernets = interface.get_interface_providernets(iface)
                for net in providernets:
                    device_mappings.append("%s:%s" % (net, port['name']))

        config = {
            'neutron::agents::ml2::sriov::physical_device_mappings':
                device_mappings,
        }

        if host.personality == constants.CONTROLLER:
            service_parameters = self._get_service_parameter_configs(
                constants.SERVICE_TYPE_NETWORK)

            if service_parameters is None:
                return config

            # check if neutron bgp speaker is configured
            if host.hostname == constants.CONTROLLER_0_HOSTNAME:
                bgp_router_id = self._service_parameter_lookup_one(
                    service_parameters,
                    constants.SERVICE_PARAM_SECTION_NETWORK_BGP,
                    constants.SERVICE_PARAM_NAME_BGP_ROUTER_ID_C0,
                    None)
            else:
                bgp_router_id = self._service_parameter_lookup_one(
                    service_parameters,
                    constants.SERVICE_PARAM_SECTION_NETWORK_BGP,
                    constants.SERVICE_PARAM_NAME_BGP_ROUTER_ID_C1,
                    None)

            if bgp_router_id is not None:
                config.update({
                    'openstack::neutron::params::bgp_router_id':
                    bgp_router_id})

        return config

    def get_public_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT)

    def get_internal_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT)

    def get_admin_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT)

    def get_region_name(self):
        return self._get_service_region_name(self.SERVICE_NAME)
