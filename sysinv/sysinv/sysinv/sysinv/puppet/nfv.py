#
# Copyright (c) 2017-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import utils
from sysinv.helm import helm

from . import openstack


class NfvPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for vim configuration"""

    SERVICE_NAME = 'vim'
    SERVICE_PORT = 4545
    PLATFORM_KEYRING_SERVICE = 'CGCS'

    def get_secure_static_config(self):
        kspass = self._get_service_password(self.SERVICE_NAME)

        return {
            'nfv::keystone::auth::password': kspass,
        }

    def get_system_config(self):
        system = self._get_system()

        if system.system_mode == constants.SYSTEM_MODE_SIMPLEX:
            single_hypervisor = True
            single_controller = True
        else:
            single_hypervisor = False
            single_controller = False

        config = {
            'nfv::keystone::auth::public_url': self.get_public_url(),
            'nfv::keystone::auth::internal_url': self.get_internal_url(),
            'nfv::keystone::auth::admin_url': self.get_admin_url(),
            'nfv::keystone::auth::auth_name':
                self._get_service_user_name(self.SERVICE_NAME),
            'nfv::keystone::auth::region':
                self._get_service_region_name(self.SERVICE_NAME),
            'nfv::keystone::auth::tenant': self._get_service_tenant_name(),

            'nfv::nfvi::host_listener_host':
                self._get_management_address(),

            'nfv::nfvi::platform_username':
                self._operator.keystone.get_admin_user_name(),
            'nfv::nfvi::platform_tenant':
                self._operator.keystone.get_admin_project_name(),
            'nfv::nfvi::platform_auth_host':
                self._keystone_auth_address(),
            'nfv::nfvi::platform_user_domain':
                self._operator.keystone.get_admin_user_domain(),
            'nfv::nfvi::platform_project_domain':
                self._operator.keystone.get_admin_project_domain(),
            'nfv::nfvi::platform_keyring_service':
                self.PLATFORM_KEYRING_SERVICE,

            'nfv::nfvi::keystone_region_name': self._keystone_region_name(),
            'nfv::nfvi::keystone_service_name':
                self._operator.keystone.get_service_name(),
            'nfv::nfvi::keystone_service_type':
                self._operator.keystone.get_service_type(),

            'nfv::nfvi::sysinv_region_name':
                self._operator.sysinv.get_region_name(),
            'nfv::nfvi::patching_region_name':
                self._operator.patching.get_region_name(),
            'nfv::nfvi::fm_region_name':
                self._operator.fm.get_region_name(),

            'nfv::vim::vim_api_ip': self._get_management_address(),
            'nfv::vim::vim_webserver_ip': self._get_oam_address(),
            'nfv::vim::instance_single_hypervisor': single_hypervisor,
            'nfv::vim::sw_mgmt_single_controller': single_controller,

            'platform::nfv::params::service_create':
                self._to_create_services(),
        }

        if self._kubernetes_enabled():
            if utils.is_openstack_installed(self.dbapi):
                helm_data = helm.HelmOperatorData(self.dbapi)

                # The openstack services are authenticated with pod based
                # keystone.
                keystone_auth_data = helm_data.get_keystone_auth_data()
                openstack_auth_config = {
                    'nfv::nfvi::openstack_username':
                        keystone_auth_data['admin_user_name'],
                    'nfv::nfvi::openstack_tenant':
                        keystone_auth_data['admin_project_name'],
                    'nfv::nfvi::openstack_auth_host':
                        keystone_auth_data['auth_host'],
                    'nfv::nfvi::openstack_user_domain':
                        keystone_auth_data['admin_user_domain'],
                    'nfv::nfvi::openstack_project_domain':
                        keystone_auth_data['admin_project_domain'],
                    'nfv::nfvi::openstack_keyring_service':
                        self.PLATFORM_KEYRING_SERVICE,
                }
                config.update(openstack_auth_config)

                # Nova is running in a pod
                nova_endpoint_data = helm_data.get_nova_endpoint_data()
                nova_config = {
                    'nfv::nfvi::nova_endpoint_override':
                        nova_endpoint_data['endpoint_override'],
                    'nfv::nfvi::nova_region_name':
                        nova_endpoint_data['region_name'],
                }
                config.update(nova_config)

                # Cinder is running in a pod
                cinder_endpoint_data = helm_data.get_cinder_endpoint_data()
                cinder_config = {
                    'nfv::nfvi::cinder_region_name':
                        cinder_endpoint_data['region_name'],
                    'nfv::nfvi::cinder_service_name':
                        cinder_endpoint_data['service_name'],
                    'nfv::nfvi::cinder_service_type':
                        cinder_endpoint_data['service_type'],
                }
                config.update(cinder_config)

                # Glance is running in a pod
                glance_endpoint_data = helm_data.get_glance_endpoint_data()
                glance_config = {
                    'nfv::nfvi::glance_region_name':
                        glance_endpoint_data['region_name'],
                    'nfv::nfvi::glance_service_name':
                        glance_endpoint_data['service_name'],
                    'nfv::nfvi::glance_service_type':
                        glance_endpoint_data['service_type'],
                }
                config.update(glance_config)

                # Neutron is running in a pod
                neutron_endpoint_data = helm_data.get_neutron_endpoint_data()
                neutron_config = {
                    'nfv::nfvi::neutron_region_name':
                        neutron_endpoint_data['region_name'],
                }
                config.update(neutron_config)

                # Heat is running in a pod
                heat_endpoint_data = helm_data.get_heat_endpoint_data()
                heat_config = {
                    'nfv::nfvi::heat_region_name':
                        heat_endpoint_data['region_name'],
                }
                config.update(heat_config)

                # Ceilometer is running in a pod
                ceilometer_endpoint_data = \
                    helm_data.get_ceilometer_endpoint_data()
                ceilometer_config = {
                    'nfv::nfvi::ceilometer_region_name':
                        ceilometer_endpoint_data['region_name'],
                }
                config.update(ceilometer_config)

                # The openstack rabbitmq is running in a pod
                nova_oslo_messaging_data = \
                    helm_data.get_nova_oslo_messaging_data()
                rabbit_config = {
                    'nfv::nfvi::rabbit_host':
                        nova_oslo_messaging_data['host'],
                    'nfv::nfvi::rabbit_port':
                        nova_oslo_messaging_data['port'],
                    'nfv::nfvi::rabbit_virtual_host':
                        nova_oslo_messaging_data['virt_host'],
                    'nfv::nfvi::rabbit_userid':
                        nova_oslo_messaging_data['username'],
                    'nfv::nfvi::rabbit_password':
                        nova_oslo_messaging_data['password'],
                }
                config.update(rabbit_config)

                # Listen to nova api proxy on management address
                nova_api_proxy_config = {
                    'nfv::nfvi::compute_rest_api_host':
                        self._get_management_address(),
                }
                config.update(nova_api_proxy_config)
            else:
                # The openstack auth info is still required as the VIM will
                # audit some keystone entities (e.g. tenants). Point it to
                # the platform keystone.
                openstack_auth_config = {
                    'nfv::nfvi::openstack_username':
                        self._operator.keystone.get_admin_user_name(),
                    'nfv::nfvi::openstack_tenant':
                        self._operator.keystone.get_admin_project_name(),
                    'nfv::nfvi::openstack_auth_host':
                        self._keystone_auth_address(),
                    'nfv::nfvi::openstack_user_domain':
                        self._operator.keystone.get_admin_user_domain(),
                    'nfv::nfvi::openstack_project_domain':
                        self._operator.keystone.get_admin_project_domain(),
                    'nfv::nfvi::openstack_keyring_service':
                        self.PLATFORM_KEYRING_SERVICE,
                }
                config.update(openstack_auth_config)

                vim_disabled = {
                    # Disable VIM plugins for resources not yet active.
                    'nfv::vim::block_storage_plugin_disabled': True,
                    'nfv::vim::compute_plugin_disabled': True,
                    'nfv::vim::network_plugin_disabled': True,
                    'nfv::vim::image_plugin_disabled': True,
                    'nfv::vim::guest_plugin_disabled': True,
                    'nfv::nfvi::nova_endpoint_disabled': True,
                    'nfv::nfvi::neutron_endpoint_disabled': True,
                    'nfv::nfvi::cinder_endpoint_disabled': True,
                }
                config.update(vim_disabled)
        else:
            # The openstack services are authenticated with platform keystone.
            openstack_auth_config = {
                'nfv::nfvi::openstack_username':
                    self._operator.keystone.get_admin_user_name(),
                'nfv::nfvi::openstack_tenant':
                    self._operator.keystone.get_admin_project_name(),
                'nfv::nfvi::openstack_auth_host':
                    self._keystone_auth_address(),
                'nfv::nfvi::openstack_user_domain':
                    self._operator.keystone.get_admin_user_domain(),
                'nfv::nfvi::openstack_project_domain':
                    self._operator.keystone.get_admin_project_domain(),
                'nfv::nfvi::openstack_keyring_service':
                    self.PLATFORM_KEYRING_SERVICE,
            }
            config.update(openstack_auth_config)

            openstack_config = {
                'nfv::nfvi::nova_endpoint_override':
                    self._get_nova_endpoint_url(),
                'nfv::nfvi::nova_region_name':
                    self._operator.nova.get_region_name(),
                'nfv::nfvi::cinder_region_name':
                    self._operator.cinder.get_region_name(),
                'nfv::nfvi::cinder_service_name':
                    self._operator.cinder.get_service_name_v2(),
                'nfv::nfvi::cinder_service_type':
                    self._operator.cinder.get_service_type_v2(),
                'nfv::nfvi::cinder_endpoint_disabled':
                    not self._operator.cinder.is_service_enabled(),
                'nfv::nfvi::glance_region_name':
                    self._operator.glance.get_region_name(),
                'nfv::nfvi::glance_service_name':
                    self._operator.glance.get_service_name(),
                'nfv::nfvi::glance_service_type':
                    self._operator.glance.get_service_type(),
                'nfv::nfvi::neutron_region_name':
                    self._operator.neutron.get_region_name(),
                'nfv::nfvi::heat_region_name':
                    self._operator.heat.get_region_name(),
                'nfv::nfvi::ceilometer_region_name':
                    self._operator.ceilometer.get_region_name(),
            }
            config.update(openstack_config)

        return config

    def get_host_config(self, host):
        if (constants.CONTROLLER not in utils.get_personalities(host)):
            return {}
        database_dir = "/opt/platform/nfv/vim/%s" % host.software_load
        return {
            'nfv::vim::database_dir': database_dir,
        }

    def get_public_url(self):
        return self._format_public_endpoint(self.SERVICE_PORT)

    def get_internal_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT)

    def get_admin_url(self):
        return self._format_private_endpoint(self.SERVICE_PORT)

    def _get_nova_endpoint_url(self):
        return self._format_private_endpoint(
            self._operator.nova.SERVICE_API_PORT)
