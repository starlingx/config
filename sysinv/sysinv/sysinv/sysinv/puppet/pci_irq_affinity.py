#
# Copyright (c) 2017-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import utils
from sysinv.helm import helm
from sysinv.puppet import openstack


class PciIrqAffinityPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for PciIrqAffinity configuration"""
    PLATFORM_KEYRING_SERVICE = 'CGCS'
    OPENSTACK_VERSION_WITH_CONTAINER_SUPPORT = 125

    # This function will be removed when the service is completely removed from the platform
    def should_enable_agent_service(self):
        """
        Checks whether the OpenStack application version
        includes the pci irq affinity agent container
        """
        try:
            openstack_app_version = utils.find_openstack_app(self.dbapi).app_version
            # stx-openstack app version string format: x.y-wz-release-info
            openstack_app_version = int(openstack_app_version.split('-', 2)[1])
        except Exception:
            return False

        if openstack_app_version < self.OPENSTACK_VERSION_WITH_CONTAINER_SUPPORT:
            return True
        return False

    def get_secure_static_config(self):
        return {}

    def get_system_config(self):
        config = {}

        if utils.is_openstack_applied(self.dbapi):
            helm_data = helm.HelmOperatorData(self.dbapi)

            # if openstack includes the agent container then agent
            # service on platform must be disabled
            enable_agent_service = self.should_enable_agent_service()

            # The openstack services are authenticated with pod based
            # keystone.
            keystone_auth_data = helm_data.get_keystone_auth_data()
            openstack_auth_config = {
                'platform::pciirqaffinity::params::openstack_enabled':
                    enable_agent_service,
                'platform::pciirqaffinity::params::openstack_username':
                    keystone_auth_data['admin_user_name'],
                'platform::pciirqaffinity::params::openstack_tenant':
                    keystone_auth_data['admin_project_name'],
                'platform::pciirqaffinity::params::openstack_auth_host':
                    keystone_auth_data['auth_host'],
                'platform::pciirqaffinity::params::openstack_user_domain':
                    keystone_auth_data['admin_user_domain'],
                'platform::pciirqaffinity::params::openstack_project_domain':
                    keystone_auth_data['admin_project_domain'],
                'platform::pciirqaffinity::params::openstack_keyring_service':
                    self.PLATFORM_KEYRING_SERVICE,
            }
            config.update(openstack_auth_config)

            # The openstack rabbitmq is running in a pod
            nova_oslo_messaging_data = \
                helm_data.get_nova_oslo_messaging_data()
            rabbit_config = {
                'platform::pciirqaffinity::params::rabbit_host':
                    nova_oslo_messaging_data['host'],
                'platform::pciirqaffinity::params::rabbit_port':
                    nova_oslo_messaging_data['port'],
                'platform::pciirqaffinity::params::rabbit_virtual_host':
                    nova_oslo_messaging_data['virt_host'],
                'platform::pciirqaffinity::params::rabbit_userid':
                    nova_oslo_messaging_data['username'],
                'platform::pciirqaffinity::params::rabbit_password':
                    nova_oslo_messaging_data['password'],
            }
            config.update(rabbit_config)
        else:
            configs = {
                'platform::pciirqaffinity::params::openstack_enabled':
                    False,
                'platform::pciirqaffinity::params::openstack_username':
                    'undef',
                'platform::pciirqaffinity::params::openstack_tenant':
                    'undef',
                'platform::pciirqaffinity::params::openstack_auth_host':
                    'undef',
                'platform::pciirqaffinity::params::openstack_user_domain':
                    'undef',
                'platform::pciirqaffinity::params::openstack_project_domain':
                    'undef',
                'platform::pciirqaffinity::params::openstack_keyring_service':
                    'undef',
                'platform::pciirqaffinity::params::rabbit_host':
                    'undef',
                'platform::pciirqaffinity::params::rabbit_port':
                    'undef',
                'platform::pciirqaffinity::params::rabbit_virtual_host':
                    'undef',
                'platform::pciirqaffinity::params::rabbit_userid':
                    'undef',
                'platform::pciirqaffinity::params::rabbit_password':
                    'undef',
            }
            config.update(configs)

        return config

    def get_host_config(self, host):
        return {}

    def get_public_url(self):
        # not an openstack service
        raise NotImplementedError()

    def get_internal_url(self):
        # not an openstack service
        raise NotImplementedError()

    def get_admin_url(self):
        # not an openstack service
        raise NotImplementedError()
