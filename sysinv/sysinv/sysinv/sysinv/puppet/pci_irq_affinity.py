#
# Copyright (c) 2017-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import exception
from sysinv.common import utils
from sysinv.helm import common
from sysinv.helm import helm
from sysinv.puppet import openstack


class PciIrqAffinityPuppet(openstack.OpenstackBasePuppet):
    """Class to encapsulate puppet operations for PciIrqAffinity configuration"""
    PLATFORM_KEYRING_SERVICE = 'CGCS'
    HELM_CHART_PCI_IRQ_AFFINITY_AGENT = 'pci-irq-affinity-agent'

    # This function will be removed when the service is completely removed from the platform
    def should_enable_agent_service(self):
        """
        Checks whether the OpenStack application version
        includes the pci irq affinity agent container
        """
        try:
            openstack_app = utils.find_openstack_app(self.dbapi)
        except exception.KubeAppNotFound:
            return False
        # Service should only be enabled if the containerized version of the service is not
        # present
        return not utils.is_chart_enabled(
            self.dbapi,
            openstack_app.name,
            self.HELM_CHART_PCI_IRQ_AFFINITY_AGENT,
            common.HELM_NS_OPENSTACK
        )

    def get_secure_static_config(self):
        return {}

    def get_system_config(self):
        config = {}

        if utils.is_openstack_applied(self.dbapi):
            helm_data = helm.HelmOperatorData(self.dbapi)

            # The openstack services are authenticated with pod based
            # keystone.
            keystone_auth_data = helm_data.get_keystone_auth_data()
            openstack_auth_config = {
                'platform::pciirqaffinity::params::openstack_enabled':
                    True,
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
        host_labels = self.dbapi.label_get_by_host(host.id)
        return {
            'platform::pciirqaffinity::params::openstack_enabled':
                utils.is_openstack_applied(self.dbapi) and
                utils.has_openstack_compute(host_labels) and
                self.should_enable_agent_service(),
        }

    def get_public_url(self):
        # not an openstack service
        raise NotImplementedError()

    def get_internal_url(self):
        # not an openstack service
        raise NotImplementedError()

    def get_admin_url(self):
        # not an openstack service
        raise NotImplementedError()
