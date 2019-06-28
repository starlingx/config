#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception

from sysinv.helm import common
from sysinv.helm import openstack


class IronicHelm(openstack.OpenstackBaseHelm):
    """Class to encapsulate helm operations for the ironic chart"""

    CHART = constants.HELM_CHART_IRONIC

    SERVICE_NAME = 'ironic'
    SERVICE_USERS = ['glance']
    AUTH_USERS = ['ironic']

    def execute_manifest_updates(self, operator, app_name=None):
        if (self._num_controllers() >= 2 and
                self._is_labeled(common.LABEL_IRONIC, 'enabled')):
            # If there are fewer than 2 controllers or openstack-ironic
            # label was not set, ironic chart won't be added to
            # openstack-compute-kit chartgroup
            operator.chart_group_chart_insert('openstack-compute-kit',
                                              'openstack-ironic')

    def get_overrides(self, namespace=None):
        overrides = {
            common.HELM_NS_OPENSTACK: {
                'manifests': self._get_ironic_manifests(),
                'pod': {
                    'replicas': {
                        'api': self._num_controllers(),
                        'conductor': self._num_controllers()
                    }
                },
                'network': self._get_network_overrides(),
                'endpoints': self._get_endpoints_overrides()
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides

    def _ironic_manifests(self, is_labeled):
        manifests = {
            'configmap_bin': is_labeled,
            'configmap_etc': is_labeled,
            'deployment_api': is_labeled,
            'ingress_api': is_labeled,
            'job_bootstrap': is_labeled,
            'job_db_init': is_labeled,
            'job_db_sync': is_labeled,
            'job_image_repo_sync': is_labeled,
            'job_ks_endpoints': is_labeled,
            'job_ks_service': is_labeled,
            'job_ks_user': is_labeled,
            'job_manage_cleaning_network': is_labeled,
            'job_rabbit_init': is_labeled,
            'pdb_api': is_labeled,
            'secret_db': is_labeled,
            'secret_keystone': is_labeled,
            'secret_rabbitmq': is_labeled,
            'service_api': is_labeled,
            'service_ingress_api': is_labeled,
            'statefulset_conductor': is_labeled
        }
        return manifests

    def _get_ironic_manifests(self):
        ironic_label = self._is_labeled(common.LABEL_IRONIC, 'enabled')
        return self._ironic_manifests(ironic_label)

    def _get_endpoints_overrides(self):
        overrides = {
            'identity': {
                'auth': self._get_endpoints_identity_overrides(
                    self.SERVICE_NAME, self.AUTH_USERS),
            },
            'oslo_cache': {
                'auth': {
                    'memcache_secret_key':
                        self._get_common_password('auth_memcache_key')
                }
            },
            'oslo_db': {
                'auth': self._get_endpoints_oslo_db_overrides(
                    self.SERVICE_NAME, self.AUTH_USERS)
            },
            'oslo_messaging': {
                'auth': self._get_endpoints_oslo_messaging_overrides(
                    self.SERVICE_NAME, self.AUTH_USERS)
            },
        }

        # Service user passwords already exist in other chart overrides
        for user in self.SERVICE_USERS:
            overrides['identity']['auth'].update({
                user: {
                    'region_name': self._region_name(),
                    'password': self._get_or_generate_password(
                        user, common.HELM_NS_OPENSTACK, user)
                }
            })

        return overrides

    def _get_interface_port_name(self, iface):
        """
        Determine the port name of the underlying device.
        """
        assert iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET
        port = self.dbapi.port_get_by_interface(iface.id)
        if port:
            return port[0]['name']

    def _get_ironic_port(self):
        ironic_port = ''
        if self.dbapi is None:
            return ironic_port
        # find the first interface with ironic network type
        networks = self.dbapi.networks_get_by_type(
                constants.NETWORK_TYPE_IRONIC)
        for network in networks:
            interface = self.dbapi.iinterface_get_by_network(network.name)
            if interface:
                # get first interface as ironic port
                ironic_port = self._get_interface_port_name(interface[0])
                if ironic_port:
                    break
        return ironic_port

    def _get_ironic_addrpool(self):
        ironic_addrpool = {}
        if self.dbapi is None:
            return ironic_addrpool
        networks = self.dbapi.networks_get_by_type(
                constants.NETWORK_TYPE_IRONIC)
        for network in networks:
            addrpool = self.dbapi.address_pool_get(network.pool_uuid)
            if addrpool:
                ironic_addrpool['cidr'] = str(addrpool.network) + \
                        '/' + str(addrpool.prefix)
                ironic_addrpool['gateway'] = str(addrpool.gateway_address)
                ironic_addrpool['start'] = str(addrpool.ranges[0][0])
                ironic_addrpool['end'] = str(addrpool.ranges[0][1])
                break
        return ironic_addrpool

    # retrieve ironic network settings from address pools,
    # ironic ethernet port name from interfaces,
    # and ironic provider network from data networks.
    #
    # NOTE: Different ethernet port name for ironic conductor not supported.
    # Currently the name of ironic port should be the same on each
    # controllers to support HA, otherwise the initialization
    # of ironic-conductor-pxe would be failed. It's a limitation
    # from openstack-helm/ironic that ironic conductors use same
    # configuration file for init.
    def _get_network_overrides(self):
        ironic_addrpool = self._get_ironic_addrpool()
        gateway = ironic_addrpool.get('gateway', '')
        cidr = ironic_addrpool.get('cidr', '')
        start = ironic_addrpool.get('start', '')
        end = ironic_addrpool.get('end', '')

        overrides = {
            'pxe': {
                'device': str(self._get_ironic_port()),
                # User can define it's own tenant network name by
                # 'system helm-override-update' to update this value
                'neutron_provider_network': 'ironic',
                'neutron_subnet_gateway': str(gateway),
                'neutron_subnet_cidr': str(cidr),
                'neutron_subnet_alloc_start': str(start),
                'neutron_subnet_alloc_end': str(end)
            },
        }

        return overrides
