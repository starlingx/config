#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import netaddr

from sysinv.common import constants
from sysinv.common import exception

from sysinv.puppet import base
from sysinv.puppet import interface


class NetworkingPuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for networking configuration"""

    def get_system_config(self):
        config = {}
        config.update(self._get_pxeboot_network_config())
        config.update(self._get_mgmt_network_config())
        config.update(self._get_oam_network_config())
        config.update(self._get_cluster_network_config())
        config.update(self._get_ironic_network_config())
        return config

    def get_host_config(self, host):
        config = {}
        config.update(self._get_pxeboot_interface_config())
        config.update(self._get_mgmt_interface_config())
        config.update(self._get_cluster_interface_config())
        config.update(self._get_ironic_interface_config())
        config.update(self._get_ptp_interface_config())
        if host.personality == constants.CONTROLLER:
            config.update(self._get_oam_interface_config())
        return config

    def _get_pxeboot_network_config(self):
        return self._get_network_config(constants.NETWORK_TYPE_PXEBOOT)

    def _get_mgmt_network_config(self):
        networktype = constants.NETWORK_TYPE_MGMT

        config = self._get_network_config(networktype)

        platform_nfs_address = self._get_address_by_name(
            constants.CONTROLLER_PLATFORM_NFS, networktype).address

        try:
            gateway_address = self._get_address_by_name(
                constants.CONTROLLER_GATEWAY, networktype).address
        except exception.AddressNotFoundByName:
            gateway_address = None

        config.update({
            'platform::network::%s::params::gateway_address' % networktype:
                gateway_address,
            'platform::network::%s::params::platform_nfs_address' % networktype:
                platform_nfs_address,
        })

        return config

    def _get_cluster_network_config(self):
        networktype = constants.NETWORK_TYPE_CLUSTER_HOST
        config = self._get_network_config(networktype)
        return config

    def _get_oam_network_config(self):
        networktype = constants.NETWORK_TYPE_OAM

        config = self._get_network_config(networktype)

        try:
            gateway_address = self._get_address_by_name(
                constants.CONTROLLER_GATEWAY, networktype).address
        except exception.AddressNotFoundByName:
            gateway_address = None

        config.update({
            'platform::network::%s::params::gateway_address' % networktype:
                gateway_address,
        })

        return config

    def _get_ironic_network_config(self):
        networktype = constants.NETWORK_TYPE_IRONIC
        config = self._get_network_config(networktype)
        return config

    def _get_network_config(self, networktype):
        try:
            network = self.dbapi.network_get_by_type(networktype)
        except exception.NetworkTypeNotFound:
            # network not configured
            return {}

        address_pool = self.dbapi.address_pool_get(network.pool_uuid)

        subnet = netaddr.IPNetwork(
            str(address_pool.network) + '/' + str(address_pool.prefix))

        subnet_version = address_pool.family
        subnet_network = str(subnet.network)
        subnet_netmask = str(subnet.netmask)
        subnet_prefixlen = subnet.prefixlen

        subnet_start = str(address_pool.ranges[0][0])
        subnet_end = str(address_pool.ranges[0][-1])

        try:
            controller_address = self._get_address_by_name(
                constants.CONTROLLER_HOSTNAME, networktype).address
        except exception.AddressNotFoundByName:
            controller_address = None

        try:
            controller0_address = self._get_address_by_name(
                constants.CONTROLLER_0_HOSTNAME, networktype).address
        except exception.AddressNotFoundByName:
            controller0_address = None

        try:
            controller1_address = self._get_address_by_name(
                constants.CONTROLLER_1_HOSTNAME, networktype).address
        except exception.AddressNotFoundByName:
            controller1_address = None

        controller_address_url = self._format_url_address(controller_address)
        subnet_network_url = self._format_url_address(subnet_network)

        # Convert the dash to underscore because puppet parameters cannot have
        # dashes
        networktype = networktype.replace('-', '_')

        return {
            'platform::network::%s::params::subnet_version' % networktype:
                subnet_version,
            'platform::network::%s::params::subnet_network' % networktype:
                subnet_network,
            'platform::network::%s::params::subnet_network_url' % networktype:
                subnet_network_url,
            'platform::network::%s::params::subnet_prefixlen' % networktype:
                subnet_prefixlen,
            'platform::network::%s::params::subnet_netmask' % networktype:
                subnet_netmask,
            'platform::network::%s::params::subnet_start' % networktype:
                subnet_start,
            'platform::network::%s::params::subnet_end' % networktype:
                subnet_end,
            'platform::network::%s::params::controller_address' % networktype:
                controller_address,
            'platform::network::%s::params::controller_address_url' % networktype:
                controller_address_url,
            'platform::network::%s::params::controller0_address' % networktype:
                controller0_address,
            'platform::network::%s::params::controller1_address' % networktype:
                controller1_address,
        }

    def _get_pxeboot_interface_config(self):
        return self._get_interface_config(constants.NETWORK_TYPE_PXEBOOT)

    def _get_mgmt_interface_config(self):
        return self._get_interface_config(constants.NETWORK_TYPE_MGMT)

    def _get_oam_interface_config(self):
        return self._get_interface_config(constants.NETWORK_TYPE_OAM)

    def _get_cluster_interface_config(self):
        return self._get_interface_config(constants.NETWORK_TYPE_CLUSTER_HOST)

    def _get_ironic_interface_config(self):
        return self._get_interface_config(constants.NETWORK_TYPE_IRONIC)

    def _get_ptp_interface_config(self):
        config = {}
        ptp_devices = {
            constants.INTERFACE_PTP_ROLE_MASTER: [],
            constants.INTERFACE_PTP_ROLE_SLAVE: []
        }
        ptp_interfaces = interface.get_ptp_interfaces(self.context)
        ptp = self.dbapi.ptp_get_one()
        is_udp = (ptp.transport == constants.PTP_TRANSPORT_UDP)
        for network_interface in ptp_interfaces:
            interface_devices = interface.get_interface_devices(self.context, network_interface)

            address_family = None
            if is_udp:
                address = interface.get_interface_primary_address(self.context, network_interface)
                if address:
                    address_family = netaddr.IPAddress(address['address']).version

            for device in interface_devices:
                ptp_devices[network_interface['ptp_role']].append({'device': device, 'family': address_family})

        config.update({
            'platform::ptp::master_devices': ptp_devices[constants.INTERFACE_PTP_ROLE_MASTER],
            'platform::ptp::slave_devices': ptp_devices[constants.INTERFACE_PTP_ROLE_SLAVE]
        })

        return config

    def _get_interface_config(self, networktype):
        config = {}

        network_interface = interface.find_interface_by_type(
            self.context, networktype)

        if network_interface:
            interface_name = interface.get_interface_os_ifname(
                self.context, network_interface)
            interface_devices = interface.get_interface_devices(
                self.context, network_interface)
            network_id = interface.find_network_id_by_networktype(
                self.context, networktype)
            # Convert the dash to underscore because puppet parameters cannot
            # have dashes
            networktype = networktype.replace('-', '_')
            config.update({
                'platform::network::%s::params::interface_name' % networktype:
                    interface_name,
                'platform::network::%s::params::interface_devices' % networktype:
                    interface_devices,
                'platform::network::%s::params::mtu' % networktype:
                    network_interface.imtu
            })

            interface_address = interface.get_interface_primary_address(
                self.context, network_interface, network_id)
            if interface_address:
                config.update({
                    'platform::network::%s::params::interface_address' %
                    networktype:
                        interface_address['address']
                })

        return config
