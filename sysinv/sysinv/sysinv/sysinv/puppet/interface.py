#
# Copyright (c) 2017-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import collections
import copy
import os
import six

from netaddr import IPAddress
from netaddr import IPNetwork

from oslo_log import log
from sysinv._i18n import _
from sysinv.common import constants
from sysinv.common import device as dconstants
from sysinv.common import exception
from sysinv.common import interface
from sysinv.common import utils
from sysinv.conductor import openstack
from sysinv.puppet import base
from sysinv.puppet import quoted_str


LOG = log.getLogger(__name__)

PLATFORM_NETWORK_TYPES = [constants.NETWORK_TYPE_PXEBOOT,
                          constants.NETWORK_TYPE_MGMT,
                          constants.NETWORK_TYPE_CLUSTER_HOST,
                          constants.NETWORK_TYPE_OAM,
                          constants.NETWORK_TYPE_IRONIC,
                          constants.NETWORK_TYPE_STORAGE]

DATA_NETWORK_TYPES = [constants.NETWORK_TYPE_DATA]

DATA_INTERFACE_CLASSES = [constants.INTERFACE_CLASS_DATA]

PCI_NETWORK_TYPES = [constants.NETWORK_TYPE_PCI_SRIOV,
                     constants.NETWORK_TYPE_PCI_PASSTHROUGH]

PCI_INTERFACE_CLASSES = [constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                         constants.INTERFACE_CLASS_PCI_SRIOV]

ACTIVE_STANDBY_AE_MODES = ['active_backup', 'active-backup', 'active_standby']
BALANCED_AE_MODES = ['balanced', 'balanced-xor']
LACP_AE_MODES = ['802.3ad']

LOOPBACK_IFNAME = 'lo'
LOOPBACK_METHOD = 'loopback'
STATIC_METHOD = 'static'
MANUAL_METHOD = 'manual'
DHCP_METHOD = 'dhcp'

NETWORK_CONFIG_RESOURCE = 'platform::network::interfaces::network_config'
SRIOV_CONFIG_RESOURCE = 'platform::network::interfaces::sriov::sriov_config'
FPGA_CONFIG_RESOURCE = 'platform::network::interfaces::fpga::fpga_config'
ADDRESS_CONFIG_RESOURCE = 'platform::network::addresses::address_config'
ROUTE_CONFIG_RESOURCE = 'platform::network::routes::route_config'

DATA_IFACE_LIST_RESOURCE = 'platform::lmon::params::data_iface_devices'

IFACE_UP_OP = 1
IFACE_PRE_UP_OP = 2
IFACE_POST_UP_OP = 3
IFACE_DOWN_OP = 4
IFACE_PRE_DOWN_OP = 5
IFACE_POST_DOWN_OP = 6


class InterfacePuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for interface configuration"""

    def __init__(self, *args, **kwargs):
        super(InterfacePuppet, self).__init__(*args, **kwargs)
        self._openstack = None

    @property
    def openstack(self):
        if not self._openstack:
            self._openstack = openstack.OpenStackOperator(self.dbapi)
        return self._openstack

    def get_host_config(self, host):
        """
        Generate the hiera data for the puppet network config and route config
        resources for the host.
        """
        # Normalize some of the host info into formats that are easier to
        # use when parsing the interface list.
        context = self._create_interface_context(host)

        # interface configuration is organized into sets of network_config,
        # route_config and address_config resource hashes (dict)
        config = {
            NETWORK_CONFIG_RESOURCE: {},
            ROUTE_CONFIG_RESOURCE: {},
            ADDRESS_CONFIG_RESOURCE: {},
            SRIOV_CONFIG_RESOURCE: {},
            FPGA_CONFIG_RESOURCE: {},
            DATA_IFACE_LIST_RESOURCE: [],
        }

        system = self._get_system()
        # For AIO-SX subcloud, mgmt n/w will be on a separate
        # physical interface instead of the loopback interface.
        if system.system_mode != constants.SYSTEM_MODE_SIMPLEX or \
                self._distributed_cloud_role() == \
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            # Setup the loopback interface first
            generate_loopback_config(config)

        # Generate the actual interface config resources
        generate_interface_configs(context, config)

        # Generate the actual interface config resources
        generate_address_configs(context, config)

        # Generate data iface list configuration
        generate_data_iface_list_config(context, config)

        # Update the global context with generated interface context
        self.context.update(context)

        return config

    def _create_interface_context(self, host):
        host_interfaces = self.dbapi.iinterface_get_by_ihost(host.uuid)
        context = {
            'hostname': host.hostname,
            'personality': host.personality,
            'subfunctions': host.subfunctions,
            'system_uuid': host.isystem_uuid,
            'system_mode': self._get_system().system_mode,
            'ports': self._get_port_interface_id_index(host),
            'interfaces': self._get_interface_name_index(host_interfaces),
            'interfaces_datanets': self._get_interface_name_datanets(
                host.hostname, host_interfaces),
            'devices': self._get_port_pciaddr_index(host),
            'addresses': self._get_address_interface_name_index(host),
            'routes': self._get_routes_interface_name_index(host),
            'networks': self._get_network_type_index(),
            'gateways': self._get_gateway_index(),
            'floatingips': self._get_floating_ip_index(),
            'datanets': self._get_datanetworks(host),
            'vswitchtype': self._vswitch_type(),
        }
        return context

    def _find_host_interface(self, host_interfaces, networktype):
        """
        Search the host interface list looking for an interface with a given
        primary network type.
        """
        for iface in host_interfaces:
            for ni in self.dbapi.interface_network_get_by_interface(
                    iface['id']):
                network = self.dbapi.network_get(ni.id)
                if network.type == networktype:
                    return iface

    def _get_port_interface_id_index(self, host):
        """
        Builds a dictionary of ports indexed by interface id.
        """
        return interface._get_port_interface_id_index(self.dbapi, host)

    def _get_interface_name_index(self, host_interfaces):
        """
        Builds a dictionary of interfaces indexed by interface name.
        """
        return interface._get_interface_name_index(host_interfaces)

    def _get_interface_name_datanets(self, hostname, host_interfaces):
        """
        Builds a dictionary of datanets indexed by interface name.
        """
        return interface._get_interface_name_datanets(
            self.dbapi, hostname, host_interfaces)

    def _get_port_pciaddr_index(self, host):
        """
        Builds a dictionary of port lists indexed by PCI address.
        """
        devices = collections.defaultdict(list)
        for port in self.dbapi.ethernet_port_get_by_host(host.id):
            devices[port.pciaddr].append(port)
        return devices

    def _get_address_interface_name_index(self, host):
        """
        Builds a dictionary of address lists indexed by interface name.
        """
        return interface._get_address_interface_name_index(self.dbapi, host)

    def _get_routes_interface_name_index(self, host):
        """
        Builds a dictionary of route lists indexed by interface name.
        """
        routes = collections.defaultdict(list)
        for route in self.dbapi.routes_get_by_host(host.id):
            routes[route.ifname].append(route)

        results = collections.defaultdict(list)
        for ifname, entries in six.iteritems(routes):
            entries = sorted(entries, key=lambda r: r['prefix'], reverse=True)
            results[ifname] = entries
        return results

    def _get_network_type_index(self):
        networks = {}
        for network in self.dbapi.networks_get_all():
            networks[network['type']] = network
        return networks

    def _get_gateway_index(self):
        """
        Builds a dictionary of gateway IP addresses indexed by network type.
        """
        gateways = {}
        try:
            mgmt_address = self._get_address_by_name(
                constants.CONTROLLER_GATEWAY, constants.NETWORK_TYPE_MGMT)
            gateways.update({
                constants.NETWORK_TYPE_MGMT: mgmt_address.address})
        except exception.AddressNotFoundByName:
            pass

        try:
            oam_address = self._get_address_by_name(
                constants.CONTROLLER_GATEWAY, constants.NETWORK_TYPE_OAM)
            gateways.update({
                constants.NETWORK_TYPE_OAM: oam_address.address})
        except exception.AddressNotFoundByName:
            pass

        return gateways

    def _get_floating_ip_index(self):
        """
        Builds a dictionary of floating ip addresses indexed by network type.
        """
        mgmt_address = self._get_address_by_name(
            constants.CONTROLLER_HOSTNAME, constants.NETWORK_TYPE_MGMT)

        mgmt_floating_ip = (str(mgmt_address.address) + '/' +
                            str(mgmt_address.prefix))

        floating_ips = {
            constants.NETWORK_TYPE_MGMT: mgmt_floating_ip
        }

        try:
            pxeboot_address = self._get_address_by_name(
                constants.CONTROLLER_HOSTNAME, constants.NETWORK_TYPE_PXEBOOT)

            pxeboot_floating_ip = (str(pxeboot_address.address) + '/' +
                                   str(pxeboot_address.prefix))

            floating_ips.update({
                constants.NETWORK_TYPE_PXEBOOT: pxeboot_floating_ip,
            })
        except exception.AddressNotFoundByName:
            pass

        system = self._get_system()
        if system.system_mode != constants.SYSTEM_MODE_SIMPLEX:
            oam_address = self._get_address_by_name(
                constants.CONTROLLER_HOSTNAME, constants.NETWORK_TYPE_OAM)

            oam_floating_ip = (str(oam_address.address) + '/' +
                               str(oam_address.prefix))

            floating_ips.update({
                constants.NETWORK_TYPE_OAM: oam_floating_ip
            })

        try:
            cluster_address = self._get_address_by_name(
                constants.CONTROLLER_HOSTNAME,
                constants.NETWORK_TYPE_CLUSTER_HOST)
            if cluster_address:
                cluster_floating_ip = (str(cluster_address.address) + '/' +
                                       str(cluster_address.prefix))
                floating_ips.update({
                    constants.NETWORK_TYPE_CLUSTER_HOST: cluster_floating_ip
                })
        except exception.AddressNotFoundByName:
            pass

        try:
            ironic_address = self._get_address_by_name(
                constants.CONTROLLER_HOSTNAME, constants.NETWORK_TYPE_IRONIC)

            ironic_floating_ip = (str(ironic_address.address) + '/' +
                                  str(ironic_address.prefix))

            floating_ips.update({
                constants.NETWORK_TYPE_IRONIC: ironic_floating_ip,
            })
        except exception.AddressNotFoundByName:
            pass

        try:
            storage_address = self._get_address_by_name(
                constants.CONTROLLER_HOSTNAME, constants.NETWORK_TYPE_STORAGE)

            storage_floating_ip = (str(storage_address.address) + '/' +
                                   str(storage_address.prefix))

            floating_ips.update({
                constants.NETWORK_TYPE_STORAGE: storage_floating_ip,
            })
        except exception.AddressNotFoundByName:
            pass

        return floating_ips

    def _get_datanetworks(self, host):
        dnets = {}
        if constants.WORKER in utils.get_personalities(host):
            dnets = self.dbapi.datanetworks_get_all()
        return dnets


def is_platform_network_type(iface):
    return bool(iface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM)


def is_data_network_type(iface):
    return bool(iface['ifclass'] == constants.INTERFACE_CLASS_DATA)


def is_controller(context):
    """
    Determine we are creating a manifest for a controller node; regardless of
    whether it has a worker subfunction or not.
    """
    return bool(context['personality'] == constants.CONTROLLER)


def is_worker_subfunction(context):
    """
    Determine if we are creating a manifest for a worker node or a worker
    subfunction.
    """
    if context['personality'] == constants.WORKER:
        return True
    if constants.WORKER in context['subfunctions']:
        return True
    return False


def is_vswitch_type_unaccelerated(context):
    """
    Determine if the underlying device vswitch type is unaccelerated.
    """
    if context['vswitchtype'] == constants.VSWITCH_TYPE_NONE:
        return True
    return False


def is_pci_interface(iface):
    """
    Determine if the interface is one of the PCI device types.
    """
    return bool(iface['ifclass'] in PCI_INTERFACE_CLASSES)


def is_platform_interface(context, iface):
    """
    Determine whether the interface needs to be configured in the linux kernel
    as opposed to interfaces that exist purely in the vswitch.  This includes
    interfaces that are themselves platform interfaces or interfaces that have
    platform interfaces above them.  Both of these groups of interfaces require
    a linux interface that will be used for platform purposes (i.e., pxeboot,
    mgmt, cluster-host, oam).
    """
    if '_kernel' in iface:  # check cached result
        return iface['_kernel']
    else:
        kernel = False
        if is_platform_network_type(iface):
            kernel = True
        else:
            upper_ifnames = iface['used_by'] or []
            for upper_ifname in upper_ifnames:
                upper_iface = context['interfaces'][upper_ifname]
                if is_platform_interface(context, upper_iface):
                    kernel = True
                    break
    iface['_kernel'] = kernel  # cache the result
    return iface['_kernel']


def is_data_interface(context, iface):
    """
    Determine whether the interface needs to be configured in the vswitch.
    This includes interfaces that are themselves data interfaces or interfaces
    that have data interfaces above them.  Both of these groups of interfaces
    require vswitch configuration data.
    """
    if '_data' in iface:  # check cached result
        return iface['_data']
    else:
        data = False
        if is_data_network_type(iface):
            data = True
        else:
            upper_ifnames = iface['used_by'] or []
            for upper_ifname in upper_ifnames:
                upper_iface = context['interfaces'][upper_ifname]
                if is_data_interface(context, upper_iface):
                    data = True
                    break
    iface['_data'] = data  # cache the result
    return iface['_data']


def is_dpdk_compatible(context, iface):
    """
    Determine whether an interface can be supported in vswitch as a native DPDK
    interface.  Since whether an interface is supported or not by the DPDK
    means whether the DPDK has a hardware device driver for the underlying
    physical device this also implies that all non-hardware related interfaces
    are automatically supported in the DPDK.  For this reason we report True
    for VLAN and AE interfaces but check the DPDK support status for any
    ethernet interfaces.
    """
    if '_dpdksupport' in iface:  # check the cached result
        return iface['_dpdksupport']
    elif iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET:
        port = get_interface_port(context, iface)
        dpdksupport = port.get('dpdksupport', False)
    else:
        dpdksupport = True
    iface['_dpdksupport'] = dpdksupport  # cache the result
    return iface['_dpdksupport']


def is_a_mellanox_device(context, iface):
    """
    Determine if the underlying device is a Mellanox device.
    """
    if (iface['iftype'] not in
            [constants.INTERFACE_TYPE_ETHERNET, constants.INTERFACE_TYPE_VF]):
        # We only care about configuring specific settings for related ethernet
        # devices or VFs on top of these
        return False

    if iface['ifclass'] == constants.INTERFACE_CLASS_PCI_SRIOV:
        port = get_sriov_interface_port(context, iface)
    else:
        port = get_interface_port(context, iface)

    # port['driver'] may be a string of various comma separated driver names
    if port['driver']:
        drivers = (d.strip() for d in port['driver'].split(','))
        for d in drivers:
            if d in constants.MELLANOX_DRIVERS:
                return True
    return False


def is_an_n3000_i40_device(context, iface):
    """
    Determine if the underlying device is onboard an N3000 FPGA.
    """
    if iface['iftype'] != constants.INTERFACE_TYPE_ETHERNET:
        # We only care about configuring specific settings for related ethernet
        # devices.
        return False

    port = get_interface_port(context, iface)
    if not port:
        return False

    device_id = interface.get_pci_device_id(port)
    if not device_id:
        return False

    if device_id == dconstants.PCI_DEVICE_ID_FPGA_INTEL_I40_PF:
        return True
    return False


def get_master_interface(context, iface):
    """
    Get the interface name of the given interface's master (if any).  The
    master interface is the AE interface for any Ethernet interfaces.
    """
    if '_master' not in iface:  # check the cached result
        master = None
        if iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET:
            upper_ifnames = iface['used_by'] or []
            for upper_ifname in upper_ifnames:
                upper_iface = context['interfaces'][upper_ifname]
                if upper_iface['iftype'] == constants.INTERFACE_TYPE_AE:
                    master = upper_iface['ifname']
                    break
        iface['_master'] = master  # cache the result
    return iface['_master']


def is_slave_interface(context, iface):
    """
    Determine if this interface is a slave interface.  A slave interface is an
    interface that is part of an AE interface.
    """
    if '_slave' not in iface:  # check the cached result
        master = get_master_interface(context, iface)
        iface['_slave'] = bool(master)  # cache the result
    return iface['_slave']


def get_interface_mtu(context, iface):
    """
    Determine the MTU value to use for a given interface.  We trust that sysinv
    has selected the correct value.
    """
    return iface['imtu']


def get_interface_datanets(context, iface):
    """
    Return the list of data networks of the supplied interface
    """
    return interface.get_interface_datanets(context, iface)


def _get_datanetwork_names(context, iface):
    """
    Return the CSV list of data networks of the supplied interface
    """
    return interface._get_datanetwork_names(context, iface)


def get_interface_port(context, iface):
    """
    Determine the port of the underlying device.
    """
    return interface.get_interface_port(context, iface)


def get_interface_port_name(context, iface):
    """
    Determine the port name of the underlying device.
    """
    assert iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET
    port = get_interface_port(context, iface)
    if port:
        return port['name']


def get_lower_interface(context, iface):
    """
    Return the interface object that is used to implement a VLAN interface.
    """
    return interface.get_lower_interface(context, iface)


def get_lower_interface_os_ifname(context, iface):
    """
    Return the kernel interface name of the lower interface used to implement a
    VLAN interface.
    """
    lower_iface = get_lower_interface(context, iface)
    return get_interface_os_ifname(context, lower_iface)


def get_interface_os_ifname(context, iface):
    """
    Determine the interface name used in the linux kernel for the given
    interface. Ethernet interfaces uses the original linux device name while
    AE devices can use the user-defined named. VLAN interface must derive
    their names based on their lower interface name.
    """
    if '_os_ifname' in iface:  # check cached result
        return iface['_os_ifname']
    else:
        os_ifname = iface['ifname']
        if iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET:
            os_ifname = get_interface_port_name(context, iface)
        elif iface['iftype'] == constants.INTERFACE_TYPE_VLAN:
            if iface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM:
                os_ifname = "vlan" + str(iface['vlan_id'])
            else:
                lower_os_ifname = get_lower_interface_os_ifname(context, iface)
                os_ifname = lower_os_ifname + "." + str(iface['vlan_id'])
        elif iface['iftype'] == constants.INTERFACE_TYPE_AE:
            os_ifname = iface['ifname']
        iface['_os_ifname'] = os_ifname  # cache the result
        return iface['_os_ifname']


def get_interface_devices(context, iface, devices=None):
    """
    Determine all the interface devices used in the linux kernel for the given
    interface name. Ethernet interfaces uses the original linux device while AE
    and VLAN interfaces use all the slave devices. Virtual interfaces use a name.
    """
    if devices is None:
        devices = []

    if iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET:
        devices.append(get_interface_port_name(context, iface))
    elif iface['iftype'] == constants.INTERFACE_TYPE_VIRTUAL:
        devices.append(iface['ifname'])
    elif iface['iftype'] == constants.INTERFACE_TYPE_VLAN \
            or iface['iftype'] == constants.INTERFACE_TYPE_AE:
        slaves = get_interface_slaves(context, iface)
        for slave in slaves:
            get_interface_devices(context, slave, devices)

    return devices


def get_interface_routes(context, iface):
    """
    Determine the list of routes that are applicable to a given interface (if
    any).
    """
    return context['routes'][iface['ifname']]


def _set_address_netmask(address):
    """
    The netmask is not supplied by sysinv but is required by the puppet
    resource class.
    """
    network = IPNetwork(address['address'] + '/' + str(address['prefix']))
    if network.version == 6:
        address['netmask'] = str(network.prefixlen)
    else:
        address['netmask'] = str(network.netmask)
    return address


def get_interface_primary_address(context, iface, network_id=None):
    """
    Determine the primary IP address on an interface (if any).  If multiple
    addresses exist then the first address is returned.
    """
    addresses = context['addresses'].get(iface['ifname'], [])
    if len(addresses) > 0 and network_id is None:
        return _set_address_netmask(addresses[0])
    elif network_id:
        for address in addresses:
            net = find_network_by_pool_uuid(context,
                                            address.pool_uuid)
            if net and network_id == net.id:
                return _set_address_netmask(address)


def get_interface_address_family(context, iface, network_id=None):
    """
    Determine the IP family/version of the interface primary address.  If there
    is no address then the IPv4 family identifier is returned so that an
    appropriate default is always present in interface configurations.
    """
    address = get_interface_primary_address(context, iface, network_id)
    if not address:
        return 'inet'  # default to ipv4
    elif IPAddress(address['address']).version == 4:
        return 'inet'
    else:
        return 'inet6'


def get_interface_gateway_address(context, networktype):
    """
    Determine if the interface has a default gateway.
    """
    return context['gateways'].get(networktype, None)


def get_interface_address_method(context, iface, network_id=None):
    """
    Determine what type of interface to configure for each network type.
    """
    networktype = find_networktype_by_network_id(context, network_id)

    has_static_addr = False
    if (iface.ipv4_mode == constants.IPV4_STATIC or iface.ipv6_mode == constants.IPV6_STATIC):
        has_static_addr = True

    if iface.ifclass == constants.INTERFACE_CLASS_DATA:
        if is_syscfg_network():
            if is_vswitch_type_unaccelerated(context):
                return STATIC_METHOD
        else:
            if has_static_addr:
                return STATIC_METHOD
        # All data interfaces configured in the kernel because they are not
        # natively supported in vswitch or need to be shared with the kernel
        # because of a platform VLAN should be left as manual config
        return MANUAL_METHOD
    elif (iface.ifclass == constants.INTERFACE_CLASS_PLATFORM and
            networktype is None and has_static_addr):

        # On Debian, interfaces of networktype:None with alias should be
        # manual method (i.e: lo) and alias will be Static method (i.e: lo:1)
        if not is_syscfg_network() and len(iface.networktypelist) > 1:
            return MANUAL_METHOD

        # Allow platform-class interface with ipv4 mode set to static to
        # have static ip address
        return STATIC_METHOD
    elif not iface.ifclass or iface.ifclass == constants.INTERFACE_CLASS_NONE \
            or not networktype:
        # Interfaces that are configured purely as a dependency from other
        # interfaces (i.e., vlan lower interface, bridge member, bond slave)
        # should be left as manual config
        return MANUAL_METHOD
    elif iface.ifclass in PCI_INTERFACE_CLASSES:
        return MANUAL_METHOD
    else:
        if is_controller(context):
            # All other interface types that exist on a controller are setup
            # statically since the controller themselves run the DHCP server.
            return STATIC_METHOD
        elif networktype == constants.NETWORK_TYPE_CLUSTER_HOST:
            return STATIC_METHOD
        elif networktype == constants.NETWORK_TYPE_STORAGE:
            return STATIC_METHOD
        elif networktype == constants.NETWORK_TYPE_PXEBOOT:
            # All pxeboot interfaces that exist on non-controller nodes are set
            # to manual as they are not needed/used once the install is done.
            # They exist only in support of the vlan mgmt interface above it.
            return MANUAL_METHOD
        else:
            # All other types get their addresses from the controller
            return DHCP_METHOD


def get_interface_traffic_classifier(context, iface):
    """
    Get the interface traffic classifier command line (if any)
    """
    for networktype in iface.networktypelist:
        if (networktype == constants.NETWORK_TYPE_MGMT):
            networkspeed = constants.LINK_SPEED_10G
            ifname = get_interface_os_ifname(context, iface)
            return '%s %s %s %s > /dev/null' \
                   % (constants.TRAFFIC_CONTROL_SCRIPT,
                      ifname,
                      networktype,
                      networkspeed)
    return None


def get_bridge_interface_name(context, iface):
    """
    If the given interface is a bridge member then retrieve the bridge
    interface name otherwise return None.
    """
    if '_bridge' in iface:  # check the cached result
        return iface['_bridge']
    else:
        bridge = None
        if (iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET and
                is_data_interface(context, iface) and
                not is_dpdk_compatible(context, iface) and
                not is_vswitch_type_unaccelerated(context)):
            bridge = 'br-' + get_interface_os_ifname(context, iface)
        iface['_bridge'] = bridge  # cache the result
        return iface['_bridge']


def is_bridged_interface(context, iface):
    """
    Determine if this interface is a member of a bridge.  A interface is a
    member of a bridge if the interface is a data interface that is not
    accelerated (i.e., a slow data interface).
    """
    if '_bridged' in iface:  # check the cached result
        return iface['_bridged']
    else:
        bridge = get_bridge_interface_name(context, iface)
        iface['_bridged'] = bool(bridge)  # cache the result
        return iface['_bridged']


def needs_interface_config(context, iface):
    """
    Determine whether an interface needs to be configured in the linux kernel.
    This is true if the interface is a platform interface, is required by a
    platform interface (i.e., an AE member, a VLAN lower interface), or is an
    unaccelerated data interface.
    """
    if is_platform_interface(context, iface):
        return True
    elif not is_worker_subfunction(context):
        return False
    elif is_data_interface(context, iface):
        if is_vswitch_type_unaccelerated(context):
            # a platform interface configuration will use the host interface when
            # the vswitch is unaccelerated.
            return True
        if not is_dpdk_compatible(context, iface):
            # vswitch interfaces for devices that are not natively supported by
            # the DPDK are created as regular Linux devices and then bridged in
            # to vswitch in order for it to be able to use it indirectly.
            return True
        if is_a_mellanox_device(context, iface):
            # Check for Mellanox data interfaces. We must set the MTU sizes of
            # Mellanox data interfaces in case it is not the default.  Normally
            # data interfaces are owned by DPDK, they are not managed through
            # Linux but in the Mellanox case, the interfaces are still visible
            # in Linux so in case one needs to set jumbo frames, it has to be
            # set in Linux as well. We only do this for combined nodes or
            # non-controller nodes.
            return True
    elif is_pci_interface(iface):
        return True
    return False


def get_basic_network_config(ifname, ensure='present',
                             method='manual', onboot='true',
                             hotplug='false', family='inet',
                             mtu=None):
    """
    Builds a basic network config dictionary with all of the fields required to
    format a basic network_config puppet resource.
    """
    config = {'ifname': ifname,
              'ensure': ensure,
              'family': family,
              'method': method,
              'hotplug': hotplug,
              'onboot': onboot,
              'options': {}}
    if mtu:
        if is_syscfg_network():
            config['mtu'] = str(mtu)
        else:
            config['options']['mtu'] = str(mtu)
    return config


def get_bridge_network_config(context, iface):
    """
    Builds a network config dictionary for bridge interface resource.
    """
    os_ifname = get_interface_os_ifname(context, iface)
    os_ifname = 'br-' + os_ifname
    method = get_interface_address_method(context, iface)
    family = get_interface_address_family(context, iface)
    config = get_basic_network_config(
        os_ifname, method=method, family=family)
    config['options']['TYPE'] = 'Bridge'
    return config


def is_disable_dad_required(context, iface, config, network_id=None):
    """
    Determine whether DAD is required to be disabled.
    If mgmt and cluster-host are separate vlans, the vlan has DAD disabled.
    If the vlans are shared between networks, the DAD is disabled
       on the parent vlan interface, not the alias interfaces.
    If mgmt and cluster-host are not vlan, the interfaces have DAD disabled.
    """
    networktype = find_networktype_by_network_id(context, network_id)
    if len(iface.networktypelist) > 1:
        if (iface['iftype'] == constants.INTERFACE_TYPE_VLAN and
                network_id is None):
            return True
    elif (networktype and networktype in [constants.NETWORK_TYPE_MGMT,
                                          constants.NETWORK_TYPE_CLUSTER_HOST]):
        return True
    return False


def get_interface_sysctl_ifname(context, iface):
    """
    Get the interface name that is used for sysctl commands
    """
    os_ifname = get_interface_os_ifname(context, iface)
    if (iface['iftype'] == constants.INTERFACE_TYPE_VLAN):
        return os_ifname.replace('.', '/')
    else:
        return os_ifname


def get_duplex_direct_network_config(context, iface, config, sysctl_ifname, network_id):
    """
    Disable dad on the specified interface for duplex-direct config
    """
    networktype = find_networktype_by_network_id(context, network_id)
    if (networktype and networktype in [constants.NETWORK_TYPE_MGMT,
                                        constants.NETWORK_TYPE_CLUSTER_HOST]):
        command = ("/sbin/modprobe bonding; "
                   "grep %s /sys/class/net/bonding_masters || "
                   "echo +%s > /sys/class/net/bonding_masters" % (
                       iface['ifname'], iface['ifname']))
        fill_interface_config_option_operation(config['options'], IFACE_PRE_UP_OP, command)
    new_pre_up = "sysctl -wq net.ipv6.conf.%s.accept_dad=0" % sysctl_ifname
    fill_interface_config_option_operation(config['options'], IFACE_PRE_UP_OP, new_pre_up)
    return config


def get_vlan_network_config(context, iface, config):
    """
    Augments a basic config dictionary with the attributes specific to a VLAN
    interface.
    """
    lower_os_ifname = get_lower_interface_os_ifname(context, iface)
    if is_syscfg_network():
        options = {'VLAN': 'yes', 'PHYSDEV': lower_os_ifname}
    else:
        options = {'vlan-raw-device': lower_os_ifname}
    fill_interface_config_option_operation(options, IFACE_PRE_UP_OP,
                                           '/sbin/modprobe -q 8021q')
    config['options'].update(options)
    return config


def get_bond_interface_options_sysconfig(iface, primary_iface):
    """
    Get the interface config attribute for bonding options
    """
    ae_mode = iface['aemode']
    tx_hash_policy = iface['txhashpolicy']
    options = None
    if ae_mode in ACTIVE_STANDBY_AE_MODES:
        # Requires the active device in an active_standby LAG
        # configuration to be determined based on the lowest MAC address
        options = 'mode=active-backup miimon=100 primary={}'.format(primary_iface['ifname'])
        if iface['primary_reselect']:
            options += ' primary_reselect=%s' % iface['primary_reselect']
    else:
        options = 'xmit_hash_policy=%s miimon=100' % tx_hash_policy
        if ae_mode in BALANCED_AE_MODES:
            options = 'mode=balance-xor ' + options
        elif ae_mode in LACP_AE_MODES:
            options = 'mode=802.3ad lacp_rate=fast ' + options
    return options


def get_bond_interface_options_ifupdown(iface, primary_iface):
    """
    Get the interface config attribute for bonding options
    """
    ae_mode = iface['aemode']
    tx_hash_policy = iface['txhashpolicy']
    options = dict()
    options['bond-miimon'] = '100'
    if ae_mode in ACTIVE_STANDBY_AE_MODES:
        # Requires the active device in an active_standby LAG
        # configuration to be determined based on the lowest MAC address
        options['bond-mode'] = 'active-backup'
        options['bond-primary'] = primary_iface['ifname']
        if iface['primary_reselect']:
            options['bond-primary-reselect'] = iface['primary_reselect']
    else:
        options['bond-xmit-hash-policy'] = tx_hash_policy
        if ae_mode in BALANCED_AE_MODES:
            options['bond-mode'] = 'balance-xor'
        elif ae_mode in LACP_AE_MODES:
            options['bond-mode'] = '802.3ad'
            options['bond-lacp-rate'] = 'fast'
    if iface['uses']:
        bond_slaves = str()
        for iface in iface['uses']:
            bond_slaves += (iface + ' ')
        options['bond-slaves'] = bond_slaves
    return options


def get_bond_network_config(context, iface, config, network_id):
    """
    Augments a basic config dictionary with the attributes specific to a bond
    interface.
    """
    primary_iface = get_primary_bond_interface(context, iface)
    options = dict()
    bonding_options = None
    iface_mac = iface['imac'].rstrip()

    if is_syscfg_network():
        options['MACADDR'] = iface_mac
        bonding_options = get_bond_interface_options_sysconfig(iface, primary_iface)
        if bonding_options:
            options['BONDING_OPTS'] = bonding_options
    else:
        options['hwaddress'] = iface_mac
        bonding_options = get_bond_interface_options_ifupdown(iface, primary_iface)
        if bonding_options:
            options.update(bonding_options)

    if bonding_options:
        fill_interface_config_option_operation(options, IFACE_UP_OP, 'sleep 10')
    config['options'].update(options)
    return config


def get_primary_bond_interface(context, iface):
    """
    Return the slave interface with the lowest MAC address
    """
    slaves = get_interface_slaves(context, iface)
    sorted_slaves = sorted(slaves, key=slave_sort_key)
    primary_iface = sorted_slaves[0]
    return primary_iface


def get_interface_slaves(context, iface):
    """
    Return the slave interface objects for the corresponding
    bond or vlan interface.
    """
    slaves = iface['uses']
    ifaces = []
    for ifname, iface in six.iteritems(context['interfaces']):
        if ifname in slaves:
            ifaces.append(iface)
    return ifaces


def slave_sort_key(iface):
    """
    Sort interfaces by lowest MAC address
    """
    return int(iface['imac'].replace(':', ''), 16)


def get_ethernet_network_config(context, iface, config):
    """
    Augments a basic config dictionary with the attributes specific to an
    ethernet interface.
    """
    interface_class = iface['ifclass']
    options = {}
    # Increased to accommodate devices that require more time to
    # complete link auto-negotiation
    if is_syscfg_network():
        options['LINKDELAY'] = '20'

    if is_bridged_interface(context, iface):
        if is_syscfg_network():
            options['BRIDGE'] = get_bridge_interface_name(context, iface)
    elif is_slave_interface(context, iface):
        if not is_data_interface(context, iface):
            # Data interfaces that require a network configuration are not
            # candidates for bonding.  They exist because their DPDK drivers
            # rely on the Linux device driver to setup some or all functions
            # on the device (e.g., the Mellanox DPDK driver relies on the
            # Linux driver to set the proper MTU value).
            if is_syscfg_network():
                options['SLAVE'] = 'yes'
                options['MASTER'] = get_master_interface(context, iface)
                options['PROMISC'] = 'yes'
            else:
                master = get_master_interface(context, iface)
                options['bond-master'] = master
                osname = get_interface_os_ifname(context, iface)
                command = '/usr/sbin/ip link set dev {} promisc on'.format(osname)
                fill_interface_config_option_operation(options, IFACE_PRE_UP_OP, command)
                # the allow-* is a separated stanza in ifupdown, but without
                # support in puppet-network module, this stanza is needed to
                # make ifup to run the slave's pre-up commands. It will be
                # adjusted during parsing in apply_network_config.sh
                options['allow-{}'.format(master)] = osname
    elif interface_class == constants.INTERFACE_CLASS_PCI_SRIOV:
        if iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET:
            sriovfs_path = ("/sys/class/net/%s/device/sriov_numvfs" %
                            get_interface_port_name(context, iface))
            command = "echo 0 > %s; echo %s > %s" % (sriovfs_path, iface['sriov_numvfs'],
                                                        sriovfs_path)
            iface_op = get_device_sriov_setup_op(context, iface)
            fill_interface_config_option_operation(options, iface_op, command)
    elif interface_class == constants.INTERFACE_CLASS_PCI_PASSTHROUGH:
        sriovfs_path = ("/sys/class/net/%s/device/sriov_numvfs" %
                        get_interface_port_name(context, iface))
        command = "if [ -f  %s ]; then echo 0 > %s; fi" % (
            sriovfs_path, sriovfs_path)
        iface_op = get_device_sriov_setup_op(context, iface)
        fill_interface_config_option_operation(options, iface_op, command)

    config['options'].update(options)
    return config


def get_route_config(route, ifname):
    """
    Builds a basic route config dictionary with all of the fields required to
    format a basic network_route puppet resource.
    """
    if route['prefix']:
        name = '%s/%s' % (route['network'], route['prefix'])
    else:
        name = 'default'
    netmask = IPNetwork(route['network'] + "/" + str(route['prefix'])).netmask
    config = {
        'name': name,
        'ensure': 'present',
        'gateway': route['gateway'],
        'interface': ifname,
        'netmask': str(netmask) if route['prefix'] else '0.0.0.0',
        'network': route['network'] if route['prefix'] else 'default',
        'options': 'metric ' + str(route['metric'])

    }
    return config


def get_device_sriov_setup_op(context, iface):
    """
    Determines if the interface has a driver that requires it to be up before
    SR-IOV/virtual function interfaces can be set up. Returns the corresponding
    interface pre/post-up operation code.
    """
    port = get_interface_port(context, iface)

    if port['driver'] in constants.DRIVERS_UP_BEFORE_SRIOV:
        return IFACE_POST_UP_OP
    else:
        return IFACE_PRE_UP_OP


def get_sriov_interface_up_requirement(context, iface):
    """
    Determines if an interface has a driver that requires it to be
    administratively up before VFs can be set up.
    """
    port = get_interface_port(context, iface)

    if port['driver'] in constants.DRIVERS_UP_BEFORE_SRIOV:
        return True
    else:
        return False


def get_sriov_interface_port(context, iface):
    """
    Determine the underlying port of the SR-IOV interface.
    """
    return interface.get_sriov_interface_port(context, iface)


def get_sriov_interface_device_id(context, iface):
    """
    Determine the underlying PCI device id of the SR-IOV interface.
    """
    return interface.get_sriov_interface_device_id(context, iface)


def get_sriov_interface_vf_addrs(context, iface, vf_addr_list):
    """
    Determine the virtual function addresses of SR-IOV interface,
    given the list of vf addresses on the port.
    """
    return interface.get_sriov_interface_vf_addrs(context, iface, vf_addr_list)


def get_sriov_vf_config(context, iface, port, vf_config):
    """
    Determine the virtual function config for an SR-IOV interface.
    """

    # Calculate the VF addresses to assign to a logical VF interface,
    # taking into account any upper or lower interfaces.
    vf_addr_list = []
    all_vf_addr_list = []
    all_vf_addrs = port.get('sriov_vfs_pci_address', None)
    if all_vf_addrs:
        all_vf_addr_list = all_vf_addrs.split(',')
        vf_addr_list = interface.get_sriov_interface_vf_addrs(
            context, iface, all_vf_addr_list)

    # Format the vf addresses as quoted strings in order to prevent
    # puppet from treating the address as a time/date value
    vf_addrs = [quoted_str(addr.strip()) for addr in vf_addr_list if addr]

    # Get the user specified VF driver, if any.  If the driver is
    # None, the driver will be determined by the kernel.  That is,
    # No explicit bind will be done.
    vf_driver = iface.get('sriov_vf_driver', None)
    if vf_driver:
        if constants.SRIOV_DRIVER_TYPE_VFIO in vf_driver:
            vf_driver = constants.SRIOV_DRIVER_VFIO_PCI
        elif constants.SRIOV_DRIVER_TYPE_NETDEVICE in vf_driver:
            vf_driver = port.get('sriov_vf_driver', None)

    for addr in vf_addrs:
        rate = iface.get('max_tx_rate', None)
        if rate:
            vfnum = utils.get_sriov_vf_index(addr, all_vf_addr_list)
            vf_config.update({
                addr: {
                    'addr': addr,
                    'driver': vf_driver,
                    'vfnumber': vfnum,
                    'max_tx_rate': rate
                }
            })
        else:
            vf_config.update({
                addr: {
                    'addr': addr,
                    'driver': vf_driver
                }
            })

    if iface.get('used_by', None):
        upper_ifaces = iface['used_by']
        for upper_ifname in upper_ifaces:
            upper_iface = context['interfaces'][upper_ifname]
            if upper_iface['iftype'] == constants.INTERFACE_TYPE_VF:
                get_sriov_vf_config(context, upper_iface, port, vf_config)


def get_sriov_config(context, iface):
    """
    Returns an SR-IOV interface config dictionary.
    """
    vf_config = {}

    if iface['iftype'] != constants.INTERFACE_TYPE_ETHERNET:
        return {}

    port = interface.get_sriov_interface_port(context, iface)
    if not port:
        return {}

    # Include the desired number of VFs if the device supports SR-IOV
    # config via sysfs and is not a sub-interface
    num_vfs = None
    if iface['iftype'] != constants.INTERFACE_TYPE_VF:
        num_vfs = iface['sriov_numvfs']

    get_sriov_vf_config(context, iface, port, vf_config)

    config = {
        'ifname': iface['ifname'],
        'addr': quoted_str(port['pciaddr'].strip()),
        'num_vfs': num_vfs,
        'device_id': interface.get_sriov_interface_device_id(context, iface),
        'port_name': port['name'],
        'up_requirement': get_sriov_interface_up_requirement(context, iface),
        'vf_config': vf_config
    }
    return config


def get_n3000_config(context, iface):
    config = {}
    if is_an_n3000_i40_device(context, iface):
        port = get_interface_port(context, iface)
        if not port:
            return {}

        device_id = interface.get_pci_device_id(port)
        if not device_id:
            return {}

        vlans = []
        for ifname in iface.get('used_by', []):
            upper = context['interfaces'][ifname]
            if upper['iftype'] == constants.INTERFACE_TYPE_VLAN:
                vlans.append(get_interface_os_ifname(context, upper))

        config = {
            'ifname': port['name'],
            'device_id': device_id,
            'used_by': vlans
        }
    return config


def get_fpga_config(context, iface):
    """
    Returns an FPGA interface config dictionary.
    """
    config = {}
    config.update(get_n3000_config(context, iface))
    return config


def get_common_network_config(context, iface, config, network_id=None):
    """
    Augments a basic config dictionary with the attributes specific to an upper
    layer interface (i.e., an interface that is used to terminate IP traffic).
    """
    LOG.debug("get_common_network_config %s %s network_id=%s" %
              (iface.ifname, iface.networktypelist, network_id))

    os_ifname = get_interface_os_ifname(context, iface)
    if os_ifname == config['ifname']:
        # post-up scripts do not work for aliases.
        traffic_classifier = get_interface_traffic_classifier(context, iface)
        if traffic_classifier:
            fill_interface_config_option_operation(config['options'], IFACE_POST_UP_OP,
                                                   traffic_classifier)

    method = get_interface_address_method(context, iface, network_id)
    if method == STATIC_METHOD:
        address = get_interface_primary_address(context, iface, network_id)
        if address:
            config['ipaddress'] = address['address']
            config['netmask'] = address['netmask']
        else:
            LOG.info("Interface %s has no primary address" % iface['ifname'])

        networktype = find_networktype_by_network_id(context, network_id)
        gateway = get_interface_gateway_address(context, networktype)
        if gateway:
            if is_syscfg_network():
                config['gateway'] = gateway
            else:
                config['options']['gateway'] = gateway
    return config


def get_final_network_config(context, iface, config, network_id=None):
    """
    Augments a basic config dictionary with the attribute that must be
    appended to an attribute that is already configured (e.g. pre_up)
    """
    # add duplex_direct specific network config
    if context['system_mode'] == constants.SYSTEM_MODE_DUPLEX_DIRECT:
        if is_disable_dad_required(context, iface, config, network_id):
            dd_ifname = get_interface_sysctl_ifname(context, iface)
            config = get_duplex_direct_network_config(context, iface, config,
                                                      dd_ifname, network_id)
    return config


def get_interface_network_config(context, iface, network_id=None):
    """
    Builds a network_config resource dictionary for a given interface
    """

    if iface['iftype'] == constants.INTERFACE_TYPE_VF:
        # Only the parent SR-IOV interface needs a network config
        return {}

    # Create a basic network config resource
    os_ifname = get_interface_os_ifname(context, iface)
    method = get_interface_address_method(context, iface, network_id)
    family = get_interface_address_family(context, iface, network_id)

    # setup an alias interface if there are multiple addresses assigned
    # NOTE: DHCP will only operate over a non-alias interface
    if len(iface.networktypelist) > 1 and network_id and method != DHCP_METHOD:
        ifname = "%s:%d" % (os_ifname, network_id)
    else:
        ifname = os_ifname

    mtu = get_interface_mtu(context, iface)
    config = get_basic_network_config(
        ifname, method=method, family=family, mtu=mtu)

    # Add options common to all top level interfaces
    config = get_common_network_config(context, iface, config, network_id)

    # ensure addresses have host scope when configured against the loopback
    if os_ifname == LOOPBACK_IFNAME:
        if is_syscfg_network():
            options = {'SCOPE': 'scope host'}
        else:
            options = {'scope': 'host'}
        config['options'].update(options)

    # Add type specific options
    if iface['iftype'] == constants.INTERFACE_TYPE_VLAN:
        config = get_vlan_network_config(context, iface, config)
    elif iface['iftype'] == constants.INTERFACE_TYPE_AE:
        config = get_bond_network_config(context, iface, config, network_id)
    else:
        config = get_ethernet_network_config(context, iface, config)

    # Add final options
    config = get_final_network_config(context, iface, config, network_id)

    # disable ipv6 autoconfig
    if is_syscfg_network():
        config['options'].update({'IPV6_AUTOCONF': 'no'})
    else:
        interface_op = IFACE_POST_UP_OP
        if is_slave_interface(context, iface):
            # ifupdown's ifup only runs pre-up for slave interfaces
            interface_op = IFACE_PRE_UP_OP

        if iface['iftype'] == constants.INTERFACE_TYPE_VLAN:
            # When configuring a static IPv6 interface, CentOS' ifup tool uses 'ip link'
            # command to set both IPv4 and IPv6 MTU.
            # Debian's ifup tool instead uses sysctl to set only the IPv6 MTU. But this
            # value gets reset to the underlying device's MTU soon after ifup set sets the
            # interface state to up. So we need to set the MTU again during post-up.
            # Using 'ip link' command here instead of sysctl, will set both IPv4 and IPv6
            # MTU like in CentOS.
            set_mtu = '/usr/sbin/ip link set dev {} mtu {}'.format(os_ifname, mtu)
            fill_interface_config_option_operation(config['options'], interface_op, set_mtu)

        autoconf_off = 'echo 0 > /proc/sys/net/ipv6/conf/{}/autoconf'.format(os_ifname)
        fill_interface_config_option_operation(config['options'], interface_op, autoconf_off)
        accept_ra_off = 'echo 0 > /proc/sys/net/ipv6/conf/{}/accept_ra'.format(os_ifname)
        fill_interface_config_option_operation(config['options'], interface_op, accept_ra_off)
        accept_redir_off = 'echo 0 > /proc/sys/net/ipv6/conf/{}/accept_redirects'.format(os_ifname)
        fill_interface_config_option_operation(config['options'], interface_op, accept_redir_off)

    return config


def generate_network_config(context, hiera_config, iface):
    """
    Produce the puppet network config resources necessary to configure the
    given interface.  In some cases this will emit a single network_config
    resource, while in other cases it will emit multiple resources to create a
    bridge, or to add additional route resources.
    """
    ifname = get_interface_os_ifname(context, iface)

    # Setup the default device configuration for the interface.  This will be
    # overridden if there is a specific network type configuration, otherwise
    # it will act as the parent device for the aliases
    net_config = get_interface_network_config(context, iface)
    if net_config:
        hiera_config[NETWORK_CONFIG_RESOURCE].update({
            net_config['ifname']: format_network_config(net_config)
        })

    for net_type in iface.networktypelist:
        net_id = find_network_id_by_networktype(context, net_type)
        net_config = get_interface_network_config(context, iface, net_id)
        if net_config:
            hiera_config[NETWORK_CONFIG_RESOURCE].update({
                net_config['ifname']: format_network_config(net_config)
            })

    # Add complementary puppet resource definitions (if needed)
    for route in get_interface_routes(context, iface):
        route_config = get_route_config(route, ifname)
        hiera_config[ROUTE_CONFIG_RESOURCE].update({
            route_config['name']: route_config
        })

    interface_class = iface['ifclass']
    if interface_class == constants.INTERFACE_CLASS_PCI_SRIOV:
        sriov_config = get_sriov_config(context, iface)
        if sriov_config:
            hiera_config[SRIOV_CONFIG_RESOURCE].update({
                sriov_config['ifname']: format_sriov_config(sriov_config)
            })

    fpga_config = get_fpga_config(context, iface)
    if fpga_config:
        hiera_config[FPGA_CONFIG_RESOURCE].update({
            fpga_config['ifname']: format_fpga_config(fpga_config)
        })


def find_network_by_pool_uuid(context, pool_uuid):
    for networktype, network in six.iteritems(context['networks']):
        if network.pool_uuid == pool_uuid:
            return network
    return None


def find_network_id_by_networktype(context, networktype):
    for net_type, network in six.iteritems(context['networks']):
        if networktype == net_type:
            return network.id


def find_networktype_by_network_id(context, network_id):
    for networktype, network in six.iteritems(context['networks']):
        if network.id == network_id:
            return networktype


def find_interface_by_type(context, networktype):
    """
    Lookup an interface based on networktype.  This is only intended for
    platform interfaces that have only 1 such interface per node (i.e., oam,
    mgmt, cluster-host, pxeboot, bmc).
    """
    for ifname, iface in six.iteritems(context['interfaces']):
        for net_type in iface.networktypelist:
            if networktype == net_type:
                return iface


def find_address_by_type(context, networktype):
    """
    Lookup an address based on networktype.  This is only intended for for
    types that only have 1 such address per node.  For example, for SDN we
    only expect/support a single data IP address per node because the SDN
    controller cannot support more than 1.
    """
    for ifname, addresses in six.iteritems(context['addresses']):
        for address in addresses:
            if address['networktype'] == networktype:
                return address['address'], address['prefix']
    return None, None


def find_sriov_interfaces_by_driver(context, driver):
    """
    Lookup all interfaces based on port driver.
    To be noted that this is only used for IFTYPE_ETHERNET
    """
    ifaces = []
    for ifname, iface in six.iteritems(context['interfaces']):
        if iface['iftype'] != constants.INTERFACE_TYPE_ETHERNET:
            continue
        port = get_interface_port(context, iface)
        if (port['driver'] == driver and
                iface['ifclass'] == constants.INTERFACE_CLASS_PCI_SRIOV):
            ifaces.append(iface)
    return ifaces


def get_ptp_interfaces(context):
    """
    Lookup interfaces with a ptp_role specified
    """
    ifaces = []
    for ifname, iface in six.iteritems(context['interfaces']):
        if iface['ptp_role'] != constants.INTERFACE_PTP_ROLE_NONE:
            ifaces.append(iface)
    return ifaces


def interface_sort_key(iface):
    """
    Sort interfaces by interface type placing ethernet interfaces ahead of
    aggregated ethernet and vlan interfaces, with pci interfaces last.
    """
    if iface['iftype'] == constants.INTERFACE_TYPE_VIRTUAL:
        return 0, iface['ifname']
    elif iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET and not is_pci_interface(iface):
        return 1, iface['ifname']
    elif iface['iftype'] == constants.INTERFACE_TYPE_AE:
        return 2, iface['ifname']
    elif iface['iftype'] == constants.INTERFACE_TYPE_VLAN:
        return 3, iface['ifname']
    elif is_pci_interface(iface):
        return 4, iface['ifname']
    else:
        msg = _('Invalid iftype: %s') % iface['iftype']
        raise exception.SysinvException(msg)


def generate_interface_configs(context, config):
    """
    Generate the puppet resource for each of the interface and route config
    resources.
    """
    for iface in sorted(context['interfaces'].values(),
                        key=interface_sort_key):
        if needs_interface_config(context, iface):
            generate_network_config(context, config, iface)


def get_address_config(context, iface, address):
    ifname = get_interface_os_ifname(context, iface)
    return {
        'ifname': ifname,
        'address': address,
    }


def generate_address_configs(context, config):
    """
    Generate the puppet resource for each of the floating IP addresses
    """
    for networktype, address in six.iteritems(context['floatingips']):
        iface = find_interface_by_type(context, networktype)
        if iface:
            address_config = get_address_config(context, iface, address)
            config[ADDRESS_CONFIG_RESOURCE].update({
                networktype: address_config
            })
        elif networktype == constants.NETWORK_TYPE_PXEBOOT:
            # Fallback PXE boot address against management interface
            iface = find_interface_by_type(context,
                                           constants.NETWORK_TYPE_MGMT)
            if iface:
                address_config = get_address_config(context, iface, address)
                config[ADDRESS_CONFIG_RESOURCE].update({
                    networktype: address_config
                })
        elif networktype == constants.NETWORK_TYPE_CLUSTER_HOST:
            # Fallback cluster host address against management interface
            iface = find_interface_by_type(context,
                                           constants.NETWORK_TYPE_CLUSTER_HOST)
            if iface:
                address_config = get_address_config(context, iface, address)
                config[ADDRESS_CONFIG_RESOURCE].update({
                    networktype: address_config
                })


def generate_data_iface_list_config(context, config):
    """
    Generate the puppet resource for data-network iface name.
    """
    for iface in context['interfaces'].values():
        if is_data_interface(context, iface):
            ifname = get_interface_os_ifname(context, iface)
            config[DATA_IFACE_LIST_RESOURCE].append(ifname)


def generate_loopback_config(config):
    """
    Generate the loopback network config resource so that the loopback
    interface is automatically enabled on reboots.
    """
    network_config = get_basic_network_config(LOOPBACK_IFNAME,
                                              method=LOOPBACK_METHOD)
    config[NETWORK_CONFIG_RESOURCE].update({
        LOOPBACK_IFNAME: format_network_config(network_config)
    })


def format_network_config(config):
    """
    Converts a network_config resource dictionary to the equivalent puppet
    resource definition parameters.
    """
    network_config = copy.copy(config)
    del network_config['ifname']
    return network_config


def format_sriov_config(config):
    """
    Converts a sriov_config resource dictionary to the equivalent puppet
    resource definition parameters.
    """
    sriov_config = copy.copy(config)
    del sriov_config['ifname']
    return sriov_config


def format_fpga_config(config):
    """
    Converts a fpga_config resource dictionary to the equivalent puppet
    resource definition parameters.
    """
    fpga_config = copy.copy(config)
    del fpga_config['ifname']
    return fpga_config


def fill_interface_config_option_operation(options, operation, command):
    """
    Join new command to previous commands on the same operation
    """
    if_op = {IFACE_UP_OP: 'up', IFACE_PRE_UP_OP: 'pre_up', IFACE_POST_UP_OP: 'post_up',
         IFACE_DOWN_OP: 'down', IFACE_PRE_DOWN_OP: 'pre_down', IFACE_POST_DOWN_OP: 'post_down'}
    if not is_syscfg_network():
        if_op[IFACE_PRE_UP_OP] = 'pre-up'
        if_op[IFACE_POST_UP_OP] = 'post-up'
        if_op[IFACE_PRE_DOWN_OP] = 'pre-down'
        if_op[IFACE_POST_DOWN_OP] = 'post-down'

    if operation in if_op.keys():
        if if_op[operation] in options.keys():
            previous_command = options[if_op[operation]]
            options[if_op[operation]] = "{}; {}".format(previous_command,
                                                        command)
        else:
            options[if_op[operation]] = command


def is_syscfg_network():
    """
    Detect if the system is using sysconfig network interface file format
    """
    if not os.path.isdir("/etc/sysconfig/network-scripts/"):
        return False
    return True
