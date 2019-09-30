#
# Copyright (c) 2017-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import collections
import copy
import six

from netaddr import IPAddress
from netaddr import IPNetwork

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import interface
from sysinv.common import utils
from sysinv.conductor import openstack
from sysinv.openstack.common import log

from sysinv.puppet import base
from sysinv.puppet import quoted_str


LOG = log.getLogger(__name__)

PLATFORM_NETWORK_TYPES = [constants.NETWORK_TYPE_PXEBOOT,
                          constants.NETWORK_TYPE_MGMT,
                          constants.NETWORK_TYPE_CLUSTER_HOST,
                          constants.NETWORK_TYPE_OAM,
                          constants.NETWORK_TYPE_IRONIC]

DATA_NETWORK_TYPES = [constants.NETWORK_TYPE_DATA]

DATA_INTERFACE_CLASSES = [constants.INTERFACE_CLASS_DATA]

PCI_NETWORK_TYPES = [constants.NETWORK_TYPE_PCI_SRIOV,
                     constants.NETWORK_TYPE_PCI_PASSTHROUGH]

PCI_INTERFACE_CLASSES = [constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                         constants.INTERFACE_CLASS_PCI_SRIOV]

ACTIVE_STANDBY_AE_MODES = ['active_backup', 'active-backup', 'active_standby']
BALANCED_AE_MODES = ['balanced', 'balanced-xor']
LACP_AE_MODES = ['802.3ad']

DRIVER_MLX_CX3 = 'mlx4_core'
DRIVER_MLX_CX4 = 'mlx5_core'

MELLANOX_DRIVERS = [DRIVER_MLX_CX3,
                    DRIVER_MLX_CX4]

LOOPBACK_IFNAME = 'lo'
LOOPBACK_METHOD = 'loopback'
STATIC_METHOD = 'static'
MANUAL_METHOD = 'manual'
DHCP_METHOD = 'dhcp'

NETWORK_CONFIG_RESOURCE = 'platform::interfaces::network_config'
ROUTE_CONFIG_RESOURCE = 'platform::interfaces::route_config'
SRIOV_CONFIG_RESOURCE = 'platform::interfaces::sriov_config'
ADDRESS_CONFIG_RESOURCE = 'platform::addresses::address_config'


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

        # Generate driver specific configuration
        generate_driver_config(context, config)

        # Update the global context with generated interface context
        self.context.update(context)

        return config

    def _create_interface_context(self, host):
        context = {
            'hostname': host.hostname,
            'personality': host.personality,
            'subfunctions': host.subfunctions,
            'system_uuid': host.isystem_uuid,
            'system_mode': self._get_system().system_mode,
            'ports': self._get_port_interface_id_index(host),
            'interfaces': self._get_interface_name_index(host),
            'interfaces_datanets': self._get_interface_name_datanets(host),
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

    def _find_host_interface(self, host, networktype):
        """
        Search the host interface list looking for an interface with a given
        primary network type.
        """
        for iface in self.dbapi.iinterface_get_by_ihost(host.id):
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

    def _get_interface_name_index(self, host):
        """
        Builds a dictionary of interfaces indexed by interface name.
        """
        return interface._get_interface_name_index(self.dbapi, host)

    def _get_interface_name_datanets(self, host):
        """
        Builds a dictionary of datanets indexed by interface name.
        """
        return interface._get_interface_name_datanets(self.dbapi, host)

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
    if iface['iftype'] != constants.INTERFACE_TYPE_ETHERNET:
        # We only care about configuring specific settings for related ethernet
        # devices.
        return False
    port = get_interface_port(context, iface)
    if port['driver'] in MELLANOX_DRIVERS:
        return True
    return False


def is_a_mellanox_cx3_device(context, iface):
    """
    Determine if the underlying device is a Mellanox CX3 device.
    """
    if iface['iftype'] != constants.INTERFACE_TYPE_ETHERNET:
        # We only care about configuring specific settings for related ethernet
        # devices.
        return False
    port = get_interface_port(context, iface)
    if port['driver'] == DRIVER_MLX_CX3:
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
    assert iface['iftype'] == constants.INTERFACE_TYPE_VLAN
    lower_ifname = iface['uses'][0]
    return context['interfaces'][lower_ifname]


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

    if iface.ifclass == constants.INTERFACE_CLASS_DATA:
        if is_vswitch_type_unaccelerated(context):
            return STATIC_METHOD
        # All data interfaces configured in the kernel because they are not
        # natively supported in vswitch or need to be shared with the kernel
        # because of a platform VLAN should be left as manual config
        return MANUAL_METHOD
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
        elif networktype == constants.NETWORK_TYPE_PXEBOOT:
            # All pxeboot interfaces that exist on non-controller nodes are set
            # to manual as they are not needed/used once the install is done.
            # They exist only in support of the vlan mgmt interface above it.
            return MANUAL_METHOD
        else:
            # All other types get their addresses from the controller
            return DHCP_METHOD


def get_interface_traffic_classifier(context, iface, network_id=None):
    """
    Get the interface traffic classifier command line (if any)
    """
    networktype = find_networktype_by_network_id(context, network_id)
    if (networktype and
            networktype == constants.NETWORK_TYPE_MGMT):
        networkspeed = constants.LINK_SPEED_10G
        ifname = get_interface_os_ifname(context, iface)
        return '/usr/local/bin/cgcs_tc_setup.sh %s %s %s > /dev/null' \
               % (ifname,
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
        config['mtu'] = str(mtu)
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
    if (iface['iftype'] == constants.INTERFACE_TYPE_VLAN):
        os_ifname = get_interface_os_ifname(context, iface)
        return os_ifname.replace('.', '/')
    else:
        return iface['ifname']


def get_duplex_direct_network_config(context, iface, config, sysctl_ifname):
    """
    Disable dad on the specified interface for duplex-direct config
    """
    new_pre_up = "sysctl -wq net.ipv6.conf.%s.accept_dad=0" % sysctl_ifname
    old_pre_up = config['options'].get('pre_up')
    if old_pre_up:
        new_pre_up = "%s ; %s" % (old_pre_up, new_pre_up)
    options = {'pre_up': new_pre_up}
    config['options'].update(options)
    return config


def get_vlan_network_config(context, iface, config):
    """
    Augments a basic config dictionary with the attributes specific to a VLAN
    interface.
    """
    options = {'VLAN': 'yes',
               'pre_up': '/sbin/modprobe -q 8021q'}
    config['options'].update(options)
    return config


def get_bond_interface_options(iface, primary_iface):
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
    else:
        options = 'xmit_hash_policy=%s miimon=100' % tx_hash_policy
        if ae_mode in BALANCED_AE_MODES:
            options = 'mode=balance-xor ' + options
        elif ae_mode in LACP_AE_MODES:
            options = 'mode=802.3ad lacp_rate=fast ' + options
    return options


def get_bond_network_config(context, iface, config, network_id):
    """
    Augments a basic config dictionary with the attributes specific to a bond
    interface.
    """
    options = {'MACADDR': iface['imac'].rstrip()}
    primary_iface = get_primary_bond_interface(context, iface)
    bonding_options = get_bond_interface_options(iface, primary_iface)
    if bonding_options:
        options['BONDING_OPTS'] = bonding_options
        options['up'] = 'sleep 10'
        networktype = find_networktype_by_network_id(context, network_id)
        if (networktype and networktype in [constants.NETWORK_TYPE_MGMT,
                                            constants.NETWORK_TYPE_CLUSTER_HOST]):
            options['pre_up'] = "/sbin/modprobe bonding; echo +%s > /sys/class/net/bonding_masters" % (
                iface['ifname'])
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
    options['LINKDELAY'] = '20'
    if is_bridged_interface(context, iface):
        options['BRIDGE'] = get_bridge_interface_name(context, iface)
    elif is_slave_interface(context, iface):
        if not is_data_interface(context, iface):
            # Data interfaces that require a network configuration are not
            # candidates for bonding.  They exist because their DPDK drivers
            # rely on the Linux device driver to setup some or all functions
            # on the device (e.g., the Mellanox DPDK driver relies on the
            # Linux driver to set the proper MTU value).
            options['SLAVE'] = 'yes'
            options['MASTER'] = get_master_interface(context, iface)
            options['PROMISC'] = 'yes'
    elif interface_class == constants.INTERFACE_CLASS_PCI_SRIOV:
        if not is_a_mellanox_cx3_device(context, iface):
            # CX3 device can only use kernel module options to enable vfs
            # others share the same pci-sriov sysfs enabling mechanism
            sriovfs_path = ("/sys/class/net/%s/device/sriov_numvfs" %
                            get_interface_port_name(context, iface))
            options['pre_up'] = "echo 0 > %s; echo %s > %s" % (
                sriovfs_path, iface['sriov_numvfs'], sriovfs_path)
    elif interface_class == constants.INTERFACE_CLASS_PCI_PASSTHROUGH:
        sriovfs_path = ("/sys/class/net/%s/device/sriov_numvfs" %
                        get_interface_port_name(context, iface))
        options['pre_up'] = "if [ -f  %s ]; then echo 0 > %s; fi" % (
            sriovfs_path, sriovfs_path)

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


def get_sriov_config(context, iface):
    vf_driver = iface['sriov_vf_driver']
    port = get_interface_port(context, iface)
    vf_addr_list = port['sriov_vfs_pci_address']

    if not vf_addr_list:
        return {}

    if vf_driver:
        if "vfio" in vf_driver:
            vf_driver = "vfio-pci"
        elif "netdevice" in vf_driver:
            if port['sriov_vf_driver'] is not None:
                vf_driver = port['sriov_vf_driver']
            else:
                # Should not happen, but in this case the vf driver
                # will be determined by the kernel.  That is,
                # no explicit bind will be performed by Puppet.
                vf_driver = None

    # Format the vf addresses as quoted strings in order to prevent
    # puppet from treating the address as a time/date value
    vf_addrs = [quoted_str(addr.strip()) for addr in vf_addr_list.split(",")]

    config = {
        'ifname': iface['ifname'],
        'vf_driver': vf_driver,
        'vf_addrs': vf_addrs
    }
    return config


def get_common_network_config(context, iface, config, network_id=None):
    """
    Augments a basic config dictionary with the attributes specific to an upper
    layer interface (i.e., an interface that is used to terminate IP traffic).
    """
    LOG.debug("get_common_network_config %s %s network_id=%s" %
              (iface.ifname, iface.networktypelist, network_id))
    traffic_classifier = get_interface_traffic_classifier(context, iface,
                                                          network_id)
    if traffic_classifier:
        config['options']['post_up'] = traffic_classifier

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
            config['gateway'] = gateway
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
                                                      dd_ifname)
    return config


def get_interface_network_config(context, iface, network_id=None):
    """
    Builds a network_config resource dictionary for a given interface
    """
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
        options = {'SCOPE': 'scope host'}
        config['options'].update(options)

    # Add type specific options
    if iface['iftype'] == constants.INTERFACE_TYPE_VLAN:
        config = get_vlan_network_config(context, iface, config)
    elif iface['iftype'] == constants.INTERFACE_TYPE_AE:
        config = get_bond_network_config(context, iface, config,
                                         network_id)
    else:
        config = get_ethernet_network_config(context, iface, config)

    # Add final options
    config = get_final_network_config(context, iface, config, network_id)

    return config


def generate_network_config(context, config, iface):
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
    config[NETWORK_CONFIG_RESOURCE].update({
        net_config['ifname']: format_network_config(net_config)
    })

    for net_type in iface.networktypelist:
        net_id = find_network_id_by_networktype(context, net_type)
        net_config = get_interface_network_config(context, iface, net_id)
        config[NETWORK_CONFIG_RESOURCE].update({
            net_config['ifname']: format_network_config(net_config)
        })

    # Add complementary puppet resource definitions (if needed)
    for route in get_interface_routes(context, iface):
        route_config = get_route_config(route, ifname)
        config[ROUTE_CONFIG_RESOURCE].update({
            route_config['name']: route_config
        })

    interface_class = iface['ifclass']
    if interface_class == constants.INTERFACE_CLASS_PCI_SRIOV:
        sriov_config = get_sriov_config(context, iface)
        if sriov_config:
            config[SRIOV_CONFIG_RESOURCE].update({
                sriov_config['ifname']: format_sriov_config(sriov_config)
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


def interface_sort_key(iface):
    """
    Sort interfaces by interface type placing ethernet interfaces ahead of
    aggregated ethernet interfaces, and vlan interfaces last.
    """
    if iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET:
        return 0, iface['ifname']
    elif iface['iftype'] == constants.INTERFACE_TYPE_AE:
        return 1, iface['ifname']
    else:  # if iface['iftype'] == constants.INTERFACE_TYPE_VLAN:
        return 2, iface['ifname']


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


def build_mlx4_num_vfs_options(context):
    """
    Generate the manifest fragment that will create mlx4_core
    modprobe conf file in which VF is set and reload the mlx4_core
    kernel module
    """
    ifaces = find_sriov_interfaces_by_driver(context, DRIVER_MLX_CX3)
    if not ifaces:
        return ""

    num_vfs_options = ""
    for iface in ifaces:
        port = get_interface_port(context, iface)
        # For CX3 SR-IOV configuration, we only configure VFs on the 1st port
        # Since two ports share the same PCI address, if the first port has
        # been configured, we need to skip the second port
        if port['pciaddr'] in num_vfs_options:
            continue

        if not num_vfs_options:
            num_vfs_options = "%s-%d;0;0" % (port['pciaddr'],
                                             iface['sriov_numvfs'])
        else:
            num_vfs_options += ",%s-%d;0;0" % (port['pciaddr'],
                                               iface['sriov_numvfs'])

    return num_vfs_options


def generate_mlx4_core_options(context, config):
    """
    Generate the config options that will create mlx4_core modprobe
    conf file in which VF is set and execute mlx4_core_conf.sh in which
    /var/run/.mlx4_cx3_reboot_required is created to indicate a reboot
    is needed for goenable and /etc/modprobe.d/mlx4_sriov.conf is injected
    into initramfs, this way mlx4_core options can be applied after reboot
    """
    num_vfs_options = build_mlx4_num_vfs_options(context)
    if not num_vfs_options:
        return

    mlx4_core_options = "port_type_array=2,2 num_vfs=%s" % num_vfs_options
    config['platform::networking::mlx4_core_options'] = mlx4_core_options


def generate_driver_config(context, config):
    """
    Generate custom configuration for driver specific parameters.
    """
    if is_worker_subfunction(context):
        generate_mlx4_core_options(context, config)


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
