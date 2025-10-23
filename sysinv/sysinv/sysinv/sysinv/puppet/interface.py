#
# Copyright (c) 2017-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import collections
import copy
import re
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
                          constants.NETWORK_TYPE_STORAGE,
                          constants.NETWORK_TYPE_ADMIN]

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
RATE_LIMIT_CONFIG_RESOURCE = 'platform::network::interfaces::rate_limit::rate_limit_config'
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
            RATE_LIMIT_CONFIG_RESOURCE: {},
            DATA_IFACE_LIST_RESOURCE: [],
        }

        # Setup the loopback interface first
        generate_loopback_config(config)

        # Generate the actual interface config resources
        generate_interface_configs(context, config, self.dbapi)

        # Generate the actual interface config resources
        generate_address_configs(context, config, self.dbapi)

        # Generate data iface list configuration
        generate_data_iface_list_config(context, config)

        # Generate data for iface rate limit configuration
        generate_data_iface_rate_limit(context, config, self.dbapi)

        # Update the global context with generated interface context
        self.context.update(context)

        return config

    def _create_interface_context(self, host):
        host_interfaces = self.dbapi.iinterface_get_by_ihost(host.uuid)
        networks = self._get_network_type_index()
        address_pools = self._get_address_pool_index()
        network_address_pools = self._get_network_addresspool_index()
        addresses = self._get_address_interface_name_index(host)
        context = {
            'hostname': host.hostname,
            'personality': host.personality,
            'subfunctions': host.subfunctions,
            'system_uuid': host.isystem_uuid,
            'system_mode': self._get_system().system_mode,
            'ports': self._get_port_interface_id_index(host),
            'interfaces': self._get_interface_name_index(host_interfaces),
            'interface_networks': self._get_interface_network_index(
                host_interfaces, addresses, networks, address_pools, network_address_pools),
            'interfaces_datanets': self._get_interface_name_datanets(
                host.hostname, host_interfaces),
            'devices': self._get_port_pciaddr_index(host),
            'addresses': addresses,
            'routes': self._get_routes_interface_name_index(host),
            'networks': networks,
            'address_pools': address_pools,
            'floatingips': self._get_floating_ip_index(networks, address_pools,
                                                       network_address_pools),
            'gateways': self._get_default_gateway_index(host, addresses, address_pools,
                                                        network_address_pools),
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

    def _get_interface_network_index(self, host_interfaces, address_index, network_type_index,
                                     addrpool_index, network_addrpool_index):
        """
        Builds a dictionary that associates interfaces with networks and addresses.
        Format:
        {
            <interface_name>: {
                <network_id or None>: {
                    'network': <network_object or None>,
                    'addresses': [ <address 1>, <address 2>, ... ]
                }
            }
        }
        """

        network_id_index = {}
        for network in network_type_index.values():
            network_id_index[network.id] = network

        interface_index = {}
        for iface in host_interfaces:
            interface_dict = {None: {'network': None, 'addresses': []}}
            for networktype in iface.networktypelist:
                network = network_type_index[networktype]
                interface_dict[network.id] = {'network': network, 'addresses': []}
            interface_index[iface.ifname] = interface_dict

        for address_list in address_index.values():
            for address in address_list:
                addrpool = addrpool_index.get(address.pool_uuid, None)
                network_addrpool = network_addrpool_index.get(address.pool_uuid, None)

                network = None
                if addrpool and network_addrpool:
                    network = network_id_index[network_addrpool.network_id]

                network_id = network.id if network else None

                interface_entry = interface_index.get(address.ifname, None)
                if not interface_entry:
                    continue

                network_entry = interface_entry.get(network_id, None)

                if not network_entry:
                    network_entry = {
                        'network': network,
                        'addresses': []
                    }
                    interface_entry[network_id] = network_entry

                network_entry['addresses'].append(address)

        return interface_index

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

    def _get_address_pool_index(self):
        addrpool_index = {}
        addrpools = self.dbapi.address_pools_get_all()
        for addrpool in addrpools:
            addrpool_index[addrpool.uuid] = addrpool
        return addrpool_index

    def _get_network_addresspool_index(self):
        network_addrpool_index = {}
        network_addrpools = self.dbapi.network_addrpool_get_all()
        for network_addrpool in network_addrpools:
            network_addrpool_index[network_addrpool.address_pool_uuid] = network_addrpool
        return network_addrpool_index

    def _get_floating_ip_index(self, networks, address_pools, network_address_pools):
        """
        Builds a dictionary of floating ip addresses indexed by network type.
        """

        networktypes = [
            constants.NETWORK_TYPE_MGMT,
            constants.NETWORK_TYPE_PXEBOOT,
            constants.NETWORK_TYPE_CLUSTER_HOST,
            constants.NETWORK_TYPE_IRONIC,
            constants.NETWORK_TYPE_STORAGE,
            constants.NETWORK_TYPE_ADMIN
        ]

        system = self._get_system()
        if system.system_mode != constants.SYSTEM_MODE_SIMPLEX:
            networktypes.append(constants.NETWORK_TYPE_OAM)

        network_index = {}
        for network in networks.values():
            if network.type in networktypes:
                network_index[network.id] = network

        floating_ips = collections.defaultdict(list)
        for network_address_pool in network_address_pools.values():
            network = network_index.get(network_address_pool.network_id, None)
            if not network:
                continue
            address_pool = address_pools[network_address_pool.address_pool_uuid]
            if not address_pool.floating_address_id:
                continue
            try:
                address = self.dbapi.address_get_by_id(address_pool.floating_address_id)
                floating_ips[network.type].append(address)
            except exception.AddressNotFoundById:
                pass

        return floating_ips

    GATEWAY_PRECEDENCE_LIST = [constants.NETWORK_TYPE_OAM,
                               constants.NETWORK_TYPE_MGMT,
                               constants.NETWORK_TYPE_ADMIN]

    def _get_addrpool_gateway_field(self, host_personality, network_type):
        if host_personality in [constants.STORAGE, constants.WORKER] and \
                network_type == constants.NETWORK_TYPE_MGMT:
            return 'floating_address'
        return 'gateway_address'

    def _get_default_gateway_index(self, host, addresses, address_pools, network_address_pools):
        '''
        Gets a dictionary containing the default gateway addresses indexed by the corresponding
        address pools. There can be only one default gateway per address family, so if there are
        multiple address pools with gateways, the default one will follow the precedence order
        OAM -> Management -> Admin. Only address pools which have an address assigned to an
        interface in the current host are considered.
        '''

        assigned_addrpools = set()
        for address_list in addresses.values():
            for address in address_list:
                if address.forihostid == host.id and address.pool_uuid:
                    assigned_addrpools.add(address.pool_uuid)

        nw_addrpool_index = {}
        for nw_addrpool in network_address_pools.values():
            if nw_addrpool.network_type not in self.GATEWAY_PRECEDENCE_LIST:
                continue
            if nw_addrpool.address_pool_uuid not in assigned_addrpools:
                continue
            addrpools = nw_addrpool_index.setdefault(nw_addrpool.network_type, [])
            addrpools.append(address_pools[nw_addrpool.address_pool_uuid])

        gateway_index = {}
        for nw_type in self.GATEWAY_PRECEDENCE_LIST:
            addrpools = nw_addrpool_index.get(nw_type, None)
            if not addrpools:
                continue
            field = self._get_addrpool_gateway_field(host.personality, nw_type)
            for addrpool in addrpools:
                gateway = getattr(addrpool, field)
                if gateway:
                    gateway_index[addrpool.uuid] = gateway
            if gateway_index:
                break

        return gateway_index

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


def get_vlan_os_ifname(iface):
    """
    Generate the interface name used in the linux kernel for the given VLAN
    interface.
    """
    if iface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM:
        return "vlan" + str(iface['vlan_id'])
    # If ifname is in the format vlanNNN or xxx.NNN, replace the dot by '#' to
    # avoid problems when added to /etc/network/interfaces.
    ifname = iface['ifname']
    if re.search("^vlan[0-9]+$", ifname):
        return "vlan#%s" % ifname[4:]
    match = re.search("\.[0-9]+$", ifname)
    if match:
        return ifname[:match.start()] + '#' + ifname[match.start() + 1:]
    return ifname


def get_interface_os_ifname(context, iface):
    """
    Determine the interface name used in the linux kernel for the given
    interface. Ethernet interfaces uses the original linux device name while
    AE devices can use the user-defined named. VLAN interfaces use ifname as
    Linux interface name.
    """
    if '_os_ifname' in iface:  # check cached result
        return iface['_os_ifname']
    else:
        os_ifname = iface['ifname']
        if iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET:
            os_ifname = get_interface_port_name(context, iface)
        elif iface['iftype'] == constants.INTERFACE_TYPE_VLAN:
            os_ifname = get_vlan_os_ifname(iface)
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


def get_gateway_address(context, address):
    """
    Gets the corresponding gateway for the provided address
    """
    return context['gateways'].get(address.pool_uuid, None)


def get_interface_address_method(context, iface, network=None, address=None):
    networktype = network.type if network else None

    has_static_addr = False
    if address:
        if address.family == constants.IPV4_FAMILY:
            if iface.ipv4_mode in {constants.IPV4_STATIC, constants.IPV4_POOL}:
                has_static_addr = True
        elif address.family == constants.IPV6_FAMILY:
            if iface.ipv6_mode in {constants.IPV6_STATIC, constants.IPV6_POOL}:
                has_static_addr = True

    if iface.ifclass == constants.INTERFACE_CLASS_DATA:
        if has_static_addr:
            return STATIC_METHOD
        # All data interfaces configured in the kernel because they are not
        # natively supported in vswitch or need to be shared with the kernel
        # because of a platform VLAN should be left as manual config
        return MANUAL_METHOD
    elif (iface.ifclass == constants.INTERFACE_CLASS_PLATFORM and networktype is None):
        if has_static_addr:
            return STATIC_METHOD
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
        elif networktype == constants.NETWORK_TYPE_MGMT:
            return STATIC_METHOD
        elif networktype == constants.NETWORK_TYPE_CLUSTER_HOST:
            return STATIC_METHOD
        elif networktype == constants.NETWORK_TYPE_STORAGE:
            return STATIC_METHOD
        elif networktype == constants.NETWORK_TYPE_ADMIN:
            return STATIC_METHOD
        elif networktype == constants.NETWORK_TYPE_PXEBOOT:
            if context['personality'] in [constants.WORKER, constants.STORAGE]:
                return DHCP_METHOD
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
        config['options']['mtu'] = str(mtu)
    return config


def is_disable_dad_required(iface, network=None):
    """
    Disable DAD command is included in the base interface config, only for interfaces associated
    with management and cluster-host networks.
    """

    if network:
        return False
    networks = [constants.NETWORK_TYPE_MGMT, constants.NETWORK_TYPE_CLUSTER_HOST]
    for networktype in iface.networktypelist:
        if networktype in networks:
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


def get_duplex_direct_network_config(context, iface, config, network):
    """
    Disable dad on the specified interface for duplex-direct config
    """
    if iface['iftype'] == constants.INTERFACE_TYPE_AE:
        command = ("/sbin/modprobe bonding; "
                "grep %s /sys/class/net/bonding_masters || "
                "echo +%s > /sys/class/net/bonding_masters" % (
                    iface['ifname'], iface['ifname']))
        fill_interface_config_option_operation(config['options'], IFACE_PRE_UP_OP, command)

    if iface['iftype'] == constants.INTERFACE_TYPE_VLAN:
        add_vlan_interface_creation_command(context, iface, config['options'])

    sysctl_ifname = get_interface_sysctl_ifname(context, iface)
    new_pre_up = "sysctl -wq net.ipv6.conf.%s.accept_dad=0" % sysctl_ifname
    fill_interface_config_option_operation(config['options'], IFACE_PRE_UP_OP, new_pre_up)
    return config


def get_vlan_network_config(context, iface, config):
    """
    Augments a basic config dictionary with the attributes specific to a VLAN
    interface.
    """
    lower_os_ifname = get_lower_interface_os_ifname(context, iface)
    options = {'vlan-raw-device': lower_os_ifname}
    fill_interface_config_option_operation(options, IFACE_PRE_UP_OP,
                                           '/sbin/modprobe -q 8021q')
    if iface['ifclass'] != constants.INTERFACE_CLASS_PLATFORM:
        add_vlan_interface_creation_command(context, iface, options)
    config['options'].update(options)
    return config


def add_vlan_interface_creation_command(context, iface, options):
    if hasattr(iface, '_has_create_cmd'):
        return
    iface['_has_create_cmd'] = True
    os_ifname = get_interface_os_ifname(context, iface)
    lower_os_ifname = get_lower_interface_os_ifname(context, iface)
    fill_interface_config_option_operation(options, IFACE_PRE_UP_OP,
        'ip link add link %s name %s type vlan id %d' %
        (lower_os_ifname, os_ifname, iface['vlan_id']))
    fill_interface_config_option_operation(options, IFACE_POST_DOWN_OP,
        'ip link del %s' % (os_ifname))


def get_bond_interface_options_ifupdown(context, iface, primary_iface):
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
        port_name = get_interface_devices(context, primary_iface)
        if len(port_name):
            options['bond-primary'] = port_name[0]
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
        os_ifname = get_interface_devices(context, iface)
        for interface_name in os_ifname:
            bond_slaves += (interface_name + ' ')
        options['bond-slaves'] = bond_slaves
    return options


def get_bond_network_config(context, iface, config):
    """
    Augments a basic config dictionary with the attributes specific to a bond
    interface.
    """
    primary_iface = get_primary_bond_interface(context, iface)
    options = dict()
    bonding_options = None
    iface_mac = iface['imac'].rstrip()

    options['hwaddress'] = iface_mac
    bonding_options = get_bond_interface_options_ifupdown(context, iface,
                                                          primary_iface)
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

    if is_bridged_interface(context, iface):
        pass
    elif is_slave_interface(context, iface):
        if not is_data_interface(context, iface):
            # Data interfaces that require a network configuration are not
            # candidates for bonding.  They exist because their DPDK drivers
            # rely on the Linux device driver to setup some or all functions
            # on the device (e.g., the Mellanox DPDK driver relies on the
            # Linux driver to set the proper MTU value).
            master = get_master_interface(context, iface)
            options['bond-master'] = master
            osname = get_interface_os_ifname(context, iface)
            command = '/usr/sbin/ip link set dev {} promisc on'.format(osname)
            fill_interface_config_option_operation(options, IFACE_PRE_UP_OP, command)
            # the allow-* is a separated stanza in ifupdown, but without
            # support in puppet-network module, this stanza is needed to
            # make ifup to run the slave's pre-up commands. It will be
            # adjusted during parsing in apply_network_config.py
            options['allow-{}'.format(master)] = osname
            if interface_class == constants.INTERFACE_CLASS_PCI_SRIOV:
                if iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET:
                    sriovfs_path = ("/sys/class/net/%s/device/sriov_numvfs" %
                            get_interface_port_name(context, iface))
                command = "echo 0 > %s; echo %s > %s" % (sriovfs_path, iface['sriov_numvfs'],
                                                        sriovfs_path)
                iface_op = get_device_sriov_setup_op(context, iface)
                fill_interface_config_option_operation(options, iface_op, command)
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
    Builds a basic route config string with all of the fields required to
    be used by the networking.service
    """
    options = 'metric ' + str(route['metric'])
    netmask = IPNetwork(route['network'] + "/" + str(route['prefix'])).netmask
    if route['network'] == '0.0.0.0' or route['network'] == '::':
        route['network'] = 'default'
    config = f"{route['network']} {netmask} {route['gateway']} {ifname} {options}\n"
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


def get_common_network_config(context, iface, config, network=None, address=None):
    """
    Augments a basic config dictionary with the attributes specific to an upper
    layer interface (i.e., an interface that is used to terminate IP traffic).
    """

    os_ifname = get_interface_os_ifname(context, iface)
    if os_ifname == config['ifname']:
        # post-up scripts do not work for aliases.
        traffic_classifier = get_interface_traffic_classifier(context, iface)
        if traffic_classifier:
            fill_interface_config_option_operation(config['options'], IFACE_POST_UP_OP,
                                                   traffic_classifier)

    method = get_interface_address_method(context, iface, network, address)
    if method == STATIC_METHOD:
        if address:
            _set_address_netmask(address)

            config['ipaddress'] = address['address']
            config['netmask'] = address['netmask']

            gateway = get_gateway_address(context, address)
            if gateway:
                config['options']['gateway'] = gateway
    return config


def get_final_network_config(context, iface, config, network=None):
    """
    Augments a basic config dictionary with the attribute that must be
    appended to an attribute that is already configured (e.g. pre_up)
    """
    # add duplex_direct specific network config
    if context['system_mode'] == constants.SYSTEM_MODE_DUPLEX_DIRECT:
        if is_disable_dad_required(iface, network):
            config = get_duplex_direct_network_config(context, iface, config, network)
    return config


def get_interface_network_config(context, iface, network=None, address=None):
    """
    Builds a network_config resource dictionary for a given interface
    """

    method = get_interface_address_method(context, iface, network, address)

    # if and address is present but the address mode is not static, there's
    # no need to generate a labeled config for the interface
    if address is not None and method == MANUAL_METHOD:
        return {}

    os_ifname = get_interface_os_ifname(context, iface)
    family = get_address_family(address)

    # for now label all interfaces that have network_id, later we will
    # set the definitive values
    if network or address:
        net_num = network.id if network else 0
        addr_num = address.id if address else 0
        if network and network.type == constants.NETWORK_TYPE_PXEBOOT:
            # the name format for pxeboot does not need to contain the address id as
            # this network does not have dual-stack support and MTCE uses the format
            # below to identify the pxeboot address
            ifname = "%s:%d" % (os_ifname, net_num)
        else:
            ifname = "%s:%d-%d" % (os_ifname, net_num, addr_num)
    else:
        ifname = os_ifname

    mtu = get_interface_mtu(context, iface)
    config = get_basic_network_config(
        ifname, method=method, family=family, mtu=mtu)

    # Add options common to all top level interfaces
    config = get_common_network_config(context, iface, config, network, address)

    # ensure addresses have host scope when configured against the loopback
    if os_ifname == LOOPBACK_IFNAME:
        options = {'scope': 'host'}
        config['options'].update(options)

    # Add type specific options
    if iface['iftype'] == constants.INTERFACE_TYPE_VLAN:
        config = get_vlan_network_config(context, iface, config)
    elif iface['iftype'] == constants.INTERFACE_TYPE_AE:
        config = get_bond_network_config(context, iface, config)
    else:
        config = get_ethernet_network_config(context, iface, config)

    # Add final options
    config = get_final_network_config(context, iface, config, network)

    if iface['iftype'] == constants.INTERFACE_TYPE_VLAN:
        # When configuring a static IPv6 interface, CentOS' ifup tool uses 'ip link'
        # command to set both IPv4 and IPv6 MTU.
        # Debian's ifup tool instead uses sysctl to set only the IPv6 MTU. But this
        # value gets reset to the underlying device's MTU soon after ifup set sets the
        # interface state to up. So we need to set the MTU again during post-up.
        # Using 'ip link' command here instead of sysctl, will set both IPv4 and IPv6
        # MTU like in CentOS.
        set_mtu = '/usr/sbin/ip link set dev {} mtu {}'.format(os_ifname, mtu)
        fill_interface_config_option_operation(config['options'], IFACE_POST_UP_OP, set_mtu)

    # disable ipv6 autoconfig
    interface_op = IFACE_POST_UP_OP
    if is_slave_interface(context, iface):
        # ifupdown's ifup only runs pre-up for slave interfaces
        interface_op = IFACE_PRE_UP_OP

    autoconf_off = 'echo 0 > /proc/sys/net/ipv6/conf/{}/autoconf'.format(os_ifname)
    fill_interface_config_option_operation(config['options'], interface_op, autoconf_off)
    accept_ra_off = 'echo 0 > /proc/sys/net/ipv6/conf/{}/accept_ra'.format(os_ifname)
    fill_interface_config_option_operation(config['options'], interface_op, accept_ra_off)
    accept_redir_off = 'echo 0 > /proc/sys/net/ipv6/conf/{}/accept_redirects'.format(os_ifname)
    fill_interface_config_option_operation(config['options'], interface_op, accept_redir_off)
    keep_addr_on_down_on = 'echo 1 > /proc/sys/net/ipv6/conf/{}/keep_addr_on_down'.format(os_ifname)
    fill_interface_config_option_operation(config['options'], interface_op, keep_addr_on_down_on)

    network_type = network.type if network else None

    # add the description field with the database ifname and networktype if available
    config['options']['stx-description'] = f"ifname:{iface['ifname']},net:{network_type}"

    return config


def _append_interface_config(iface_configs, iface_config):
    if len(iface_config) > 0:
        iface_configs.append(iface_config)


def get_interface_network_configs(context, iface, network=None):
    """
    Builds a list of network_config resource dictionaries for a given interface,
    each corresponding to an associated address, plus the base unlabeled config
    """

    if iface['iftype'] == constants.INTERFACE_TYPE_VF:
        # Only the parent SR-IOV interface needs a network config
        return []

    iface_configs = []

    network_id = network.id if network else None
    network_dict = context['interface_networks'][iface.ifname][network_id]

    if network:
        if len(network_dict['addresses']) == 0:
            iface_config = get_interface_network_config(context, iface, network)
            _append_interface_config(iface_configs, iface_config)
    else:
        # Most basic interface config, no network no address
        iface_config = get_interface_network_config(context, iface)
        _append_interface_config(iface_configs, iface_config)

    for address in network_dict['addresses']:
        iface_config = get_interface_network_config(context, iface, network, address)
        _append_interface_config(iface_configs, iface_config)

    return iface_configs


def get_address_family(address):
    if address and IPAddress(address['address']).version == 6:
        return 'inet6'
    return 'inet'


def generate_network_config(context, hiera_config, iface):
    """
    Produce the puppet network config resources necessary to configure the
    given interface.  In some cases this will emit a single network_config
    resource, while in other cases it will emit multiple resources to create a
    bridge, or to add additional route resources.
    """

    os_ifname = get_interface_os_ifname(context, iface)

    # Setup the default device configuration for the interface.  This will be
    # overridden if there is a specific network type configuration, otherwise
    # it will act as the parent device for the aliases
    networks = context['interface_networks'][iface.ifname]
    for network_dict in networks.values():
        net_configs = get_interface_network_configs(context, iface, network_dict['network'])
        for net_config in net_configs:
            hiera_config[NETWORK_CONFIG_RESOURCE][net_config['ifname']] = \
                    format_network_config(net_config)

    # Add complementary puppet resource definitions (if needed)

    # the puppet-network plugin is very inneficient when the number of routes is in the 1000s,
    # generate the networking.service routes file content directly in the final format
    route_config = "\n"
    for route in get_interface_routes(context, iface):
        route_data = get_route_config(route, os_ifname)
        route_config = route_config + route_data
    hiera_config[ROUTE_CONFIG_RESOURCE] = f"{route_config}"

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


def find_network_id_by_networktype(context, networktype):
    network = context['networks'].get(networktype, None)
    if network:
        return network.id
    return None


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


def generate_interface_configs(context, config, db_api):
    """
    Generate the puppet resource for each of the interface and route config
    resources.
    """
    to_config_iface = list()
    for iface in sorted(context['interfaces'].values(),
                        key=interface_sort_key):
        if needs_interface_config(context, iface):
            generate_network_config(context, config, iface)
            to_config_iface.append(iface)

    generate_unassigned_pxeboot_intf_config(context, config, db_api,
                                            to_config_iface)

    # all interfaces were generated with label. Now run a logic to adjust
    # the interfaces that actually require labeling
    process_interface_labels(config, context)


def process_interface_labels(config, context):
    """
    Adjust interface labeling according to ifupdown package rules and StarlingX
    requirements
    """
    # This rules are a result of using Debian's ifupdown package
    #
    # Rules for label adjustment:
    # 1) if the interface have just one label:
    #   - keep the label as it can receive dual-stack configuration later
    #   - if part of pxeboot network, move the content of label to interface,
    #     keeping compatibility with MTCE operation (pxeboot is single-stack only)
    # 2) if the interface have more that one label
    #   - if the family is inet
    #       - just keep the labeling
    #       - DHCPv4 can use a labeled interface (pxeboot for now is only IPv4),
    #         that was not the case when using CentOS
    #   - if the family is inet6
    #       - interface needs to contain the static address that will be used as
    #         source address (non-deprecated)
    #           - in inet6 labeled interfaces mark the static address as deprecated
    #           - a post-up operation will be added to remove this flag in one
    #             of the interfaces
    #               - the selected label interface will follow the precedence
    #                   - oam
    #                   - mgmt
    #                   - admin
    #                   - cluster-host
    #                   - pxeboot
    #                   - storage
    #               - if a vlan is shared by mgmt and another network,
    #                 the mgmt interface will not have the address deprecated
    #       - DHCPv6 cannot use label (pxeboot for now is only IPv4, so we don't
    #         have a use case for now for platform interfaces), move the label
    #         to interface

    label_map = dict()
    for net_cfg_key in config[NETWORK_CONFIG_RESOURCE].keys():
        base_interface = net_cfg_key.split(':')[0]
        if base_interface not in label_map.keys():
            label_map.update({base_interface: dict()})
        if ":" in net_cfg_key:
            label_map[base_interface].update({
                net_cfg_key: config[NETWORK_CONFIG_RESOURCE][net_cfg_key]})

    for intf in label_map.keys():
        if intf == 'lo':
            # no need to change the loopback
            continue

        if not label_map[intf]:
            continue

        # process main ipv6 address
        for label in label_map[intf].keys():
            intf_data = label_map[intf][label]
            if (intf_data['family'] == 'inet6') and (intf_data['method'] == 'static'):
                name_net = intf_data['options']['stx-description'].split(',')
                ifname = (name_net[0].split(":"))[1]
                net = (name_net[1].split(":"))[1]
                networktypelist = context['interfaces'][ifname].networktypelist
                undeprecate = "ip -6 addr replace" + \
                                f" {intf_data['ipaddress']}/{intf_data['netmask']}" + \
                                f" dev {intf} preferred_lft forever"
                if ('vlan' in label and len(networktypelist) > 1
                        and constants.NETWORK_TYPE_MGMT in networktypelist):
                    if net == constants.NETWORK_TYPE_MGMT:
                        fill_interface_config_option_operation(intf_data['options'],
                                                            IFACE_POST_UP_OP, undeprecate)
                        break
                    else:
                        continue
                elif constants.NETWORK_TYPE_OAM in networktypelist:
                    fill_interface_config_option_operation(intf_data['options'],
                                                            IFACE_POST_UP_OP, undeprecate)
                    break
                elif constants.NETWORK_TYPE_MGMT in networktypelist:
                    fill_interface_config_option_operation(intf_data['options'],
                                                            IFACE_POST_UP_OP, undeprecate)
                    break
                elif constants.NETWORK_TYPE_ADMIN in networktypelist:
                    fill_interface_config_option_operation(intf_data['options'],
                                                            IFACE_POST_UP_OP, undeprecate)
                    break
                elif constants.NETWORK_TYPE_CLUSTER_HOST in networktypelist:
                    fill_interface_config_option_operation(intf_data['options'],
                                                            IFACE_POST_UP_OP, undeprecate)
                    break
                elif constants.NETWORK_TYPE_PXEBOOT in networktypelist:
                    fill_interface_config_option_operation(intf_data['options'],
                                                            IFACE_POST_UP_OP, undeprecate)
                    break
                elif constants.NETWORK_TYPE_STORAGE in networktypelist:
                    fill_interface_config_option_operation(intf_data['options'],
                                                            IFACE_POST_UP_OP, undeprecate)
                    break

        if len(label_map[intf]) == 1:
            # process DHCPv6, needs to be in the base interface, limitation in ifupdown to handle
            # this case (for now not used in StarlingX).
            for label in label_map[intf].keys():
                intf_data = label_map[intf][label]
                if (intf_data['family'] == 'inet6') and (intf_data['method'] == 'dhcp'):
                    merge_interface_operations(config, intf, label)
                    config[NETWORK_CONFIG_RESOURCE][intf] = config[NETWORK_CONFIG_RESOURCE][label]
                    del config[NETWORK_CONFIG_RESOURCE][label]
                    break


def merge_interface_operations(config, intf, label):
    """
    Collect the operations in the labeled interface and merge with the existing operations
    in the base interface, update the result in the labeled interface config
    """
    label_intf = config[NETWORK_CONFIG_RESOURCE][label]
    base_intf = config[NETWORK_CONFIG_RESOURCE][intf]
    # merge operations from base and label
    for oper in [IFACE_PRE_UP_OP, IFACE_UP_OP, IFACE_POST_UP_OP,
                    IFACE_PRE_DOWN_OP, IFACE_DOWN_OP, IFACE_POST_DOWN_OP]:
        opername = get_intf_op_name(oper)

        if opername in base_intf['options']:
            base_oper = base_intf['options'][opername].split("; ")
            if opername in label_intf['options']:
                label_oper = label_intf['options'][opername].split("; ")
                for cmd in base_oper:
                    if cmd not in label_oper:
                        fill_interface_config_option_operation(label_intf['options'], oper, cmd)
            else:
                for cmd in base_oper:
                    fill_interface_config_option_operation(label_intf['options'], oper, cmd)


def generate_unassigned_pxeboot_intf_config(context, config, db_api,
                                            to_config_iface):

    """
    If the pxeboot network isn't explicitly assigned to an interface, it is necessary
    to add the network config in the same interface used by the management network
    """
    platform_untag_networks = list()
    mgmt_intf = None
    for iface in to_config_iface:
        # get list of platform networks are untagged (no vlan)
        if (iface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM
                and (iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET
                    or iface['iftype'] == constants.INTERFACE_TYPE_AE)) \
                and iface['iftype'] != constants.INTERFACE_TYPE_VIRTUAL \
                and iface['iftype'] != constants.INTERFACE_TYPE_VF:
            try:
                intf_networks = db_api.interface_network_get_by_interface(iface['id'])
                for intf_net in intf_networks:
                    network = db_api.network_get(intf_net.network_uuid)
                    if network:
                        platform_untag_networks.append(network)
                    if intf_net['network_type'] == constants.NETWORK_TYPE_MGMT:
                        mgmt_intf = iface
            except Exception as ex:
                LOG.info(f"DB query failed with {ex}")
                LOG.exception(ex)

    # assigning pxeboot network to an interface is not mandatory if the management
    # interface is untagged. If that is the case prepare a configuration for pxeboot
    # in the same interface used by the management interface.
    is_pxeboot_present = [network.type for network in platform_untag_networks
                            if network.type == constants.NETWORK_TYPE_PXEBOOT]
    is_mgmt_present = [network.type for network in platform_untag_networks
                        if network.type == constants.NETWORK_TYPE_MGMT]
    if not is_pxeboot_present and is_mgmt_present:
        if mgmt_intf:
            LOG.info(f"add pxeboot network config in {mgmt_intf.ifname} ")
            network = context['networks'][constants.NETWORK_TYPE_PXEBOOT]
            # Setup the default device configuration for the interface.  This will be
            # overridden if there is a specific network type configuration, otherwise
            # it will act as the parent device for the aliases
            mgmt_intf.networktypelist.append(constants.NETWORK_TYPE_PXEBOOT)
            address_name = None
            if context['hostname'] == constants.CONTROLLER_0_HOSTNAME:
                address_name = utils.format_address_name(constants.CONTROLLER_0_HOSTNAME,
                                                         constants.NETWORK_TYPE_PXEBOOT)
            elif context['hostname'] == constants.CONTROLLER_1_HOSTNAME:
                address_name = utils.format_address_name(constants.CONTROLLER_1_HOSTNAME,
                                                         constants.NETWORK_TYPE_PXEBOOT)
            address = None
            if address_name:
                address = utils.get_primary_address_by_name(db_api, address_name,
                                                            constants.NETWORK_TYPE_PXEBOOT)

            net_config = get_interface_network_config(context, mgmt_intf, network, address)

            if net_config:
                config[NETWORK_CONFIG_RESOURCE].update({
                    net_config['ifname']: format_network_config(net_config)
                })


def get_address_config(context, iface, addresses):
    ifname = get_interface_os_ifname(context, iface)

    address_list = []
    for address in addresses:
        address_list.append(str(address.address) + '/' + str(address.prefix))
    return {
        'ifname': ifname,
        'addresses': address_list,
    }


def generate_address_configs(context, config, db_api):
    """
    Generate the puppet resource for each of the floating IP addresses
    """
    for networktype, addresses in six.iteritems(context['floatingips']):
        if (
            utils.is_aio_simplex_system(db_api)
            and networktype in (
                constants.NETWORK_TYPE_ADMIN,
                constants.NETWORK_TYPE_MGMT,
                constants.NETWORK_TYPE_STORAGE,
                constants.NETWORK_TYPE_CLUSTER_HOST,
                constants.NETWORK_TYPE_PXEBOOT,
            )
        ):
            continue
        iface = find_interface_by_type(context, networktype)
        if iface:
            address_config = get_address_config(context, iface, addresses)
            config[ADDRESS_CONFIG_RESOURCE].update({
                networktype: address_config
            })
        elif networktype == constants.NETWORK_TYPE_PXEBOOT:
            # Fallback PXE boot address against management interface
            iface = find_interface_by_type(context,
                                           constants.NETWORK_TYPE_MGMT)
            if iface:
                address_config = get_address_config(context, iface, addresses)
                config[ADDRESS_CONFIG_RESOURCE].update({
                    networktype: address_config
                })
        elif networktype == constants.NETWORK_TYPE_CLUSTER_HOST:
            # Fallback cluster host address against management interface
            iface = find_interface_by_type(context,
                                           constants.NETWORK_TYPE_CLUSTER_HOST)
            if iface:
                address_config = get_address_config(context, iface, addresses)
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
    if_op = {IFACE_UP_OP: 'up',
             IFACE_PRE_UP_OP: 'pre-up',
             IFACE_POST_UP_OP: 'post-up',
             IFACE_DOWN_OP: 'down',
             IFACE_PRE_DOWN_OP: 'pre-down',
             IFACE_POST_DOWN_OP: 'post-down'}

    if operation in if_op.keys():
        if if_op[operation] in options.keys():
            previous_command = options[if_op[operation]]
            options[if_op[operation]] = "{}; {}".format(previous_command,
                                                        command)
        else:
            options[if_op[operation]] = command


def get_intf_op_name(operation):
    if_op = {IFACE_UP_OP: 'up',
             IFACE_PRE_UP_OP: 'pre-up',
             IFACE_POST_UP_OP: 'post-up',
             IFACE_DOWN_OP: 'down',
             IFACE_PRE_DOWN_OP: 'pre-down',
             IFACE_POST_DOWN_OP: 'post-down'}

    return if_op[operation]


def generate_data_iface_rate_limit(context, config, db_api):
    """
    Generating the data for the interface rate limit configuration
    for puppet hieradata.
    """
    ip_pool = {}
    _get_ip_pool(context, db_api, ip_pool)
    if not ip_pool:
        LOG.error("Failed to generate interface data for rate limit: ip_pool is empty")
        return

    try:
        interfaces = context['interfaces'].values()
        for iface in interfaces:
            if check_interface_rate_limit_conditions(iface, db_api):
                _build_iface_rate_limit_config(context, iface, config, ip_pool)
    except Exception as e:
        LOG.error(f"Failed to generate interface data for rate limit: {e}", exc_info=True)


def _build_iface_rate_limit_config(context, iface, config, ip_pool):
    """
    Function to populate interface data -
    { max_tx_rate, max_rx_rate, address_pool, and accept_subnet}
    for rate limit configuration in puppet hieradata.
    """
    try:
        iface_dict = {}
        # max_tx_rate
        iface_dict['max_tx_rate'] = iface.get('max_tx_rate', None)

        # max_rx_rate
        iface_dict['max_rx_rate'] = iface.get('max_rx_rate', None)

        networktypelist = iface.get('networktypelist', [])
        ifname = iface.get('ifname', None)

        # Handle multiple network types on an interface
        # with same or different address pools.
        for network_type in networktypelist:
            if (network_type in ip_pool):
                if iface_dict.get('address_pool') is None:
                    iface_dict['address_pool'] = ip_pool[network_type]
                elif iface_dict['address_pool'] != ip_pool[network_type]:
                    iface_dict['address_pool'] = constants.DUAL
                    break

        if networktypelist and constants.NETWORK_TYPE_MGMT in networktypelist:
            iface_dict['accept_subnet'] = [constants.NETWORK_TYPE_MGMT]
        os_ifname = get_interface_os_ifname(context, iface)
        LOG.info(f"Configuring the rate limit for {ifname} under ifname: {os_ifname}")
        config[RATE_LIMIT_CONFIG_RESOURCE][os_ifname] = iface_dict
    except Exception as ex:
        LOG.error(f"Failed to add rate limit data: {ex}", exc_info=True)


def check_interface_rate_limit_conditions(iface, db_api):
    """
    Function to check the interface rate limit conditions:-
    1. Interface class is platform.
    2. Interface type is ethernet, ae, or vlan.
    3. Interface has max_tx_rate or max_rx_rate configured.
    4. Interface networktypes has no internal traffic type.
    5. If Interface networktype has mgmt, It should be a Distributed Cloud set up.
       Only in DC setup, mgmt network has both internal and external platform traffic.
       In other cases it is only internal.
    6. External networktypes like oam, admin are allowed.
    """
    if_class = iface.get('ifclass', None)
    if_type = iface.get('iftype', None)

    if not (if_class == constants.INTERFACE_CLASS_PLATFORM and
            if_type in {constants.INTERFACE_TYPE_ETHERNET,
                        constants.INTERFACE_TYPE_AE,
                        constants.INTERFACE_TYPE_VLAN}):
        return False

    if iface.get('max_tx_rate', None) is None and iface.get('max_rx_rate', None) is None:
        return False

    networktypelist = iface.get('networktypelist', [])
    ifname = iface.get('ifname', None)

    if not networktypelist:
        LOG.error(f"iface {ifname} has no networktypes, but rate_limit is configured")
        return False

    if set(networktypelist).intersection(constants.INTERNAL_NETWORK_TYPES):
        LOG.error(f"Cannot configure rate limit for iface {ifname}  \
                internal networktypes {constants.INTERNAL_NETWORK_TYPES} are not supported")
        return False

    if constants.NETWORK_TYPE_MGMT in networktypelist:
        system = db_api.isystem_get_one()
        if not system.distributed_cloud_role:
            LOG.error(f"Cannot rate-limit iface {ifname},\
                      has mgmt networktype, But is not of DC system mode")
            return False

    """
    returning True if iface networktype has mgmt (valid only in DC Setup) or
    other external networktypes like oam, admin.
    internal networktypes are not allowed to be rate-limited.
    """
    return True


def _get_ip_pool(context, db_api, ip_pool):
    """
    Get the ip pool such as ipv6, ipv4, and dual.
    """
    try:
        network_addrpools = db_api.network_addrpool_get_all()
        for network_addrpool in network_addrpools:
            network_type = network_addrpool.get('network_type')
            pool_name = network_addrpool.get('address_pool_name')
            if not network_type or not pool_name:
                LOG.info(f"Skipping network_type: {network_type}, pool_name: {pool_name}")
                continue
            if network_type == constants.NETWORK_TYPE_PXEBOOT:
                ip_pool[network_type] = constants.IPV4
            elif constants.IPV4 in pool_name:
                if network_type not in ip_pool:
                    ip_pool[network_type] = constants.IPV4
                else:
                    ip_pool[network_type] = constants.DUAL
            elif constants.IPV6 in pool_name:
                if network_type not in ip_pool:
                    ip_pool[network_type] = constants.IPV6
                else:
                    ip_pool[network_type] = constants.DUAL
    except Exception as ex:
        LOG.error(f"Failed to get the ip pool: {ex}", exc_info=True)
