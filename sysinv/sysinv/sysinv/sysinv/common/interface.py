#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Common interface utility and helper functions."""

import collections
import copy
import re

from oslo_log import log
from sysinv.common import constants

LOG = log.getLogger(__name__)


def _get_port_interface_id_index(dbapi, host):
    """
    Builds a dictionary of ports indexed by interface id.
    """
    ports = {}
    for port in dbapi.ethernet_port_get_by_host(host.id):
        ports[port.interface_id] = port
    return ports


def _get_interface_name_index(dbapi, host):
    """
    Builds a dictionary of interfaces indexed by interface name.
    """
    interfaces = {}
    for iface in dbapi.iinterface_get_by_ihost(host.id):
        interfaces[iface.ifname] = iface
    return interfaces


def _get_interface_name_datanets(dbapi, host):
    """
    Builds a dictionary of datanets indexed by interface name.
    """
    datanets = {}
    for iface in dbapi.iinterface_get_by_ihost(host.id):
        ifdatanets = dbapi.interface_datanetwork_get_by_interface(iface.uuid)

        datanetworks = []
        for ifdatanet in ifdatanets:
            datanetworks.append(ifdatanet.datanetwork_uuid)

        datanetworks_list = []
        for datanetwork in datanetworks:
            dn = dbapi.datanetwork_get(datanetwork)
            datanetwork_dict = \
                {'name': dn.name,
                 'uuid': dn.uuid,
                 'network_type': dn.network_type,
                 'mtu': dn.mtu}
            if dn.network_type == constants.DATANETWORK_TYPE_VXLAN:
                datanetwork_dict.update(
                    {'multicast_group': dn.multicast_group,
                     'port_num': dn.port_num,
                     'ttl': dn.ttl,
                     'mode': dn.mode})
            datanetworks_list.append(datanetwork_dict)
        datanets[iface.ifname] = datanetworks_list

    LOG.debug('_get_interface_name_datanets '
              'host=%s, datanets=%s', host.hostname, datanets)

    return datanets


def _get_address_interface_name_index(dbapi, host):
    """
    Builds a dictionary of address lists indexed by interface name.
    """
    addresses = collections.defaultdict(list)
    for address in dbapi.addresses_get_by_host(host.id):
        addresses[address.ifname].append(address)
    return addresses


def get_interface_datanets(context, iface):
    """
    Return the list of data networks of the supplied interface
    """
    return context['interfaces_datanets'][iface.ifname]


def _get_datanetwork_names(context, iface):
    """
    Return the CSV list of data networks of the supplied interface
    """
    dnets = get_interface_datanets(context, iface)
    dnames_list = [dnet['name'] for dnet in dnets]
    dnames = ",".join(dnames_list)
    return dnames


def get_interface_port(context, iface):
    """
    Determine the port of the underlying device.
    """
    assert iface['iftype'] == constants.INTERFACE_TYPE_ETHERNET
    return context['ports'][iface['id']]


def get_lower_interface(context, iface):
    assert iface['iftype'] in [constants.INTERFACE_TYPE_VLAN,
                               constants.INTERFACE_TYPE_VF]
    lower_ifname = iface['uses'][0]
    return context['interfaces'][lower_ifname]


def get_sriov_interface_port(context, iface):
    """
    Determine the underlying port of the SR-IOV interface.
    """
    if iface['iftype'] == constants.INTERFACE_TYPE_VF:
        lower_iface = get_lower_interface(context, iface)
        return get_sriov_interface_port(context, lower_iface)
    else:
        assert iface['ifclass'] == constants.INTERFACE_CLASS_PCI_SRIOV
        return get_interface_port(context, iface)


def get_sriov_interface_device_id(context, iface):
    """
    Determine the underlying PCI device id of the SR-IOV interface.
    """
    # The device id can be found by inspecting the '[xxxx]' at the
    # end of the port's pdevice field
    device_id = None
    port = get_sriov_interface_port(context, iface)
    if port:
        device_id = re.search(r'\[([0-9a-fA-F]{1,4})\]$', port['pdevice'])
        if device_id:
            device_id = device_id.group(1)
    return device_id


def get_sriov_interface_vf_addrs(context, iface, vf_addr_list):
    """
    Determine the virtual function addresses of SR-IOV interface,
    given the list of vf addresses on the port.
    """
    vf_addrs = copy.deepcopy(vf_addr_list)

    if iface['uses']:
        lower_iface = get_lower_interface(context, iface)
        lower_vf_addrs = get_sriov_interface_vf_addrs(context, lower_iface, vf_addr_list)

        # Remove the VF addresses reserved for the lower SR-IOV interface
        vf_addrs = [addr for addr in vf_addr_list if addr not in lower_vf_addrs]

        sibling_ifaces = lower_iface['used_by']
        for sibling_ifname in sibling_ifaces:
            sibling_iface = context['interfaces'][sibling_ifname]
            sibling_numvfs = sibling_iface['sriov_numvfs']
            if sibling_ifname == iface['ifname']:
                # Reserve the appropriate number of VF addresses from
                # the end of the list for the interface.
                vf_addrs = vf_addrs[-iface['sriov_numvfs']:]
                break
            else:
                # Remove the VF addresses reserved for any sibling SR-IOV
                # interface
                del vf_addrs[-sibling_numvfs:]

    if iface['used_by']:
        upper_ifaces = iface['used_by']
        for upper_ifname in upper_ifaces:
            upper_iface = context['interfaces'][upper_ifname]
            upper_numvfs = upper_iface['sriov_numvfs']
            if upper_numvfs:
                # Remove the VF addresses reserved for any child
                # SR-IOV interface
                del vf_addrs[-upper_numvfs:]

    return vf_addrs
