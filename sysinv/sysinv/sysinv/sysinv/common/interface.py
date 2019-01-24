#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Common interface utility and helper functions."""

import collections

from sysinv.common import constants
from sysinv.openstack.common import log

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
