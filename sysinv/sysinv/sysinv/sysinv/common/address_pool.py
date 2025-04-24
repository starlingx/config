#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Common address pool utility and helper functions."""

import netaddr
import pecan
import random

from oslo_log import log
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils

LOG = log.getLogger(__name__)

# Address allocation schemes
SEQUENTIAL_ALLOCATION = 'sequential'
RANDOM_ALLOCATION = 'random'

# Address fields
FLOATING_ADDRESS = 'floating_address'
CONTROLLER0_ADDRESS = 'controller0_address'
CONTROLLER1_ADDRESS = 'controller1_address'
GATEWAY_ADDRESS = 'gateway_address'

# Address id fields
FLOATING_ADDRESS_ID = 'floating_address_id'
CONTROLLER0_ADDRESS_ID = 'controller0_address_id'
CONTROLLER1_ADDRESS_ID = 'controller1_address_id'
GATEWAY_ADDRESS_ID = 'gateway_address_id'

ADDRESS_TO_ID_FIELD_INDEX = {FLOATING_ADDRESS: FLOATING_ADDRESS_ID,
                             CONTROLLER0_ADDRESS: CONTROLLER0_ADDRESS_ID,
                             CONTROLLER1_ADDRESS: CONTROLLER1_ADDRESS_ID,
                             GATEWAY_ADDRESS: GATEWAY_ADDRESS_ID}

ID_TO_ADDRESS_FIELD_INDEX = {FLOATING_ADDRESS_ID: FLOATING_ADDRESS,
                             CONTROLLER0_ADDRESS_ID: CONTROLLER0_ADDRESS,
                             CONTROLLER1_ADDRESS_ID: CONTROLLER1_ADDRESS,
                             GATEWAY_ADDRESS_ID: GATEWAY_ADDRESS}

HOSTNAME_ADDRESS_ID_FIELDS = {constants.CONTROLLER_HOSTNAME: FLOATING_ADDRESS_ID,
                              constants.CONTROLLER_0_HOSTNAME: CONTROLLER0_ADDRESS_ID,
                              constants.CONTROLLER_1_HOSTNAME: CONTROLLER1_ADDRESS_ID,
                              constants.CONTROLLER_GATEWAY: GATEWAY_ADDRESS_ID}

ADDRESS_FIELD_HOSTNAMES = {FLOATING_ADDRESS: constants.CONTROLLER_HOSTNAME,
                           CONTROLLER0_ADDRESS: constants.CONTROLLER_0_HOSTNAME,
                           CONTROLLER1_ADDRESS: constants.CONTROLLER_1_HOSTNAME,
                           GATEWAY_ADDRESS: constants.CONTROLLER_GATEWAY}

BASE_ADDRESS_SET = {constants.CONTROLLER_HOSTNAME: FLOATING_ADDRESS_ID,
                    constants.CONTROLLER_0_HOSTNAME: CONTROLLER0_ADDRESS_ID,
                    constants.CONTROLLER_1_HOSTNAME: CONTROLLER1_ADDRESS_ID}

MULTICAST_ADDRESS_SET = {constants.SM_MULTICAST_MGMT_IP_NAME: None,
                         constants.MTCE_MULTICAST_MGMT_IP_NAME: None,
                         constants.PATCH_CONTROLLER_MULTICAST_MGMT_IP_NAME: None,
                         constants.PATCH_AGENT_MULTICAST_MGMT_IP_NAME: None}

REQUIRED_ADDRESS_SET_INDEX = {constants.NETWORK_TYPE_MGMT: BASE_ADDRESS_SET,
                              constants.NETWORK_TYPE_ADMIN: BASE_ADDRESS_SET,
                              constants.NETWORK_TYPE_PXEBOOT: BASE_ADDRESS_SET,
                              constants.NETWORK_TYPE_CLUSTER_HOST: BASE_ADDRESS_SET,
                              constants.NETWORK_TYPE_IRONIC: BASE_ADDRESS_SET,
                              constants.NETWORK_TYPE_STORAGE: BASE_ADDRESS_SET,
                              constants.NETWORK_TYPE_MULTICAST: MULTICAST_ADDRESS_SET}

# Networks for which addresses can be assigned to interfaces
ADDRESS_INTERFACE_ASSIGNABLE_NETS = {constants.NETWORK_TYPE_MGMT,
                                     constants.NETWORK_TYPE_OAM,
                                     constants.NETWORK_TYPE_CLUSTER_HOST,
                                     constants.NETWORK_TYPE_PXEBOOT,
                                     constants.NETWORK_TYPE_STORAGE,
                                     constants.NETWORK_TYPE_ADMIN,
                                     constants.NETWORK_TYPE_IRONIC}

# Networks for which addresses can be dynamically allocated
DYNAMIC_ALLOCATION_ENABLED_NETS = {constants.NETWORK_TYPE_MGMT,
                                   constants.NETWORK_TYPE_CLUSTER_HOST,
                                   constants.NETWORK_TYPE_STORAGE}

ALLOWED_OVERLAP_INDEX = {
    constants.NETWORK_TYPE_OAM: [constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM],
    constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM: [constants.NETWORK_TYPE_OAM],
    constants.NETWORK_TYPE_CLUSTER_POD: [constants.NETWORK_TYPE_CLUSTER_SERVICE,
                                         constants.NETWORK_TYPE_CLUSTER_HOST],
    constants.NETWORK_TYPE_CLUSTER_SERVICE: [constants.NETWORK_TYPE_CLUSTER_POD,
                                             constants.NETWORK_TYPE_CLUSTER_HOST],
    constants.NETWORK_TYPE_CLUSTER_HOST: [constants.NETWORK_TYPE_CLUSTER_POD,
                                          constants.NETWORK_TYPE_CLUSTER_SERVICE]}


def _select_address(available, order):
    """
    Chooses a new IP address from the set of available addresses according
    to the allocation order directive.
    """
    if order == SEQUENTIAL_ALLOCATION:
        return str(next(available.iter_ipranges())[0])
    elif order == RANDOM_ALLOCATION:
        index = random.randint(0, available.size - 1)
        for r in available.iter_ipranges():
            if index < r.size:
                return str(r[index])
            index = index - r.size
    else:
        raise exception.AddressPoolInvalidAllocationOrder(order=order)


def get_next_available_ip_address(pool, dbapi=None, order=None):
    """
    Gets the next available IP address from a pool.
    """
    if not dbapi:
        dbapi = pecan.request.dbapi
    # Build a set of defined ranges
    defined = netaddr.IPSet()
    for (start, end) in pool.ranges:
        defined.update(netaddr.IPRange(start, end))
    # Determine which addresses are already in use
    addresses = dbapi.addresses_get_by_pool(pool.id)
    inuse = netaddr.IPSet()
    for a in addresses:
        inuse.add(a.address)
    # Calculate which addresses are still available
    available = defined - inuse
    if available.size == 0:
        raise exception.AddressPoolExhausted(name=pool.name)
    if order is None:
        order = pool.order
    # Select an address according to the allocation scheme
    return _select_address(available, order)


def _do_alloc_pool_address_to_interface(pool, address_name=None, interface_id=None,
                                        dbapi=None, order=None):
    if not dbapi:
        dbapi = pecan.request.dbapi
    ip_address = get_next_available_ip_address(pool, dbapi, order)
    values = {'address': ip_address,
              'prefix': pool.prefix,
              'family': pool.family,
              'enable_dad': constants.IP_DAD_STATES[pool.family],
              'address_pool_id': pool.id,
              'interface_id': interface_id}
    if address_name:
        values['name'] = address_name
    try:
        existing_address = dbapi.address_get_by_address(ip_address)
        if existing_address.pool_id != pool.id:
            # If the address already exists, it could belong to an unassigned address pool
            # and has to be removed from it
            disassociate_address_from_pool(existing_address, dbapi)
        address_obj = dbapi.address_update(existing_address.id, values)
    except exception.AddressNotFoundByAddress:
        address_obj = dbapi.address_create(values)
    return address_obj


def alloc_pool_address_to_interface(interface_id, pool_uuid, address_name=None, dbapi=None):
    """
    Allocates the next available IP address from a pool and assigns it to
    an interface object.
    """
    if not dbapi:
        dbapi = pecan.request.dbapi
    pool = dbapi.address_pool_get(pool_uuid)
    return _do_alloc_pool_address_to_interface(pool, address_name, interface_id, dbapi)


def disassociate_address_from_pool(address, dbapi=None):
    if not address.pool_uuid:
        return
    if not dbapi:
        dbapi = pecan.request.dbapi
    addrpool = dbapi.address_pool_get(address.pool_uuid)
    for field in ADDRESS_TO_ID_FIELD_INDEX.values():
        if getattr(addrpool, field, None) == address.id:
            dbapi.address_pool_update(addrpool.id, {field: None})
            LOG.info("Address {} disassociated from address pool {{{}}}, field '{}'".format(
                address.address, addrpool.uuid, field))
            return


def associate_address_to_pool(addrpool, address_id, hostname, dbapi=None):
    field = HOSTNAME_ADDRESS_ID_FIELDS.get(hostname, None)
    if not field:
        return
    if getattr(addrpool, field) != address_id:
        if not dbapi:
            dbapi = pecan.request.dbapi
        dbapi.address_pool_update(addrpool.id, {field: address_id})


def _get_system_mode(dbapi):
    system = dbapi.isystem_get_one()
    return system.system_mode


def _get_distributed_cloud_role(dbapi):
    system = dbapi.isystem_get_one()
    return system.distributed_cloud_role


def _get_hostname_field_index(network_type, dbapi=None):
    """
    Builds a dictionary in the format {hostname: (field, mandatory)} in which each entry represents
    an address that has to be created or updated in the address pool, where:
    hostname: host name which will be used to create the address name.
    field: field name in the address pool object which holds the address id.
    mandatory: boolean indicating whether the address is mandatory. If True and the address does not
               already exist, it will be created. Otherwise, it will be just updated.
    """
    req_addresses = REQUIRED_ADDRESS_SET_INDEX.get(network_type, {})

    entries = {hostname: (field, False) for hostname, field in HOSTNAME_ADDRESS_ID_FIELDS.items()}

    for hostname, field in req_addresses.items():
        entries[hostname] = (field, True)
        if network_type in {constants.NETWORK_TYPE_ADMIN, constants.NETWORK_TYPE_MGMT} and \
                _get_system_mode(dbapi) == constants.SYSTEM_MODE_SIMPLEX:
            if hostname in [constants.CONTROLLER_0_HOSTNAME, constants.CONTROLLER_1_HOSTNAME]:
                del entries[hostname]

    return entries


def populate_network_pool_addresses(addrpool, network_type, dbapi=None):
    """
    Allocates all required addresses that are missing from the given address pool according to the
    rules pertaining the associated network. Also updates addresses' names.
    """
    if not dbapi:
        dbapi = pecan.request.dbapi

    field_index = _get_hostname_field_index(network_type, dbapi)

    addr_create_values = {'address_pool_id': addrpool.id,
                          'prefix': addrpool.prefix,
                          'family': addrpool.family,
                          'enable_dad': constants.IP_DAD_STATES[addrpool.family]}

    addr_update_values = {'address_pool_id': addrpool.id}

    addrpool_updates = {}
    obj_updates = {}
    for hostname, (field, mandatory) in field_index.items():
        name = cutils.format_address_name(hostname, network_type)
        address_id = getattr(addrpool, field) if field else None
        if address_id:
            address = dbapi.address_get(address_id)
        else:
            if mandatory:
                ip_address = get_next_available_ip_address(addrpool, order=SEQUENTIAL_ALLOCATION)
                try:
                    address = dbapi.address_get_by_address(ip_address)
                    if address.pool_id != addrpool.id:
                        disassociate_address_from_pool(address, dbapi)
                except exception.AddressNotFoundByAddress:
                    addr_create_values['address'] = ip_address
                    addr_create_values['name'] = name
                    addr_create_values.pop('uuid', None)
                    address = dbapi.address_create(addr_create_values)
                if field:
                    addrpool_updates[field] = address.id
                    obj_updates[ID_TO_ADDRESS_FIELD_INDEX.get(field)] = address.address
            else:
                address = None
        if address and (address.name != name or address.pool_id != addrpool.id):
            addr_update_values['name'] = name
            dbapi.address_update(address.id, addr_update_values)

    if addrpool_updates:
        dbapi.address_pool_update(addrpool.id, addrpool_updates)
        obj_updates.update(addrpool_updates)
        for field, value in obj_updates.items():
            setattr(addrpool, field, value)


def assign_pool_addresses_to_interfaces(addrpool, network, dbapi=None):
    if not dbapi:
        dbapi = pecan.request.dbapi
    if_net_list = pecan.request.dbapi.interface_network_get_by_network_id(network.id)
    for if_net in if_net_list:
        host = pecan.request.dbapi.ihost_get(if_net.forihostid)
        assign_network_addresses_to_interface(host, if_net.interface_id, network, [addrpool], dbapi)


def assign_network_addresses_to_interface(host, interface_id, network, addrpools, dbapi=None):
    if network.type not in ADDRESS_INTERFACE_ASSIGNABLE_NETS:
        return
    if not dbapi:
        dbapi = pecan.request.dbapi
    if host.personality == constants.CONTROLLER:
        _assign_addresses_to_controller_iface(host, interface_id, network, addrpools, dbapi)
    else:
        _assign_addresses_to_non_controller_iface(host, interface_id, network, addrpools, dbapi)


def _assign_addresses_to_controller_iface(host, interface_id, network, addrpools, dbapi):
    if network.type in [constants.NETWORK_TYPE_OAM, constants.NETWORK_TYPE_ADMIN,
                        constants.NETWORK_TYPE_MGMT] and \
            _get_system_mode(dbapi) == constants.SYSTEM_MODE_SIMPLEX:
        hostname = constants.CONTROLLER_HOSTNAME
    else:
        hostname = host.hostname
    id_field = HOSTNAME_ADDRESS_ID_FIELDS.get(hostname)
    for addrpool in addrpools:
        address_id = getattr(addrpool, id_field)
        if address_id:
            dbapi.address_update(address_id, {'interface_id': interface_id})
            if network.type == constants.NETWORK_TYPE_MGMT and addrpool.uuid == network.pool_uuid:
                mgmt_ip = getattr(addrpool, ID_TO_ADDRESS_FIELD_INDEX.get(id_field))
                pecan.request.rpcapi.mgmt_ip_set_by_ihost(
                    pecan.request.context, host.uuid, interface_id, mgmt_ip)


def _assign_addresses_to_non_controller_iface(host, interface_id, network, addrpools, dbapi):
    addr_name = cutils.format_address_name(host.hostname, network.type)
    pools_with_addrs = set()
    for addrpool in addrpools:
        try:
            address = dbapi.address_get_by_name_and_family(addr_name, addrpool.family)
            dbapi.address_update(address.uuid, {'interface_id': interface_id})
            pools_with_addrs.add(addrpool.uuid)
        except exception.AddressNotFoundByNameAndFamily:
            pass
    if len(addrpools) > len(pools_with_addrs):
        if network.dynamic and network.type in DYNAMIC_ALLOCATION_ENABLED_NETS:
            for addrpool in addrpools:
                if addrpool.uuid not in pools_with_addrs:
                    _do_alloc_pool_address_to_interface(addrpool, addr_name, interface_id, dbapi)


def _get_attrib(obj, field, default=None):
    if isinstance(obj, dict):
        return obj.get(field, default)
    return getattr(obj, field, default)


def get_address_pool_overlaps(dbapi, ref_addrpools):
    """
    Gets all the existing address pools that overlap with the ones in ref_addrpools. Only the
    pools that are associated to networks or interfaces are included.
    Return list format:
    [
        {
            'ref_addrpool': <reference address pool object>,
            'conflicting_addrpools': [
                {
                    'addrpool': <existing address pool object>,
                    'interface_uuid': <interface uuid or None>,
                    'network_uuid': <network uuid or None>
                },
                ...
            ],
        },
        ...
    ]
    """
    addr_modes = dbapi.address_modes_get_all()
    network_addrpools = dbapi.network_addrpool_get_all()

    assigned_addrpools = {}
    for addr_mode in addr_modes:
        if addr_mode.pool_uuid:
            addrpool_dict = assigned_addrpools.setdefault(addr_mode.pool_uuid, {})
            addrpool_dict['interface_uuid'] = addr_mode.interface_uuid

    for nw_addrpool in network_addrpools:
        addrpool_dict = assigned_addrpools.setdefault(nw_addrpool.address_pool_uuid, {})
        addrpool_dict['network_uuid'] = nw_addrpool.network_uuid

    for ref_addrpool in ref_addrpools:
        assigned_addrpools.pop(_get_attrib(ref_addrpool, 'uuid'), None)

    if not assigned_addrpools:
        return {}

    existing_addrpools = dbapi.address_pools_get_all()

    overlaps = []
    for ref_addrpool in ref_addrpools:
        current_pool_ip_set = netaddr.IPSet([f"{_get_attrib(ref_addrpool, 'network')}/"
                                             f"{_get_attrib(ref_addrpool, 'prefix')}"])
        ref_entry = None
        for existing_addrpool in existing_addrpools:
            addrpool_dict = assigned_addrpools.get(existing_addrpool.uuid, None)
            if not addrpool_dict:
                continue
            pool_ip_set = netaddr.IPSet([f"{existing_addrpool.network}/{existing_addrpool.prefix}"])
            intersection = current_pool_ip_set & pool_ip_set
            if intersection.size:
                if not ref_entry:
                    ref_entry = {'ref_addrpool': ref_addrpool}
                    overlaps.append(ref_entry)
                conflict_list = ref_entry.setdefault('conflicting_addrpools', [])
                conflict_item = {'addrpool': existing_addrpool,
                                 'network_uuid': addrpool_dict.get('network_uuid', None),
                                 'interface_uuid': addrpool_dict.get('interface_uuid', None)}
                conflict_list.append(conflict_item)

    return overlaps


def check_address_pools_overlaps(dbapi, ref_addrpools, network_types=None, show_ref_id=True):
    overlaps = get_address_pool_overlaps(dbapi, ref_addrpools)
    if not overlaps:
        return

    allowed_networks = {network for t in network_types if t in ALLOWED_OVERLAP_INDEX
                        for network in ALLOWED_OVERLAP_INDEX.get(t)} if network_types else {}

    addrpool_texts = []
    for overlap in overlaps:
        ref_addrpool = overlap['ref_addrpool']
        conflicts = overlap['conflicting_addrpools']
        overlap_list = []
        for conflict in conflicts:
            network = None
            interface = None
            nw_uuid = conflict['network_uuid']
            if nw_uuid:
                network = dbapi.network_get(nw_uuid)
            if allowed_networks and network:
                if network.type in allowed_networks:
                    continue
            if_uuid = conflict['interface_uuid']
            if if_uuid:
                interface = dbapi.iinterface_get(if_uuid)
                host = dbapi.ihost_get(interface.forihostid)
            addrpool_obj = conflict['addrpool']
            assigned_texts = []
            if network:
                assigned_texts.append(f"to {network.type} network")
            if interface:
                assigned_texts.append(f"to '{interface.ifname}' interface in host {host.hostname}")
            overlap_text = (f"'{addrpool_obj.name}' {{{addrpool_obj.uuid}}} "
                            f"assigned {' and '.join(assigned_texts)}")
            overlap_list.append(overlap_text)
        if not overlap_list:
            continue
        ref_id = ''
        if show_ref_id:
            ref_id = " '{}' {{{}}}".format(_get_attrib(ref_addrpool, 'name'),
                                           _get_attrib(ref_addrpool, 'uuid'))
        addrpool_text = "Address pool{} {}/{} overlaps with: {}".format(
            ref_id, _get_attrib(ref_addrpool, 'network'), _get_attrib(ref_addrpool, 'prefix'),
            ', '.join(overlap_list))
        addrpool_texts.append(addrpool_text)

    if overlap_list:
        raise exception.AddressPoolOverlaps('\n'.join(addrpool_texts))


def get_docker_no_proxy_entry():
    try:
        no_proxy_entry = pecan.request.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_DOCKER,
            section=constants.SERVICE_PARAM_SECTION_DOCKER_PROXY,
            name=constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY)
    except exception.NotFound:
        return None
    return no_proxy_entry


def update_docker_no_proxy_list(no_proxy_entry, to_remove=None, to_add=None):
    no_proxy_list = no_proxy_entry.value.split(',') if no_proxy_entry.value else []

    if to_remove:
        for family, address in to_remove:
            if family == constants.IPV6_FAMILY:
                address = '[' + address + ']'
            if address in no_proxy_list:
                no_proxy_list.remove(address)

    if to_add:
        for family, address in to_add:
            if family == constants.IPV6_FAMILY:
                address = '[' + address + ']'
            if address not in no_proxy_list:
                no_proxy_list.append(address)

    no_proxy_string = ','.join(no_proxy_list)
    pecan.request.dbapi.service_parameter_update(no_proxy_entry.uuid, {'value': no_proxy_string})


def _collect_management_addresses(addrpool):
    addresses = []
    if addrpool.floating_address:
        addresses.append((addrpool.family, addrpool.floating_address))
    if addrpool.controller0_address:
        addresses.append((addrpool.family, addrpool.controller0_address))
    return addresses


def add_management_addresses_to_no_proxy_list(addrpools):
    no_proxy_entry = get_docker_no_proxy_entry()
    if not no_proxy_entry:
        return
    for addrpool in addrpools:
        addresses = _collect_management_addresses(addrpool)
        if addresses:
            update_docker_no_proxy_list(no_proxy_entry, to_add=addresses)


def remove_management_addresses_from_no_proxy_list(addrpools):
    no_proxy_entry = get_docker_no_proxy_entry()
    if not no_proxy_entry:
        return
    for addrpool in addrpools:
        addresses = _collect_management_addresses(addrpool)
        if addresses:
            update_docker_no_proxy_list(no_proxy_entry, to_remove=addresses)
