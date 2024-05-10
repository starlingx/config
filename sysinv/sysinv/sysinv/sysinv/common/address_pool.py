#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Common address pool utility and helper functions."""

import netaddr

from sysinv.common import constants
from sysinv.common import exception

ALLOWED_OVERLAP_INDEX = {
    constants.NETWORK_TYPE_OAM: constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM,
    constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM: constants.NETWORK_TYPE_OAM}


def _get_attrib(obj, field, default=None):
    if isinstance(obj, dict):
        return obj.get(field, default)
    return getattr(obj, field, default)


def get_address_pool_overlaps(dbapi, ref_addrpools):
    '''
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
    '''
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

    allowed_networks = {ALLOWED_OVERLAP_INDEX.get(t) for t in network_types
                        if t in ALLOWED_OVERLAP_INDEX} if network_types else {}

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
