#
# Copyright (c) 2013-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#
from sysinv.common import constants
from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils
from sqlalchemy.orm import exc

from sysinv.openstack.common import log

LOG = log.getLogger(__name__)


def _get_address_mode(field, db_server, family):
    """Retrieves the address mode if populated on the DB entry"""
    for entry in getattr(db_server, 'address_modes', []):
        if entry.family == family:
            return entry.mode
    return None


def get_ipv4_address_mode(field, db_server):
    """Retrieves the IPv4 address mode if populated on the DB entry"""
    return _get_address_mode(field, db_server, constants.IPV4_FAMILY)


def get_ipv6_address_mode(field, db_server):
    """Retrieves the IPv6 address mode if populated on the DB entry"""
    return _get_address_mode(field, db_server, constants.IPV6_FAMILY)


def _get_address_pool(field, db_server, family):
    """Retrieves the address pool if populated on the DB entry"""
    for entry in getattr(db_server, 'address_modes', []):
        if entry.family == family and entry.address_pool:
            return entry.address_pool.uuid
    return None


def get_ipv4_address_pool(field, db_server):
    """Retrieves the IPv4 address pool if populated on the DB entry"""
    return _get_address_pool(field, db_server, constants.IPV4_FAMILY)


def get_ipv6_address_pool(field, db_server):
    """Retrieves the IPv6 address pool if populated on the DB entry"""
    return _get_address_pool(field, db_server, constants.IPV6_FAMILY)


def _get_interface_name_list(field, db_object):
    ifnames = []
    for i in db_object[field]:
        ifnames.append(i['ifname'])
    return ifnames


def get_host_uuid(field, db_server):
    """Retrieves the uuid of the host on which the interface resides"""
    host_uuid = None

    try:
        host = getattr(db_server, 'host', None)
        if host:
            host_uuid = host.uuid
    except exc.DetachedInstanceError:
        # instrument and return None host_uuid
        LOG.exception("DetachedInstanceError unable to get host_uuid for %s" %
                      db_server)
        pass

    return host_uuid


def get_networks(field, db_object):
    result = []
    try:
        if getattr(db_object, 'interface_networks', None):
            for entry in getattr(db_object, 'interface_networks', []):
                id_str = str(entry.network_id)
                result.append(id_str)
    except exc.DetachedInstanceError:
        # instrument and return empty network
        LOG.exception("DetachedInstanceError unable to get networks for %s" %
                      db_object)
        pass
    return result


def get_datanetworks(field, db_object):
    result = []
    try:
        if hasattr(db_object, 'interface_datanetworks'):
            for entry in getattr(db_object, 'interface_datanetworks', []):
                id_str = str(entry.datanetwork_id)
                result.append(id_str)
    except exc.DetachedInstanceError:
        # instrument and return empty datanetwork
        LOG.exception("DetachedInstanceError unable to get datanetworks \
                      for %s" % db_object)
        pass
    return result


class Interface(base.SysinvObject):
    # VERSION 1.0: Initial version
    # VERSION 1.1: Added VLAN and uses/used_by interface support
    VERSION = '1.1'

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,
            'forihostid': utils.int_or_none,
            'ihost_uuid': utils.str_or_none,

            'ifname': utils.str_or_none,
            'iftype': utils.str_or_none,
            'ifclass': utils.str_or_none,
            'imac': utils.str_or_none,
            'imtu': utils.int_or_none,
            'networktype': utils.str_or_none,
            'aemode': utils.str_or_none,
            'schedpolicy': utils.str_or_none,
            'txhashpolicy': utils.str_or_none,
            'networks': utils.list_of_strings_or_none,
            'datanetworks': utils.list_of_strings_or_none,

            'ifcapabilities': utils.dict_or_none,

            'vlan_id': utils.int_or_none,
            'vlan_type': utils.str_or_none,

            'uses': utils.list_of_strings_or_none,
            'used_by': utils.list_of_strings_or_none,

            'ipv4_mode': utils.ipv4_mode_or_none,
            'ipv6_mode': utils.ipv6_mode_or_none,
            'ipv4_pool': utils.uuid_or_none,
            'ipv6_pool': utils.uuid_or_none,
            'sriov_numvfs': utils.int_or_none
             }

    _foreign_fields = {'uses': _get_interface_name_list,
                       'used_by': _get_interface_name_list,
                       'ipv4_mode': get_ipv4_address_mode,
                       'ipv6_mode': get_ipv6_address_mode,
                       'ipv4_pool': get_ipv4_address_pool,
                       'ipv6_pool': get_ipv6_address_pool,
                       'ihost_uuid': get_host_uuid,
                       'networks': get_networks,
                       'datanetworks': get_datanetworks}

    _optional_fields = ['aemode', 'txhashpolicy', 'schedpolicy',
                        'vlan_id', 'vlan_type']

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.iinterface_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.iinterface_update(self.uuid, updates)
