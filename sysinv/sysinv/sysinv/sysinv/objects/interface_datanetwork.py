#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


def _get_mtu(field, db_object):
    mtu = None
    datanetwork = getattr(db_object, 'datanetwork', None)
    if hasattr(datanetwork, 'mtu'):
        mtu = datanetwork.mtu
    return mtu


def _get_multicast_group(field, db_object):
    multicast_group = None
    datanetwork = getattr(db_object, 'datanetwork', None)
    if hasattr(datanetwork, 'multicast_group'):
        multicast_group = datanetwork.multicast_group
    return multicast_group


def _get_port_num(field, db_object):
    port_num = None
    datanetwork = getattr(db_object, 'datanetwork', None)
    if hasattr(datanetwork, 'port_num'):
        port_num = datanetwork.port_num
    return port_num


def _get_ttl(field, db_object):
    ttl = None
    datanetwork = getattr(db_object, 'datanetwork', None)
    if hasattr(datanetwork, 'ttl'):
        ttl = datanetwork.ttl
    return ttl


def _get_mode(field, db_object):
    mode = None
    datanetwork = getattr(db_object, 'datanetwork', None)
    if hasattr(datanetwork, 'mode'):
        mode = datanetwork.mode
    return mode


class InterfaceDataNetwork(base.SysinvObject):
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.uuid_or_none,
        'forihostid': utils.int_or_none,
        'interface_id': utils.int_or_none,
        'interface_uuid': utils.uuid_or_none,
        'ifname': utils.str_or_none,
        'datanetwork_id': utils.int_or_none,
        'datanetwork_uuid': utils.uuid_or_none,
        'datanetwork_name': utils.str_or_none,
        'datanetwork_network_type': utils.str_or_none,
        'datanetwork_description': utils.str_or_none,
        'datanetwork_mtu': utils.int_or_none,
        'datanetwork_port_num': utils.int_or_none,
        'datanetwork_multicast_group': utils.str_or_none,
        'datanetwork_ttl': utils.int_or_none,
        'datanetwork_mode': utils.str_or_none,
    }

    _foreign_fields = {
        'forihostid': 'interface:forihostid',
        'interface_id': 'interface:id',
        'interface_uuid': 'interface:uuid',
        'ifname': 'interface:ifname',
        'datanetwork_uuid': 'datanetwork:uuid',
        'datanetwork_id': 'datanetwork:id',
        'datanetwork_name': 'datanetwork:name',
        'datanetwork_network_type': 'datanetwork:network_type',
        'datanetwork_description': 'datanetwork:description',
        'datanetwork_mtu': _get_mtu,
        'datanetwork_port_num': _get_port_num,
        'datanetwork_multicast_group': _get_multicast_group,
        'datanetwork_ttl': _get_ttl,
        'datanetwork_mode': _get_mode,
    }

    _optional_fields = {
        'datanetwork_port_num',
        'datanetwork_multicast_group',
        'datanetwork_ttl',
        'datanetwork_mode',
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.interface_datanetwork_get(uuid)
