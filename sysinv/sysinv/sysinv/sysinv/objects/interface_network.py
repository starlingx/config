#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class InterfaceNetwork(base.SysinvObject):
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.uuid_or_none,
        'forihostid': utils.int_or_none,
        'interface_id': utils.int_or_none,
        'interface_uuid': utils.uuid_or_none,
        'ifname': utils.str_or_none,
        'network_id': utils.int_or_none,
        'network_uuid': utils.uuid_or_none,
        'network_name': utils.str_or_none,
        'network_type': utils.str_or_none
    }

    _foreign_fields = {
        'forihostid': 'interface:forihostid',
        'interface_id': 'interface:id',
        'interface_uuid': 'interface:uuid',
        'ifname': 'interface:ifname',
        'network_uuid': 'network:uuid',
        'network_id': 'network:id',
        'network_name': 'network:name',
        'network_type': 'network:type'
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.interface_network_get(uuid)
