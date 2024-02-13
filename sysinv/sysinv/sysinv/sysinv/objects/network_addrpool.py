#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class NetworkAddrpool(base.SysinvObject):
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.uuid_or_none,
        'address_pool_id': utils.int_or_none,
        'address_pool_uuid': utils.uuid_or_none,
        'address_pool_name': utils.str_or_none,
        'network_id': utils.int_or_none,
        'network_uuid': utils.uuid_or_none,
        'network_name': utils.str_or_none,
        'network_type': utils.str_or_none,
    }

    _foreign_fields = {
        'address_pool_id': 'address_pool:id',
        'address_pool_uuid': 'address_pool:uuid',
        'address_pool_name': 'address_pool:name',
        'network_uuid': 'network:uuid',
        'network_id': 'network:id',
        'network_name': 'network:name',
        'network_type': 'network:type'
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.network_addrpool_get(uuid)
