#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class Network(base.SysinvObject):
    # VERSION 1.0: Initial version
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {'id': int,
              'uuid': utils.uuid_or_none,
              'type': utils.str_or_none,
              'mtu': utils.int_or_none,
              'link_capacity': utils.int_or_none,
              'dynamic': utils.bool_or_none,
              'vlan_id': utils.int_or_none,
              'pool_uuid': utils.uuid_or_none,
              }

    _foreign_fields = {'pool_uuid': 'address_pool:uuid'}

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.network_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.network_update(self.uuid, updates)
