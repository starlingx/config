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


class DataNetwork(base.SysinvObject):
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {'id': int,
              'uuid': utils.uuid_or_none,
              'network_type': utils.str_or_none,
              'name': utils.str_or_none,
              'description': utils.str_or_none,
              'mtu': utils.int_or_none,
              'multicast_group': utils.str_or_none,
              'port_num': utils.int_or_none,
              'ttl': utils.int_or_none,
              'mode': utils.str_or_none,
              }

    _optional_fields = {'port_num',
                        'multicast_group',
                        'ttl',
                        'mode'}

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.datanetwork_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.datanetwork_update(self.uuid, updates)
