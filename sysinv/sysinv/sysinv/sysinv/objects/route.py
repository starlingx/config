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


class Route(base.SysinvObject):
    # VERSION 1.0: Initial version
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {'id': int,
              'uuid': utils.uuid_or_none,
              'forihostid': utils.int_or_none,
              'interface_uuid': utils.uuid_or_none,
              'interface_id': int,
              'ifname': utils.str_or_none,
              'family': utils.str_or_none,
              'network': utils.ip_str_or_none(),
              'prefix': utils.int_or_none,
              'gateway': utils.ip_str_or_none(),
              'metric': utils.int_or_none,
              }

    _foreign_fields = {'interface_uuid': 'interface:uuid',
                       'interface_id': 'interface:id',
                       'ifname': 'interface:ifname',
                       'forihostid': 'interface:forihostid'}

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.route_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.route_update(self.uuid, updates)
