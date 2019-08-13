#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class LLDPTLV(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {'id': int,
              'agent_id': utils.int_or_none,
              'agent_uuid': utils.str_or_none,
              'neighbour_id': utils.int_or_none,
              'neighbour_uuid': utils.str_or_none,
              'type': utils.str_or_none,
              'value': utils.str_or_none}

    _foreign_fields = {
        'agent_uuid': 'lldp_agent:uuid',
        'neighbour_uuid': 'lldp_neighbour:uuid',
    }

    @base.remotable_classmethod
    def get_by_id(cls, context, id):
        return cls.dbapi.lldp_tlv_get_by_id(id)

    def save_changes(self, context, updates):
        self.dbapi.lldp_tlv_update(self.id,  # pylint: disable=no-member
                                   updates)
