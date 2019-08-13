#
# Copyright (c) 2013-2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class SensorGroupDiscrete(base.SysinvObject):
    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.str_or_none,
        'host_id': utils.int_or_none,

        'sensorgroupname': utils.str_or_none,
        'path': utils.str_or_none,

        'datatype': utils.str_or_none,
        'sensortype': utils.str_or_none,
        'description': utils.str_or_none,

        'state': utils.str_or_none,
        'possible_states': utils.str_or_none,
        'audit_interval_group': utils.int_or_none,
        'record_ttl': utils.str_or_none,

        'algorithm': utils.str_or_none,
        'actions_critical_choices': utils.str_or_none,
        'actions_major_choices': utils.str_or_none,
        'actions_minor_choices': utils.str_or_none,
        'actions_minor_group': utils.str_or_none,
        'actions_major_group': utils.str_or_none,
        'actions_critical_group': utils.str_or_none,

        'suppress': utils.str_or_none,
        'capabilities': utils.dict_or_none

    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.isensorgroup_discrete_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.isensorgroup_discrete_update(self.uuid,  # pylint: disable=no-member
                                                updates)
