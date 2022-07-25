#
# Copyright (c) 2013-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class SensorGroupAnalog(base.SysinvObject):
    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.str_or_none,
        'host_id': utils.int_or_none,

        'sensorgroupname': utils.str_or_none,
        'path': utils.str_or_none,

        'sensortype': utils.str_or_none,
        'datatype': utils.str_or_none,
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

        'unit_base_group': utils.str_or_none,
        'unit_modifier_group': utils.str_or_none,
        'unit_rate_group': utils.str_or_none,

        't_minor_lower_group': utils.str_or_none,
        't_minor_upper_group': utils.str_or_none,
        't_major_lower_group': utils.str_or_none,
        't_major_upper_group': utils.str_or_none,
        't_critical_lower_group': utils.str_or_none,
        't_critical_upper_group': utils.str_or_none,

        'suppress': utils.bool_or_none,
        'capabilities': utils.dict_or_none

    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.isensorgroup_analog_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.isensorgroup_analog_update(self.uuid,  # pylint: disable=no-member
                                              updates)
