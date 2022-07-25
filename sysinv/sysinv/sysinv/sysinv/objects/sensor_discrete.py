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


class SensorDiscrete(base.SysinvObject):
    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.str_or_none,
        'host_id': utils.int_or_none,
        'host_uuid': utils.str_or_none,
        'sensorgroup_id': utils.int_or_none,
        'sensorgroup_uuid': utils.str_or_none,

        'sensorname': utils.str_or_none,
        'path': utils.str_or_none,
        'datatype': utils.str_or_none,
        'sensortype': utils.str_or_none,

        'status': utils.str_or_none,
        'state': utils.str_or_none,
        'state_requested': utils.int_or_none,
        'audit_interval': utils.int_or_none,
        'algorithm': utils.str_or_none,
        'sensor_action_requested': utils.str_or_none,
        'actions_minor': utils.str_or_none,
        'actions_major': utils.str_or_none,
        'actions_critical': utils.str_or_none,

        'suppress': utils.bool_or_none,
        'capabilities': utils.dict_or_none
    }

    _foreign_fields = {
        'host_uuid': 'host:uuid',
        'sensorgroup_uuid': 'sensorgroup:uuid',
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.isensor_discrete_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.isensor_discrete_update(self.uuid,  # pylint: disable=no-member
                                           updates)
