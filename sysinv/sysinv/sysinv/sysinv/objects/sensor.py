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

from sysinv.openstack.common import log
LOG = log.getLogger(__name__)


class Sensor(base.SysinvObject):
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

        'unit_base': utils.str_or_none,
        'unit_modifier': utils.str_or_none,
        'unit_rate': utils.str_or_none,

        't_minor_lower': utils.str_or_none,
        't_minor_upper': utils.str_or_none,
        't_major_lower': utils.str_or_none,
        't_major_upper': utils.str_or_none,
        't_critical_lower': utils.str_or_none,
        't_critical_upper': utils.str_or_none,

        'suppress': utils.str_or_none,
        'capabilities': utils.dict_or_none
    }

    _foreign_fields = {
        'host_uuid': 'host:uuid',
        'sensorgroup_uuid': 'sensorgroup:uuid',
    }

    _optional_fields = [
        'unit_base',
        'unit_modifier',
        'unit_rate',

        't_minor_lower',
        't_minor_upper',
        't_major_lower',
        't_major_upper',
        't_critical_lower',
        't_critical_upper',
    ]

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.isensor_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.isensor_update(self.uuid,  # pylint: disable=no-member
                                  updates)
