#
# Copyright (c) 2013-2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc
from cgtsclient.v1 import isensor as isensor_utils


CREATION_ATTRIBUTES = ['host_uuid', 'sensortype', 'datatype',
                       'sensorgroupname',
                       'possible_states', 'actions_critical_choices',
                       'actions_major_choices', 'actions_minor_choices',
                       'algorithm', 'audit_interval_group',
                       'actions_minor_group', 'actions_major_group',
                       'actions_critical_group',
                       'record_ttl', 'capabilities',
                       'unit_base_group', 'unit_modifier_group',
                       'unit_rate_group',
                       't_minor_lower_group', 't_minor_upper_group',
                       't_major_lower_group', 't_major_upper_group',
                       't_critical_lower_group', 't_critical_upper_group',
                       ]


class isensorgroup(base.Resource):
    def __repr__(self):
        return "<isensorgroup %s>" % self._info


class isensorgroupManager(base.Manager):
    resource_class = isensorgroup

    @staticmethod
    def _path(parameter_id=None):
        return '/v1/isensorgroups/%s' % parameter_id if parameter_id else \
            '/v1/isensorgroups'

    def list(self, ihost_id):
        path = '/v1/ihosts/%s/isensorgroups' % ihost_id
        return self._list(path, "isensorgroups")

    def get(self, isensorgroup_id):
        path = '/v1/isensorgroups/%s' % isensorgroup_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/isensorgroups/'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute(key)
        return self._create(path, new)

    def delete(self, isensorgroup_id):
        path = '/v1/isensorgroups/%s' % isensorgroup_id
        return self._delete(path)

    def update(self, isensorgroup_id, patch):
        path = '/v1/isensorgroups/%s' % isensorgroup_id
        return self._update(path, patch)

    def relearn(self, ihost_uuid):
        new = {}
        new['host_uuid'] = ihost_uuid
        return self.api.json_request('POST', self._path() + "/relearn", body=new)


def get_sensorgroup_display_name(s):
    if s.sensorgroupname:
        return s.sensorgroupname
    else:
        return '(' + str(s.uuid)[-8:] + ')'


def _get_sensors(cc, ihost, sensorgroup):
    sensors = cc.isensor.list_by_sensorgroup(sensorgroup.uuid)
    sensor_list = [isensor_utils.get_sensor_display_name(p) for p in sensors]

    sensorgroup.sensors = sensor_list
