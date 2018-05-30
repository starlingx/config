#
# Copyright (c) 2013-2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['host_uuid', 'sensorgroup_uuid', 'sensortype',
                       'datatype', 'sensorname', 'path',
                       'state_current', 'state_requested',
                       'actions_possible',
                       'actions_minor', 'actions_major', 'actions_critical',
                       't_minor_lower', 't_minor_upper',
                       't_major_lower', 't_major_upper',
                       't_critical_lower', 't_critical_upper',
                       'suppress', ]


class isensor(base.Resource):
    def __repr__(self):
        return "<isensor %s>" % self._info


class isensorManager(base.Manager):
    resource_class = isensor

    def list(self, ihost_id):
        path = '/v1/ihosts/%s/isensors' % ihost_id
        return self._list(path, "isensors")

    def list_by_sensorgroup(self, isensorgroup_id):
        path = '/v1/isensorgroups/%s/isensors' % isensorgroup_id
        return self._list(path, "isensors")

    def get(self, isensor_id):
        path = '/v1/isensors/%s' % isensor_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/isensors/'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute(key)
        return self._create(path, new)

    def delete(self, isensor_id):
        path = '/v1/isensors/%s' % isensor_id
        return self._delete(path)

    def update(self, isensor_id, patch):
        path = '/v1/isensors/%s' % isensor_id
        return self._update(path, patch)


def get_sensor_display_name(s):
    if s.sensorname:
        return s.sensorname
    else:
        return '(' + str(s.uuid)[-8:] + ')'
