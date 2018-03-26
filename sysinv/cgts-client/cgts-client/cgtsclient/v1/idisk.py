#
# Copyright (c) 2013-2014, 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient.common import utils
from cgtsclient import exc


CREATION_ATTRIBUTES = ['ihost_uuid', 'istor_uuid', 'serial_id', 'device_node',
                       'device_num', 'device_type', 'device_path',
                       'capabilities', 'size_mib']


class idisk(base.Resource):
    def __repr__(self):
        return "<idisk %s>" % self._info


class idiskManager(base.Manager):
    resource_class = idisk

    def list(self, ihost_id):
        path = '/v1/ihosts/%s/idisks' % ihost_id
        return self._list(path, "idisks")

    def get(self, idisk_id):
        path = '/v1/idisks/%s' % idisk_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/idisks/'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute(key)
        return self._create(path, new)

    def delete(self, idisk_id):
        path = '/v1/idisks/%s' % idisk_id
        return self._delete(path)

    def update(self, idisk_id, patch):
        path = '/v1/idisks/%s' % idisk_id

        return self._update(path, patch)


def get_disk_display_name(d):
    if d.device_node:
        return d.device_node
    else:
        return '(' + str(d.uuid)[-8:] + ')'


def _find_disk(cc, ihost, idisk):
    if utils.is_uuid_like(idisk):
        try:
            disk = cc.idisk.get(idisk)
        except exc.HTTPNotFound:
            return None
        else:
            return disk
    else:
        disklist = cc.idisk.list(ihost.uuid)
        for disk in disklist:
            if disk.device_node == idisk or disk.device_path == idisk:
                return disk
        else:
            return None
