#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc
from cgtsclient.v1 import idisk as idisk_utils


CREATION_ATTRIBUTES = ['name', 'function', 'ihost_uuid', 'idisk_uuid',
                       'journal_location', 'journal_size_mib', 'tier_uuid']


class istor(base.Resource):
    def __repr__(self):
        return "<istor %s>" % self._info


class istorManager(base.Manager):
    resource_class = istor

    def list(self, ihost_id):
        path = '/v1/ihosts/%s/istors' % ihost_id
        return self._list(path, "istors")

    def get(self, istor_id):
        path = '/v1/istors/%s' % istor_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/istors'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(path, new)

    def delete(self, istor_id):
        path = '/v1/istors/%s' % istor_id
        return self._delete(path)

    def update(self, istor_id, patch):
        path = '/v1/istors/%s' % istor_id
        return self._update(path, patch)


def _get_disks(cc, ihost, stor):
    disks = cc.idisk.list(ihost.uuid)
    disk_list = [idisk_utils.get_disk_display_name(d) for d in disks if d.istor_uuid and d.istor_uuid == stor.uuid]
    stor.disks = disk_list
