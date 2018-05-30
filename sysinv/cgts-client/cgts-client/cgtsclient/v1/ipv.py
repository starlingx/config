#
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc
from cgtsclient.v1 import idisk as idisk_utils


CREATION_ATTRIBUTES = ['ihost_uuid', 'ilvg_uuid',
                       'disk_or_part_uuid', 'pv_type']


class ipv(base.Resource):
    def __repr__(self):
        return "<ipv %s>" % self._info


class ipvManager(base.Manager):
    resource_class = ipv

    def list(self, ihost_id):
        path = '/v1/ihosts/%s/ipvs' % ihost_id
        return self._list(path, "ipvs")

    def get(self, ipv_id):
        path = '/v1/ipvs/%s' % ipv_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/ipvs'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(path, new)

    def delete(self, ipv_id):
        path = '/v1/ipvs/%s' % ipv_id
        return self._delete(path)

    def update(self, ipv_id, patch):
        path = '/v1/ipvs/%s' % ipv_id
        return self._update(path, patch)


def _get_disks(cc, ihost, pv):
    disks = cc.idisk.list(ihost.uuid)
    disk_list = [idisk_utils.get_disk_display_name(d)
                 for d in disks
                 if d.ipv_uuid and d.ipv_uuid == pv.uuid]
    pv.disks = disk_list


def _find_ipv(cc, ihost, ipv):
    if ipv.isdigit():
        try:
            pv = cc.ipv.get(ipv)
        except exc.HTTPNotFound:
            raise exc.CommandError('physical volume not found: %s' % ipv)
        else:
            return pv
    else:
        pvlist = cc.ipv.list(ihost.uuid)
        for pv in pvlist:
            if pv.uuid == ipv:
                return pv
        else:
            raise exc.CommandError('physical volume not found: %s' % ipv)
