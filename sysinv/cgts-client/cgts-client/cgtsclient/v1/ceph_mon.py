#
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc

CREATION_ATTRIBUTES = ['ihost_uuid']


class CephMon(base.Resource):
    def __repr__(self):
        return "<ceph_mon %s>" % self._info


class CephMonManager(base.Manager):
    resource_class = CephMon

    # @staticmethod
    # def _path(id=None):
    #     return '/v1/ceph_mon/%s' % id if id else '/v1/ceph_mon'
    #
    # def list(self):
    #     return self._list(self._path(), "ceph_mon")

    def list(self, ihost_id=None):
        if ihost_id:
            path = '/v1/ihosts/%s/ceph_mon' % ihost_id
        else:
            path = '/v1/ceph_mon'
        return self._list(path, "ceph_mon")

    def get(self, ceph_mon_uuid):
        path = '/v1/ceph_mon/%s' % ceph_mon_uuid
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/ceph_mon'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(path, new)

    def delete(self, host_uuid):
        path = '/v1/ceph_mon/%s' % host_uuid
        return self._delete(path)

    def update(self, ceph_mon_id, patch):
        path = '/v1/ceph_mon/%s' % ceph_mon_id
        return self._update(path, patch)

    def ip_addresses(self):
        path = '/v1/ceph_mon/ip_addresses'
        return self._json_get(path, {})


def ceph_mon_add(cc, args, ihost_uuid):
    data = dict()

    if not vars(args).get('confirmed', None):
        return

    ceph_mon_gib = vars(args).get('ceph_mon_gib', None)

    if ceph_mon_gib:
        data['ceph_mon_gib'] = ceph_mon_gib

    data['ihost_uuid'] = ihost_uuid
    ceph_mon = cc.ceph_mon.create(**data)
    if ceph_mon and len(ceph_mon.ceph_mon):
        suuid = ceph_mon.ceph_mon[0].get('uuid', '')
    else:
        raise exc.CommandError(
            "Created ceph_mon has invalid data.")
    try:
        ceph_mon = cc.ceph_mon.get(suuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created ceph mon UUID not found: %s' % suuid)
