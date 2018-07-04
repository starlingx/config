#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['lvm_vg_name', 'ihost_uuid']


class ilvg(base.Resource):
    def __repr__(self):
        return "<ilvg %s>" % self._info


class ilvgManager(base.Manager):
    resource_class = ilvg

    def list(self, ihost_id):
        path = '/v1/ihosts/%s/ilvgs' % ihost_id
        return self._list(path, "ilvgs")

    def get(self, ilvg_id):
        path = '/v1/ilvgs/%s' % ilvg_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/ilvgs'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)

        return self._create(path, new)

    def delete(self, ilvg_id):
        path = '/v1/ilvgs/%s' % ilvg_id
        return self._delete(path)

    def update(self, ilvg_id, patch):
        path = '/v1/ilvgs/%s' % ilvg_id

        return self._update(path, patch)


def _find_ilvg(cc, ihost, ilvg):
    if ilvg.isdigit():
        try:
            lvg = cc.ilvg.get(ilvg)
        except exc.HTTPNotFound:
            raise exc.CommandError('Local volume group not found by id: %s'
                                   % ilvg)
        else:
            return lvg
    else:
        lvglist = cc.ilvg.list(ihost.uuid)
        for lvg in lvglist:
            if lvg.lvm_vg_name == ilvg:
                return lvg
            if lvg.uuid == ilvg:
                return lvg
        else:
            raise exc.CommandError('Local volume group not found by name or '
                                   'uuid: %s' % ilvg)
