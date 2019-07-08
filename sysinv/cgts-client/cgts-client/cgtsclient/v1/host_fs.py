#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


class HostFs(base.Resource):
    def __repr__(self):
        return "<host_fs %s>" % self._info


class HostFsManager(base.Manager):
    resource_class = HostFs

    def list(self, ihost_id):
        path = '/v1/ihosts/%s/host_fs' % ihost_id
        return self._list(path, "host_fs")

    def get(self, host_fs_id):
        path = '/v1/host_fs/%s' % host_fs_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def update(self, host_fs_id, patch):
        path = '/v1/host_fs/%s' % host_fs_id

        return self._update(path, patch)

    def update_many(self, ihost_id, patch):
        path = '/v1/ihosts/%s/host_fs/update_many' % ihost_id
        resp, body = self.api.json_request(
            'PUT', path, body=patch)
        if body:
            return self.resource_class(self, body)


def _find_fs(cc, ihost, host_fs):
    if host_fs.isdigit():
        try:
            fs = cc.host_fs.get(host_fs)
        except exc.HTTPNotFound:
            raise exc.CommandError('Filesystem not found by id: %s'
                                   % host_fs)
        else:
            return fs
    else:
        fs_list = cc.host_fs.list(ihost.uuid)
        for fs in fs_list:
            if fs.name == host_fs:
                return fs
            if fs.uuid == host_fs:
                return fs
        else:
            raise exc.CommandError('Filesystem not found by name or '
                                   'uuid: %s' % host_fs)
