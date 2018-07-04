#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['numa_node', 'capabilities', 'ihost_uuid']


class inode(base.Resource):
    def __repr__(self):
        return "<inode %s>" % self._info


class inodeManager(base.Manager):
    resource_class = inode

    def list(self, ihost_id):
        path = '/v1/ihosts/%s/inodes' % ihost_id
        return self._list(path, "inodes")

    def get(self, inode_id):
        path = '/v1/inodes/%s' % inode_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/inodes'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(path, new)

    def delete(self, inode_id):
        path = '/v1/inodes/%s' % inode_id
        return self._delete(path)

    def update(self, inode_id, patch):
        path = '/v1/inodes/%s' % inode_id
        return self._update(path, patch)
