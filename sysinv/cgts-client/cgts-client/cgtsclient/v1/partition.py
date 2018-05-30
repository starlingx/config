#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['ihost_uuid', 'idisk_uuid', 'size_mib', 'type_guid']


class partition(base.Resource):
    def __repr__(self):
        return "<partition %s>" % self._info


class partitionManager(base.Manager):
    resource_class = partition

    def list(self, ihost_id, idisk_id=None):
        if idisk_id:
            path = '/v1/ihosts/%s/idisks/%s/partitions' % (ihost_id, idisk_id)
        else:
            path = '/v1/ihosts/%s/partitions' % ihost_id
        return self._list(path, "partitions")

    def get(self, partition_id):
        path = '/v1/partitions/%s' % partition_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/partitions/'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute(key)
        return self._create(path, new)

    def delete(self, partition_id):
        path = '/v1/partitions/%s' % partition_id
        return self._delete(path)

    def update(self, partition_id, patch):
        path = '/v1/partitions/%s' % partition_id

        return self._update(path, patch)


def _find_partition(cc, ihost, partition, idisk=None):
    if idisk:
        part_list = cc.partition.list(ihost.uuid, idisk.uuid)
    else:
        part_list = cc.partition.list(ihost.uuid)
    for p in part_list:
        if p.device_path == partition:
            return p
        if p.uuid == partition:
            return p
    else:
        return None
