#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import base
from cgtsclient.v1 import options


class DeviceLabel(base.Resource):
    def __repr__(self):
        return "<DeviceLabel %s>" % self._info


class DeviceLabelManager(base.Manager):
    resource_class = DeviceLabel

    @staticmethod
    def _path(label_id=None):
        return '/v1/device_labels/%s' % label_id if label_id else \
            '/v1/device_labels'

    def list(self):
        path = '/v1/device_labels'
        return self._list(path, "device_labels")

    def get(self, uuid):
        path = '/v1/device_labels/%s' % uuid
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def assign(self, label, parameters=None):
        return self._create(options.build_url(self._path(), q=None,
                                              params=parameters), label)

    def remove(self, uuid):
        return self._delete(self._path(uuid))
