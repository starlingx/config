#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import base


class DeviceImageState(base.Resource):
    def __repr__(self):
        return "<DeviceImageState %s>" % self._info


class DeviceImageStateManager(base.Manager):
    resource_class = DeviceImageState

    @staticmethod
    def _path(uuid=None):
        return '/v1/device_image_state/%s' % uuid if uuid else '/v1/device_image_state'

    def list(self):
        return self._list(self._path(), "device_image_state")
