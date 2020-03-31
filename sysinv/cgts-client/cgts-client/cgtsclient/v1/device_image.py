#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import base
from cgtsclient.common import utils
from cgtsclient import exc


CREATION_ATTRIBUTES = [
    'bitstream_type', 'pci_vendor', 'pci_device',
    'bitstream_id', 'key_signature', 'revoke_key_id',
    'name', 'description', 'image_version', 'uuid']


class DeviceImage(base.Resource):
    def __repr__(self):
        return "<DeviceImage %s>" % self._info


class DeviceImageManager(base.Manager):
    resource_class = DeviceImage

    @staticmethod
    def _path(uuid=None):
        return '/v1/device_images/%s' % uuid if uuid else '/v1/device_images'

    def list(self):
        return self._list(self._path(), "device_images")

    def get(self, device_image_id):
        try:
            return self._list(self._path(device_image_id))[0]
        except IndexError:
            return None

    def create(self, file, **kwargs):
        data = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                data[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._upload_multipart(self._path(), file, data=data)

    def apply(self, device_image_id, labels=None):
        return self._update(self._path(device_image_id) + '?action=apply',
                            labels)

    def remove(self, device_image_id, labels=None):
        return self._update(self._path(device_image_id) + '?action=remove',
                            labels)

    def delete(self, device_image_id):
        return self._delete(self._path(device_image_id))


def _find_device_image(cc, device_image):
    if device_image.isdigit() and not utils.is_uuid_like(device_image):
        device_image_list = cc.device_image.list()
        for n in device_image_list:
            if str(n.id) == device_image:
                return n
        else:
            raise exc.CommandError('device image not found: %s' % device_image)
    elif utils.is_uuid_like(device_image):
        try:
            h = cc.device_image.get(device_image)
        except exc.HTTPNotFound:
            raise exc.CommandError('device image not found: %s' % device_image)
        else:
            return h
    else:
        device_image_list = cc.device_image.list()
        for n in device_image_list:
            if n.name == device_image:
                return n
        else:
            raise exc.CommandError('device image not found: %s' % device_image)
