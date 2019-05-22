#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient.v1 import options


class RegistryImage(base.Resource):
    def __repr__(self):
        return "<registry_image %s>" % self._info


class RegistryImageManager(base.Manager):
    resource_class = RegistryImage

    @staticmethod
    def _path(name=None):
        return '/v1/registry_image/%s' % name if name else '/v1/registry_image'

    def list(self):
        """Retrieve the list of images from the registry."""

        return self._list(self._path(), 'registry_images')

    def tags(self, image_name):
        """Retrieve the list of tags from the registry for a specified image.

        :param image_name: image name
        """
        path = options.build_url(self._path(), None, ['image_name=%s' % image_name])
        return self._list(path, 'registry_images')

    def delete(self, image_name_and_tag):
        """Delete registry image given name and tag

        :param image_name_and_tag: a string of the form name:tag
        """
        path = options.build_url(self._path(), None, ['image_name_and_tag=%s' % image_name_and_tag])
        return self._delete(path)

    def garbage_collect(self):
        path = options.build_url(self._path(), None, ['garbage_collect=%s' % True])
        return self._create(path, {})
