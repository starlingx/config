#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan
from pecan import rest
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.common import utils as cutils


LOG = log.getLogger(__name__)
LOCK_NAME = 'RegistryImageController'


class RegistryImage(base.APIBase):
    """API representation of a docker registry image"""

    name = wtypes.text
    "The Docker image name"

    tag = wtypes.text
    "The Docker image tag"

    def __init__(self, **kwargs):
        self.fields = []

        # set fields manually since Registry image comes from docker registry
        # and not sysinv database
        for fp in ['name', 'tag']:
            self.fields.append(fp)
            setattr(self, fp, kwargs.get(fp, None))

    @classmethod
    def convert_with_links(cls, rpc_app, expand=True):
        app = RegistryImage(**rpc_app)
        if not expand:
            app.unset_fields_except(['name', 'tag'])

        return app


class RegistryImageCollection(collection.Collection):
    """API representation of a collection of registry images."""

    registry_images = [RegistryImage]
    "A list containing RegistryImage objects"

    def __init__(self, **kwargs):
        self._type = 'registry_images'

    @classmethod
    def convert_with_links(cls, rpc_apps, expand=False):
        collection = RegistryImageCollection()
        collection.registry_images = [RegistryImage.convert_with_links(n, expand)
                           for n in rpc_apps]
        return collection


class RegistryImageController(rest.RestController):
    """REST controller for Docker registry image."""

    @wsme_pecan.wsexpose(RegistryImageCollection, wtypes.text)
    def get_all(self, image_name=None):

        # no image_name provided, list images
        if image_name is None:
            images = pecan.request.rpcapi.docker_registry_image_list(pecan.request.context)
        # image_name provided, list tags of provided image
        else:
            images = pecan.request.rpcapi.docker_registry_image_tags(pecan.request.context, image_name)
        return RegistryImageCollection.convert_with_links(images)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, wtypes.text, status_code=204)
    def delete(self, image_name_and_tag):
        """Delete the image with the given name

        :param name: image name and tag of the form name:tag
        """

        if len(image_name_and_tag.split(":")) != 2:
            raise wsme.exc.ClientSideError(_("Image name and tag must be of form name:tag"))

        return pecan.request.rpcapi.docker_registry_image_delete(pecan.request.context, image_name_and_tag)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, wtypes.text)
    def post(self, garbage_collect=None):
        """Run the registry garbage collector"""
        if garbage_collect is not None:
            pecan.request.rpcapi.docker_registry_garbage_collect(pecan.request.context)
