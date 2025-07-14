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
from sysinv.api.policies import registry_image as registry_policy
from sysinv.common import utils as cutils
from sysinv.common import exception
from sysinv.common import policy
from sysinv.openstack.common.rpc import common as rpc_common

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

    @wsme_pecan.wsexpose(RegistryImageCollection, int, wtypes.text)
    def get_all(self, filter_out_untagged=0, image_name=None):
        try:
            # no image_name provided, list images
            if image_name is None:
                images = pecan.request.rpcapi.docker_registry_image_list(
                             pecan.request.context, filter_out_untagged)
            # image_name provided, list tags of provided image
            else:
                images = pecan.request.rpcapi.docker_registry_image_tags(
                             pecan.request.context, image_name)
        # DockerRegistrySSLException and DockerRegistryAPIException
        # come in as RemoteError from the RPC handler
        except rpc_common.RemoteError as e:
            raise wsme.exc.ClientSideError(_(e.value))

        return RegistryImageCollection.convert_with_links(images)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, wtypes.text, status_code=204)
    def delete(self, image_name_and_tag):
        """Delete the image with the given name

        :param name: image name and tag of the form name:tag
        """

        if len(image_name_and_tag.split(":")) != 2:
            raise wsme.exc.ClientSideError(_("Image name and tag must be of "
                                             "form name:tag"))

        try:
            return pecan.request.rpcapi.docker_registry_image_delete(
                       pecan.request.context, image_name_and_tag)
        # DockerRegistrySSLException and DockerRegistryAPIException
        # come in as RemoteError from the RPC handler
        except rpc_common.RemoteError as e:
            raise wsme.exc.ClientSideError(_(e.value))

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, wtypes.text)
    def post(self, garbage_collect=None):
        """Run the registry garbage collector"""
        if garbage_collect is not None:
            try:
                pecan.request.rpcapi.docker_registry_garbage_collect(
                    pecan.request.context)
            # DockerRegistrySSLException and DockerRegistryAPIException
            # come in as RemoteError from the RPC handler
            except rpc_common.RemoteError as e:
                raise wsme.exc.ClientSideError(_(e.value))

    def enforce_policy(self, method_name, request):
        """Check policy rules for each action of this controller."""
        context_dict = request.context.to_dict()
        if method_name == "delete":
            policy.authorize(registry_policy.POLICY_ROOT % "delete", {}, context_dict)
        elif method_name in ["get_all", "get_one"]:
            policy.authorize(registry_policy.POLICY_ROOT % "get", {}, context_dict)
        elif method_name == "post":
            policy.authorize(registry_policy.POLICY_ROOT % "add", {}, context_dict)
        else:
            raise exception.PolicyNotFound()
