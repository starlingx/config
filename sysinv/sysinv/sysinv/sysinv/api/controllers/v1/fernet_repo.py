#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


import pecan
from pecan import rest
from six.moves import http_client
import wsme
import wsmeext.pecan as wsme_pecan
from wsme import types as wtypes

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.common import utils as cutils

LOG = log.getLogger(__name__)

LOCK_NAME = 'FernetKeyController'


class FernetKey(base.APIBase):
    """API representation of a Fernet Key.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a Fernet Key.
    """

    uuid = types.uuid
    "The UUID of the fernet key"

    id = int
    "The id of the fernet key"

    key = wtypes.text
    "Represents the fernet key"

    links = [link.Link]
    "A list containing a self link and associated key links"

    def __init__(self, **kwargs):
        self.fields = ["id", "key"]
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def from_dict(cls, obj_dict):
        """Convert a dictionary to an API object."""
        return cls(**obj_dict)

    @classmethod
    def convert_with_links(cls, rpc_fernet, expand=True):
        repo = FernetKey.from_dict(rpc_fernet)
        return repo


class FernetKeyCollection(collection.Collection):
    """API representation of a collection of fernet key."""

    keys = [FernetKey]
    "A list containing fernet key objects"

    def __init__(self, **kwargs):
        self._type = 'keys'

    @classmethod
    def convert_with_links(cls, keys, **kwargs):
        keys = sorted(keys, key=lambda x: x['id'])
        collection = FernetKeyCollection()
        collection.keys = [FernetKey.convert_with_links(k)
                           for k in keys]
        return collection


class FernetKeyController(rest.RestController):
    """REST controller for Fernet Keys."""

    def __init__(self):
        self._api_token = None

    @wsme_pecan.wsexpose(FernetKeyCollection)
    def get_all(self):
        """Provides all keys under the Fernet Repo"""
        try:
            output = pecan.request.rpcapi.get_fernet_keys(
                pecan.request.context)
        except Exception as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_(
                "Unable to perform fernet key query."))

        return FernetKeyCollection.convert_with_links(output)

    @wsme_pecan.wsexpose(FernetKey, wtypes.text)
    def get_one(self, key):
        """Provide a key under the Fernet Repo"""
        try:
            success, output = pecan.request.rpcapi.get_fernet_keys(
                pecan.request.context, key_id=int(key))
        except Exception as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_(
                "Unable to perform fernet key query."))
        return FernetKey.convert_with_links(output[0])

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, body=[FernetKey],
                         status_code=http_client.CREATED)
    def post(self, keys=None):
        key_list = None
        if keys:
            key_list = [k.as_dict() for k in keys]
        try:
            pecan.request.rpcapi.update_fernet_repo(pecan.request.context,
                                                    key_list)
        except Exception as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_(
                "Unable to create fernet keys."))

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, body=[FernetKey],
                         status_code=http_client.ACCEPTED)
    def put(self, keys):
        key_list = [k.as_dict() for k in keys]
        try:
            pecan.request.rpcapi.update_fernet_repo(pecan.request.context,
                                                    key_list)
        except Exception as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_(
                "Unable to update fernet keys."))
