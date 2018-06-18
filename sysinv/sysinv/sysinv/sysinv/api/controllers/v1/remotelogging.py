# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright 2013 UnitedStack Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#


import jsonpatch
import re

import pecan
from pecan import rest

import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log

from netaddr import IPAddress, AddrFormatError


LOG = log.getLogger(__name__)

logTransportEnum = wtypes.Enum(str, 'udp', 'tcp', 'tls')
REMOTELOGGING_RPC_TIMEOUT = 180


class RemoteLoggingPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return ['/ip_address']


class RemoteLogging(base.APIBase):
    """API representation of remote logging.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a remotelogging.
    """

    uuid = types.uuid
    "Unique UUID for this remotelogging"

    ip_address = types.ipaddress
    "Represents the ip_address of the remote logging server"

    enabled = types.boolean
    "Enables or disables the remote logging of the system"

    transport = wtypes.Enum(str, 'udp', 'tcp', 'tls')
    "Represent the transport protocol of the remote logging server"

    port = int
    "The port number that the remote logging server is listening on"

    key_file = wtypes.text
    "Represent the TLS key_file of the remote logging server"

    action = wtypes.text
    "Represent the action on the remotelogging."

    links = [link.Link]
    "A list containing a self link and associated remotelogging links"

    isystem_uuid = types.uuid
    "The UUID of the system this remotelogging belongs to"

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    def __init__(self, **kwargs):
        self.fields = objects.remotelogging.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        # 'action' is not part of objects.remotelogging.fields
        # (it's an API-only attribute)
        self.fields.append('action')
        setattr(self, 'action', kwargs.get('action', None))

    @classmethod
    def convert_with_links(cls, rpc_remotelogging, expand=True):

        remotelogging = RemoteLogging(**rpc_remotelogging.as_dict())
        if not expand:
            remotelogging.unset_fields_except(['uuid',
                                     'ip_address',
                                     'enabled',
                                     'transport',
                                     'port',
                                     'key_file',
                                     'isystem_uuid',
                                     'created_at',
                                     'updated_at'])

        remotelogging.links = [link.Link.make_link('self', pecan.request.host_url,
                                         'remoteloggings', remotelogging.uuid),
                               link.Link.make_link('bookmark',
                                         pecan.request.host_url,
                                         'remoteloggings', remotelogging.uuid,
                                         bookmark=True)
                               ]

        return remotelogging


class RemoteLoggingCollection(collection.Collection):
    """API representation of a collection of remoteloggings."""

    remoteloggings = [RemoteLogging]
    "A list containing RemoteLogging objects"

    def __init__(self, **kwargs):
        self._type = 'remoteloggings'

    @classmethod
    def convert_with_links(cls, remoteloggings, limit, url=None,
                           expand=False, **kwargs):
        collection = RemoteLoggingCollection()
        collection.remoteloggings = [RemoteLogging.convert_with_links(p, expand)
                            for p in remoteloggings]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


##############
# UTILS
##############
def _check_remotelogging_data(op, remotelogging):
    # Get data
    ip_address = remotelogging['ip_address']

    # Validate ip_address
    if ip_address:
            try:
                IPAddress(ip_address)

            except (AddrFormatError, ValueError):
                raise wsme.exc.ClientSideError(_(
                        "Invalid remote logging server %s "
                        "Please configure a valid "
                        "IP address.") % (ip_address))

    else:
        raise wsme.exc.ClientSideError(_("No remote logging provided."))

    remotelogging['ip_address'] = ip_address

    # Validate port
    port = remotelogging['port']

    path_pattern = re.compile("^[0-9]+")
    if not path_pattern.match(str(remotelogging['port'])):
        raise wsme.exc.ClientSideError(_("Invalid port: %s") % port)

    remotelogging['port'] = port

    return remotelogging


LOCK_NAME = 'RemoteLoggingController'


class RemoteLoggingController(rest.RestController):
    """REST controller for remoteloggings."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def _get_remoteloggings_collection(self, marker, limit, sort_key,
                             sort_dir, expand=False, resource_url=None):

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.remotelogging.get_by_uuid(pecan.request.context,
                                                  marker)

        remoteloggings = pecan.request.dbapi.remotelogging_get_list(limit,
                                                    marker_obj,
                                                     sort_key=sort_key,
                                                     sort_dir=sort_dir)

        return RemoteLoggingCollection.convert_with_links(remoteloggings,
                                                          limit,
                                                          url=resource_url,
                                                          expand=expand,
                                                          sort_key=sort_key,
                                                          sort_dir=sort_dir)

    @wsme_pecan.wsexpose(RemoteLoggingCollection, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of remoteloggings. Only one per system"""

        return self._get_remoteloggings_collection(marker, limit,
                                                   sort_key, sort_dir)

    @wsme_pecan.wsexpose(RemoteLoggingCollection, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of remoteloggings with detail."""
        # NOTE(lucasagomes): /detail should only work against collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "remoteloggings":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['remoteloggings', 'detail'])
        return self._get_remoteloggings_collection(marker, limit,
                                                   sort_key, sort_dir,
                                                   expand, resource_url)

    @wsme_pecan.wsexpose(RemoteLogging, types.uuid)
    def get_one(self, remotelogging_uuid):
        """Retrieve information about the given remotelogging."""
        rpc_remotelogging = objects.remotelogging.get_by_uuid(pecan.request.context, remotelogging_uuid)
        return RemoteLogging.convert_with_links(rpc_remotelogging)

    @wsme_pecan.wsexpose(RemoteLogging, body=RemoteLogging)
    def post(self, remotelogging):
        """Create a new remotelogging."""
        raise exception.OperationNotPermitted

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [RemoteLoggingPatchType])
    @wsme_pecan.wsexpose(RemoteLogging, types.uuid,
                         body=[RemoteLoggingPatchType])
    def patch(self, remotelogging_uuid, patch):
        """Update the remotelogging configuration."""

        rpc_remotelogging = objects.remotelogging.get_by_uuid(pecan.request.context, remotelogging_uuid)

        action = None
        for p in patch:
            if '/action' in p['path']:
                value = p['value']
                patch.remove(p)
                if value in (constants.APPLY_ACTION, constants.INSTALL_ACTION):
                    action = value
                break

        patch_obj = jsonpatch.JsonPatch(patch)

        state_rel_path = ['/uuid', '/id']
        if any(p['path'] in state_rel_path for p in patch_obj):
            raise wsme.exc.ClientSideError(_("The following fields can not be "
                                             "modified: %s" %
                                             state_rel_path))

        try:
            remotelogging = RemoteLogging(**jsonpatch.apply_patch(rpc_remotelogging.as_dict(),
                                               patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        remotelogging = _check_remotelogging_data("modify", remotelogging.as_dict())

        try:
            # Update only the fields that have changed
            for field in objects.remotelogging.fields:
                if rpc_remotelogging[field] != remotelogging[field]:
                    rpc_remotelogging[field] = remotelogging[field]

            rpc_remotelogging.save()

            if action == constants.APPLY_ACTION:
                # perform rpc to conductor to perform config apply
                pecan.request.rpcapi.update_remotelogging_config(pecan.request.context, timeout=REMOTELOGGING_RPC_TIMEOUT)

            return RemoteLogging.convert_with_links(rpc_remotelogging)

        except exception.HTTPNotFound:
            msg = _("remotelogging update failed: %s : patch %s"
                    % (remotelogging['ip_address'], patch))
            raise wsme.exc.ClientSideError(msg)

    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, remotelogging_uuid):
        """Delete a remotelogging."""
        raise exception.OperationNotPermitted
