# vim: tabstop=4 shiftwidth=4 softtabstop=4

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
# Copyright (c) 2015-2016 Wind River Systems, Inc.
#


import jsonpatch
import socket

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
from sysinv.common.constants import ACTIVE_LOAD_STATE
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common.rpc import common

LOG = log.getLogger(__name__)


class LoadPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class LoadImportType(base.APIBase):
    path_to_iso = wtypes.text
    path_to_sig = wtypes.text

    def __init__(self, **kwargs):
        self.fields = ['path_to_iso', 'path_to_sig']
        for k in self.fields:
            setattr(self, k, kwargs.get(k))


class Load(base.APIBase):
    """API representation of a Load

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of an
    Load.
    """

    id = int
    "The id of the Load"

    uuid = types.uuid
    "Unique UUID for this Load"

    state = wtypes.text
    "Represents the current state of the Load"

    software_version = wtypes.text
    "Represents the software version of the Load"

    compatible_version = wtypes.text
    "Represents the compatible version of the Load"

    required_patches = wtypes.text
    "A list of the patches required to upgrade to this load"

    def __init__(self, **kwargs):
        self.fields = objects.load.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_load, expand=True):

        load = Load(**rpc_load.as_dict())

        load_fields = ['id', 'uuid', 'state', 'software_version',
                       'compatible_version', 'required_patches'
                       ]

        if not expand:
            load.unset_fields_except(load_fields)

        load.links = [link.Link.make_link('self', pecan.request.host_url,
                                          'loads', load.uuid),
                      link.Link.make_link('bookmark',
                                          pecan.request.host_url,
                                          'loads', load.uuid, bookmark=True)
                      ]

        return load


class LoadCollection(collection.Collection):
    """API representation of a collection of Load objects."""

    loads = [Load]
    "A list containing Load objects"

    def __init__(self, **kwargs):
        self._type = 'loads'

    @classmethod
    def convert_with_links(cls, rpc_loads, limit, url=None,
                           expand=False, **kwargs):
        collection = LoadCollection()
        collection.loads = [Load.convert_with_links(p, expand)
                            for p in rpc_loads]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'LoadController'


class LoadController(rest.RestController):
    """REST controller for Loads."""

    _custom_actions = {
        'detail': ['GET'],
        'import_load': ['POST'],
    }

    def __init__(self):
        self._api_token = None

    def _get_loads_collection(self, marker, limit, sort_key, sort_dir,
                              expand=False, resource_url=None):

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.load.get_by_uuid(
                pecan.request.context,
                marker)

        loads = pecan.request.dbapi.load_get_list(
            limit, marker_obj,
            sort_key=sort_key,
            sort_dir=sort_dir)

        return LoadCollection.convert_with_links(loads, limit,
                                                 url=resource_url,
                                                 expand=expand,
                                                 sort_key=sort_key,
                                                 sort_dir=sort_dir)

    @wsme_pecan.wsexpose(LoadCollection, types.uuid, int, wtypes.text,
                         wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of loads."""

        return self._get_loads_collection(marker, limit, sort_key, sort_dir)

    @wsme_pecan.wsexpose(LoadCollection, types.uuid, int, wtypes.text,
                         wtypes.text)
    def detail(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of loads with detail."""

        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "loads":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['loads', 'detail'])
        return self._get_loads_collection(marker, limit, sort_key, sort_dir,
                                          expand, resource_url)

    @wsme_pecan.wsexpose(Load, unicode)
    def get_one(self, load_uuid):
        """Retrieve information about the given Load."""

        rpc_load = objects.load.get_by_uuid(
            pecan.request.context, load_uuid)

        return Load.convert_with_links(rpc_load)

    @staticmethod
    def _new_load_semantic_checks(load):
        if not load['software_version']:
            raise wsme.exc.ClientSideError(
                _("Load missing software_version key"))
        if load['state']:
            raise wsme.exc.ClientSideError(
                _("Can not set state during create"))

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Load, body=Load)
    def post(self, load):
        """Create a new Load."""
        # This method is only used to populate the inital load for the system
        # This is invoked during config_controller
        # Loads after the first are added via import
        loads = pecan.request.dbapi.load_get_list()

        if loads:
            raise wsme.exc.ClientSideError(_("Aborting. Active load exits."))

        patch = load.as_dict()
        self._new_load_semantic_checks(patch)
        patch['state'] = ACTIVE_LOAD_STATE

        try:
            new_load = pecan.request.dbapi.load_create(patch)

            # Controller-0 is added to the database before we add this load
            # so we must add a host_upgrade entry for (at least) controller-0
            hosts = pecan.request.dbapi.ihost_get_list()

            for host in hosts:
                values = dict()
                values['forihostid'] = host.id
                values['software_load'] = new_load.id
                values['target_load'] = new_load.id
                pecan.request.dbapi.host_upgrade_create(host.id,
                                                        new_load.software_version,
                                                        values)

        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data"))

        return load.convert_with_links(new_load)

    @wsme_pecan.wsexpose(Load, body=LoadImportType)
    def import_load(self, body):
        """Create a new Load."""

        # Only import loads on controller-0. This is required because the load
        # is only installed locally and we will be booting controller-1 from
        # this load during the upgrade.
        if socket.gethostname() != constants.CONTROLLER_0_HOSTNAME:
            raise wsme.exc.ClientSideError(_(
                "load-import rejected: A load can only be imported "
                "when %s is active." % constants.CONTROLLER_0_HOSTNAME))

        import_data = body.as_dict()
        path_to_iso = import_data['path_to_iso']
        path_to_sig = import_data['path_to_sig']

        try:
            new_load = pecan.request.rpcapi.start_import_load(
                pecan.request.context, path_to_iso, path_to_sig)
        except common.RemoteError as e:
            # Keep only the message raised originally by sysinv conductor.
            raise wsme.exc.ClientSideError(str(e.value))

        if new_load is None:
            raise wsme.exc.ClientSideError(
                _("Error importing load. Load not found"))

        try:
            pecan.request.rpcapi.import_load(
                pecan.request.context, path_to_iso, new_load)
        except common.RemoteError as e:
            # Keep only the message raised originally by sysinv conductor.
            raise wsme.exc.ClientSideError(str(e.value))

        return Load.convert_with_links(new_load)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(unicode, [LoadPatchType])
    @wsme_pecan.wsexpose(Load, unicode,
                         body=[LoadPatchType])
    def patch(self, load_id, patch):
        """Update an existing load."""

        # TODO (dsulliva)
        # This is a stub. We will need to place reasonable limits on what can
        # be patched as we add to the upgrade system. This portion of the API
        # likely will not be publicly accessible.
        rpc_load = objects.load.get_by_uuid(pecan.request.context, load_id)

        utils.validate_patch(patch)
        patch_obj = jsonpatch.JsonPatch(patch)

        try:
            load = Load(**jsonpatch.apply_patch(rpc_load.as_dict(), patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        fields = objects.load.fields

        for field in fields:
            if rpc_load[field] != getattr(load, field):
                rpc_load[field] = getattr(load, field)

        rpc_load.save()

        return Load.convert_with_links(rpc_load)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, unicode, status_code=204)
    def delete(self, load_id):
        """Delete a load."""

        load = pecan.request.dbapi.load_get(load_id)

        # make sure the load isn't in use by an upgrade
        try:
            upgrade = pecan.request.dbapi.software_upgrade_get_one()
        except exception.NotFound:
            pass
        else:
            if load.id == upgrade.to_load or load.id == upgrade.from_load:
                raise wsme.exc.ClientSideError(
                    _("Unable to delete load, load in use by upgrade"))

        # make sure the load isn't used by any hosts
        hosts = pecan.request.dbapi.host_upgrade_get_list()
        for host in hosts:
            if host.target_load == load.id or host.software_load == load.id:
                    raise wsme.exc.ClientSideError(_(
                        "Unable to delete load, load in use by host (id: %s)")
                        % host.forihostid)

        cutils.validate_load_for_delete(load)

        pecan.request.rpcapi.delete_load(pecan.request.context, load_id)
