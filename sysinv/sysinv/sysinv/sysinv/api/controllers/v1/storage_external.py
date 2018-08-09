# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright 2017 UnitedStack Inc.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#

import jsonpatch
import copy
import ast

from oslo_serialization import jsonutils

import pecan
from pecan import rest
import six

import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.api.controllers.v1.utils import SBApiHelper as api_helper
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common import log
from sysinv.openstack.common import uuidutils
from sysinv.openstack.common.gettextutils import _

LOG = log.getLogger(__name__)

HIERA_DATA = {
    'backend': [],
    constants.SB_SVC_CINDER: [],
    constants.SB_SVC_GLANCE: []
}


class StorageExternalPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class StorageExternal(base.APIBase):
    """API representation of an external storage.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    an external storage.
    """

    uuid = types.uuid
    "Unique UUID for this external storage backend."

    links = [link.Link]
    "A list containing a self link and associated storage backend links."

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    # Inherited attributes from the base class
    backend = wtypes.text
    "Represents the storage backend (file, lvm, ceph, or external)."

    name = wtypes.text
    "The name of the backend (to differentiate between multiple common backends)."

    state = wtypes.text
    "The state of the backend. It can be configured or configuring."

    task = wtypes.text
    "Current task of the corresponding cinder backend."

    services = wtypes.text
    "The openstack services that are supported by this storage backend."

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                                                  six.integer_types)}
    "Meta data for the storage backend"

    # Confirmation parameter [API-only field]
    confirmed = types.boolean
    "Represent confirmation that the backend operation should proceed"

    def __init__(self, **kwargs):
        defaults = {'uuid': uuidutils.generate_uuid(),
                    'state': constants.SB_STATE_CONFIGURING,
                    'task': constants.SB_TASK_NONE,
                    'capabilities': {},
                    'services': None,
                    'confirmed': False}

        self.fields = objects.storage_external.fields.keys()

        # 'confirmed' is not part of objects.storage_backend.fields
        # (it's an API-only attribute)
        self.fields.append('confirmed')

        # Set the value for any of the field
        for k in self.fields:
            setattr(self, k, kwargs.get(k, defaults.get(k)))

    @classmethod
    def convert_with_links(cls, rpc_storage_external, expand=True):

        stor_external = StorageExternal(**rpc_storage_external.as_dict())
        if not expand:
            stor_external.unset_fields_except(['uuid',
                                               'created_at',
                                               'updated_at',
                                               'isystem_uuid',
                                               'backend',
                                               'name',
                                               'state',
                                               'task',
                                               'services',
                                               'capabilities'])

        stor_external.links =\
            [link.Link.make_link('self', pecan.request.host_url,
                                 'storage_external',
                                 stor_external.uuid),
             link.Link.make_link('bookmark', pecan.request.host_url,
                                 'storage_external',
                                 stor_external.uuid,
                                 bookmark=True)]

        return stor_external


class StorageExternalCollection(collection.Collection):
    """API representation of a collection of external storage backends."""

    storage_external = [StorageExternal]
    "A list containing external storage backend objects."

    def __init__(self, **kwargs):
        self._type = 'storage_external'

    @classmethod
    def convert_with_links(cls, rpc_storage_external, limit, url=None,
                           expand=False, **kwargs):
        collection = StorageExternalCollection()
        collection.storage_external = \
                                 [StorageExternal.convert_with_links(p, expand)
             for p in rpc_storage_external]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'StorageExternalController'


class StorageExternalController(rest.RestController):
    """REST controller for external storage backend."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def _get_storage_external_collection(self, marker, limit, sort_key, sort_dir,
                                     expand=False, resource_url=None):

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.storage_external.get_by_uuid(
                pecan.request.context,
                marker)

        external_storage_backends = \
                                pecan.request.dbapi.storage_external_get_list(
                                    limit,
                                    marker_obj,
                                    sort_key=sort_key,
                                    sort_dir=sort_dir)

        return StorageExternalCollection \
            .convert_with_links(external_storage_backends,
                                limit,
                                url=resource_url,
                                expand=expand,
                                sort_key=sort_key,
                                sort_dir=sort_dir)

    @wsme_pecan.wsexpose(StorageExternalCollection, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of external storage backends."""

        return self._get_storage_external_collection(marker, limit, sort_key,
                                                 sort_dir)

    @wsme_pecan.wsexpose(StorageExternal, types.uuid)
    def get_one(self, storage_external_uuid):
        """Retrieve information about the given external storage backend."""

        rpc_storage_external = objects.storage_external.get_by_uuid(
            pecan.request.context,
            storage_external_uuid)
        return StorageExternal.convert_with_links(rpc_storage_external)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(StorageExternal, body=StorageExternal)
    def post(self, storage_external):
        """Create a new external storage backend."""

        try:
            storage_external = storage_external.as_dict()
            new_storage_external = _create(storage_external)

        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data: failed to create "
                                             "a storage_external record."))

        return StorageExternal.convert_with_links(new_storage_external)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [StorageExternalPatchType])
    @wsme_pecan.wsexpose(StorageExternal, types.uuid,
                         body=[StorageExternalPatchType])
    def patch(self, storexternal_uuid, patch):
        """Update the current external storage configuration."""
        return _patch(storexternal_uuid, patch)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, storageexternal_uuid):
        """Delete a backend."""

        return _delete(storageexternal_uuid)

#
# Common operation functions
#


def _get_options_string(storage_external):
    opt_str = ""
    caps = storage_external.get('capabilities', {})
    services = api_helper.getListFromServices(storage_external)

    # get the backend parameters
    backend_dict = caps.get("backend", {})
    be_str = ""
    for key in backend_dict:
        be_str += "\t%s: %s\n" % (key, backend_dict[key])

    # Only show the backend values if any are present
    if len(be_str) > 0:
        opt_str = "Backend:\n%s" % be_str

    # Get any supported service parameters
    for svc in constants.SB_EXTERNAL_SVCS_SUPPORTED:
        svc_dict = caps.get(svc, None)
        if svc_dict and svc in services:
            svc_str = ""
            for key in svc_dict:
                svc_str += "\t%s: %s\n" % (key, svc_dict.get(key, None))

            if len(svc_str) > 0:
                opt_str += "%s:\n%s" % (svc.title(), svc_str)

    if len(opt_str) > 0:
        opt_str = "Applying the following options:\n\n" + opt_str
    return opt_str


def _discover_and_validate_backend_hiera_data(caps_dict):
    # Currently there is no backend specific hiera_data for this backend
    pass


def _discover_and_validate_cinder_hiera_data(caps_dict):
    # Currently there is no backend specific hiera_data for this backend
    pass


def _discover_and_validate_glance_hiera_data(caps_dict):
    # Currently there is no backend specific hiera_data for this backend
    pass


def _check_backend_external(req, storage_external, confirmed=False):
    # check if it is running on secondary region
    system = pecan.request.dbapi.isystem_get_one()
    if system and system.capabilities.get('region_config') is not True:
        raise wsme.exc.ClientSideError("External backend can only be added on "
                                       "secondary region.")

    # check for the backend parameters
    capabilities = storage_external.get('capabilities', {})

    # Discover the latest hiera_data for the supported service
    _discover_and_validate_backend_hiera_data(capabilities)

    for k in HIERA_DATA['backend']:
        if not capabilities.get(k, None):
            raise wsme.exc.ClientSideError("Missing required backend "
                                           "parameter: %s" % k)

    # go through the service list and validate
    req_services = api_helper.getListFromServices(storage_external)
    for svc in req_services:
        if svc not in constants.SB_EXTERNAL_SVCS_SUPPORTED:
            raise wsme.exc.ClientSideError("Service %s is not supported for the"
                                           " %s backend" %
                                           (svc, constants.SB_TYPE_EXTERNAL))

        # Service is valid. Discover the latest hiera_data for the supported service
        discover_func = eval('_discover_and_validate_' + svc + '_hiera_data')
        discover_func(capabilities)

        # Service is valid. Check the params
        for k in HIERA_DATA[svc]:
            if not capabilities.get(k, None):
                raise wsme.exc.ClientSideError("Missing required %s service "
                                                   "parameter: %s" % (svc, k))

    # Update based on any discovered values
    storage_external['capabilities'] = capabilities

    # Check for confirmation
    if not confirmed:
        _options_str = _get_options_string(storage_external)
        raise wsme.exc.ClientSideError(
            _("%s\nWARNING : THIS OPERATION IS NOT REVERSIBLE AND CANNOT BE "
              "CANCELLED. \n\nPlease set the 'confirmed' field to execute "
              "this operation for the %s backend.") % (_options_str,
                                                       constants.SB_TYPE_EXTERNAL))


def _apply_backend_changes(op, sb_obj):
    if op in [constants.SB_API_OP_CREATE, constants.SB_API_OP_MODIFY]:
        services = api_helper.getListFromServices(sb_obj.as_dict())
        if constants.SB_SVC_CINDER in services:
            # Services are specified: Update backend + service actions
            api_helper.enable_backend(sb_obj,
                                      pecan.request.rpcapi.update_external_cinder_config)

        else:
            # If no service is specified or glance is the only service, this is a DB
            # only change => Set the state to configured
            pecan.request.dbapi.storage_external_update(
                sb_obj.uuid,
                {'state': constants.SB_STATE_CONFIGURED})

        # update shared_services
        s_s = utils.get_shared_services()
        shared_services = [] if s_s is None else ast.literal_eval(s_s)

        if services is not None:
            for s in services:
                if (s == constants.SB_SVC_CINDER and
                        constants.SERVICE_TYPE_VOLUME not in shared_services):
                    shared_services.append(constants.SERVICE_TYPE_VOLUME)

                if (s == constants.SB_SVC_GLANCE and
                        constants.SERVICE_TYPE_IMAGE not in shared_services):
                    shared_services.append(constants.SERVICE_TYPE_IMAGE)

        system = pecan.request.dbapi.isystem_get_one()

        system.capabilities['shared_services'] = str(shared_services)
        pecan.request.dbapi.isystem_update(system.uuid,
                                           {'capabilities': system.capabilities})

    elif op == constants.SB_API_OP_DELETE:
        pass


#
# Create
#

def _set_default_values(storage_external):
    defaults = {
        'backend': constants.SB_TYPE_EXTERNAL,
        'name': constants.SB_DEFAULT_NAMES[constants.SB_TYPE_EXTERNAL],
        'state': constants.SB_STATE_CONFIGURING,
        'task': constants.SB_TASK_NONE,
        'services': None,
        'capabilities': {}
    }

    sf = api_helper.set_backend_data(storage_external,
                                     defaults,
                                     HIERA_DATA,
                                     constants.SB_EXTERNAL_SVCS_SUPPORTED)
    return sf


def _create(storage_external):
    # Set the default for the storage backend
    storage_external = _set_default_values(storage_external)

    # Execute the common semantic checks for all backends, if a backend is
    # not present this will not return
    api_helper.common_checks(constants.SB_API_OP_CREATE,
                             storage_external)

    # Run the backend specific semantic checks
    _check_backend_external(constants.SB_API_OP_CREATE,
                            storage_external,
                            storage_external.pop('confirmed', False))

    # We have a valid configuration. create it.
    system = pecan.request.dbapi.isystem_get_one()
    storage_external['forisystemid'] = system.id
    storage_external_obj = pecan.request.dbapi.storage_external_create(storage_external)

    # Retreive the main StorageBackend object.
    storage_backend_obj = pecan.request.dbapi.storage_backend_get(storage_external_obj.id)

    # Enable the backend:
    _apply_backend_changes(constants.SB_API_OP_CREATE, storage_backend_obj)

    return storage_external_obj


#
# Update/Modify/Patch
#
def _hiera_data_semantic_checks(caps_dict):
    """ Validate each individual data value to make sure it's of the correct
        type and value.
    """
    pass


def _pre_patch_checks(storage_external_obj, patch_obj):
    storage_external_dict = storage_external_obj.as_dict()

    for p in patch_obj:
        if p['path'] == '/capabilities':
            patch_caps_dict = p['value']

            # Validate the change to make sure it valid
            _hiera_data_semantic_checks(patch_caps_dict)

            current_caps_dict = storage_external_dict.get('capabilities', {})
            for k in (set(current_caps_dict.keys()) -
                      set(patch_caps_dict.keys())):
                patch_caps_dict[k] = current_caps_dict[k]

            p['value'] = patch_caps_dict


def _patch(storexternal_uuid, patch):

    # Obtain current storage object.
    rpc_storexternal = objects.storage_external.get_by_uuid(
        pecan.request.context,
        storexternal_uuid)

    patch_obj = jsonpatch.JsonPatch(patch)
    for p in patch_obj:
        if p['path'] == '/capabilities':
            p['value'] = jsonutils.loads(p['value'])

    ostorexternal = copy.deepcopy(rpc_storexternal)

    # perform checks based on the current vs.requested modifications
    _pre_patch_checks(rpc_storexternal, patch_obj)

    # Obtain a storage object with the patch applied.
    try:
        storexternal_config = StorageExternal(**jsonpatch.apply_patch(
            rpc_storexternal.as_dict(),
            patch_obj))

    except utils.JSONPATCH_EXCEPTIONS as e:
        raise exception.PatchError(patch=patch, reason=e)

    # Update current storage object.
    for field in objects.storage_external.fields:
        if (field in storexternal_config.as_dict() and
                rpc_storexternal[field] != storexternal_config.as_dict()[field]):
            rpc_storexternal[field] = storexternal_config.as_dict()[field]

    # Obtain the fields that have changed.
    delta = rpc_storexternal.obj_what_changed()
    allowed_attributes = ['services', 'capabilities', 'task']
    for d in delta:
        if d not in allowed_attributes:
            raise wsme.exc.ClientSideError(
                _("Can not modify '%s' with this operation." % d))

    LOG.info("SYS_I orig storage_external: %s " % ostorexternal.as_dict())
    LOG.info("SYS_I new  storage_external: %s " % storexternal_config.as_dict())

    # Execute the common semantic checks for all backends, if backend is not
    # present this will not return
    api_helper.common_checks(constants.SB_API_OP_MODIFY,
                             rpc_storexternal.as_dict())

    # Run the backend specific semantic checks
    _check_backend_external(constants.SB_API_OP_MODIFY,
                            rpc_storexternal.as_dict(),
                            True)

    try:
        pecan.request.dbapi.storage_external_update(
                rpc_storexternal.uuid,
                {'state': constants.SB_STATE_CONFIGURING})

        rpc_storexternal.save()

        # Enable the backend changes:
        _apply_backend_changes(constants.SB_API_OP_MODIFY,
                               rpc_storexternal)

        return StorageExternal.convert_with_links(rpc_storexternal)

    except exception.HTTPNotFound:
        msg = _("StorExternal update failed: storexternal %s : "
                " patch %s"
                % (storexternal_config, patch))
        raise wsme.exc.ClientSideError(msg)


#
# Delete
#
def _delete(sb_uuid):
    # For now delete operation only deletes DB entry

    storage_external_obj = pecan.request.dbapi.storage_external_get(sb_uuid)

    # LOG.error("delete %s" % storage_external_obj.as_dict())

    # Execute the common semantic checks for all backends, if backend is not
    # present this will not return
    api_helper.common_checks(constants.SB_API_OP_DELETE,
                             storage_external_obj.as_dict())

    # Run the backend specific semantic checks
    _check_backend_external(constants.SB_API_OP_DELETE,
                        storage_external_obj.as_dict(),
                        True)

    # Enable the backend changes:
    _apply_backend_changes(constants.SB_API_OP_DELETE, storage_external_obj)

    try:
        pecan.request.dbapi.storage_backend_destroy(storage_external_obj.id)
    except exception.HTTPNotFound:
        msg = _("Deletion of backend %s failed" % storage_external_obj.uuid)
        raise wsme.exc.ClientSideError(msg)
