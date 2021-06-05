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
# Copyright (c) 2013-2021 Wind River Systems, Inc.
# Copyright (c) 2020 Intel Corporation, Inc
#

import copy
import jsonpatch
import pecan
from pecan import rest
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from oslo_serialization import jsonutils
from oslo_utils import uuidutils

from sysinv._i18n import _
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

LOG = log.getLogger(__name__)

HIERA_DATA = {
    'backend': [],
    constants.SB_SVC_GLANCE: [],
    constants.SB_SVC_CINDER: [],
    constants. SB_SVC_NOVA: [],
}


class StorageCephRookPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class StorageCephRook(base.APIBase):
    """API representation of a file storage.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    rook ceph storage.
    """

    uuid = types.uuid
    "Unique UUID for this rook ceph storage backend."

    links = [link.Link]
    "A list containing a self link and associated storage backend links."

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    # Inherited attributes from the base class
    backend = wtypes.text
    "Represents the storage backend (file, lvm, or ceph)."

    state = wtypes.text
    "The state of the backend. It can be configured or configuring."

    name = wtypes.text
    "The name of the backend (to differentiate between multiple common backends)."

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

    # Network parameter: [API-only field]
    network = wtypes.text
    "The network for backend components"

    def __init__(self, **kwargs):
        defaults = {'uuid': uuidutils.generate_uuid(),
                    'state': constants.SB_STATE_CONFIGURING,
                    'task': constants.SB_TASK_NONE,
                    'capabilities': {},
                    'services': None,
                    'confirmed': False}

        self.fields = list(objects.storage_ceph_rook.fields.keys())

        # 'confirmed' is not part of objects.storage_backend.fields
        # (it's an API-only attribute)
        self.fields.append('confirmed')

        # Set the value for any of the field
        for k in self.fields:
            setattr(self, k, kwargs.get(k, defaults.get(k)))

    @classmethod
    def convert_with_links(cls, rpc_storage_ceph_rook, expand=True):

        stor_ceph_rook = StorageCephRook(**rpc_storage_ceph_rook.as_dict())
        if not expand:
            stor_ceph_rook.unset_fields_except(['uuid',
                                           'created_at',
                                           'updated_at',
                                           'isystem_uuid',
                                           'backend',
                                           'name',
                                           'state',
                                           'task',
                                           'services',
                                           'capabilities'])

        stor_ceph_rook.links =\
            [link.Link.make_link('self', pecan.request.host_url,
                                 'storage_ceph_rook',
                                 stor_ceph_rook.uuid),
             link.Link.make_link('bookmark', pecan.request.host_url,
                                 'storage_ceph_rook',
                                 stor_ceph_rook.uuid,
                                 bookmark=True)]

        return stor_ceph_rook


class StorageCephRookCollection(collection.Collection):
    """API representation of a collection of file storage backends."""

    storage_ceph_rook = [StorageCephRook]
    "A list containing rook ceph storage backend objects."

    def __init__(self, **kwargs):
        self._type = 'storage_ceph_rook'

    @classmethod
    def convert_with_links(cls, rpc_storage_ceph_rook, limit, url=None,
                           expand=False, **kwargs):
        collection = StorageCephRookCollection()
        collection.storage_ceph_rook = \
                                 [StorageCephRook.convert_with_links(p, expand)
             for p in rpc_storage_ceph_rook]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'StorageCephRookController'


class StorageCephRookController(rest.RestController):
    """REST controller for rook ceph storage backend."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def _get_storage_ceph_rook_collection(self, marker, limit, sort_key, sort_dir,
                                     expand=False, resource_url=None):

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.storage_ceph_rook.get_by_uuid(
                pecan.request.context,
                marker)

        ceph_rook_storage_backends = \
                                pecan.request.dbapi.storage_ceph_rook_get_list(
                                    limit,
                                    marker_obj,
                                    sort_key=sort_key,
                                    sort_dir=sort_dir)

        return StorageCephRookCollection \
            .convert_with_links(ceph_rook_storage_backends,
                                limit,
                                url=resource_url,
                                expand=expand,
                                sort_key=sort_key,
                                sort_dir=sort_dir)

    @wsme_pecan.wsexpose(StorageCephRookCollection, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of ceph rook storage backends."""

        return self._get_storage_ceph_rook_collection(marker, limit, sort_key,
                                                 sort_dir)

    @wsme_pecan.wsexpose(StorageCephRook, types.uuid)
    def get_one(self, storage_ceph_rook_uuid):
        """Retrieve information about the given ceph rook storage backend."""

        rpc_storage_ceph_rook = objects.storage_ceph_rook.get_by_uuid(
            pecan.request.context,
            storage_ceph_rook_uuid)
        return StorageCephRook.convert_with_links(rpc_storage_ceph_rook)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(StorageCephRook, body=StorageCephRook)
    def post(self, storage_ceph_rook):
        """Create a new rook ceph storage backend."""

        try:
            storage_ceph_rook = storage_ceph_rook.as_dict()
            new_storage_ceph_rook = _create(storage_ceph_rook)

        except exception.SysinvException:
            LOG.exception()
            raise wsme.exc.ClientSideError(_("Invalid data: failed to create "
                                             "a storage_ceph_rook record."))

        return StorageCephRook.convert_with_links(new_storage_ceph_rook)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [StorageCephRookPatchType])
    @wsme_pecan.wsexpose(StorageCephRook, types.uuid,
                         body=[StorageCephRookPatchType])
    def patch(self, storcephrook_uuid, patch):
        """Update the current ceph rook storage configuration."""
        return _patch(storcephrook_uuid, patch)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, storagecephrook_uuid):
        """Delete a backend."""

        return _delete(storagecephrook_uuid)

#
# Common operation functions
#


def _get_options_string(storage_file):
    opt_str = ""
    caps = storage_file.get('capabilities', {})
    services = api_helper.getListFromServices(storage_file)

    # get the backend parameters
    backend_dict = caps.get("backend", {})
    be_str = ""
    for key in backend_dict:
        be_str += "\t%s: %s\n" % (key, backend_dict[key])

    # Only show the backend values if any are present
    if len(be_str) > 0:
        opt_str = "Backend:\n%s" % be_str

    # Get any supported service parameters
    for svc in constants.SB_CEPH_ROOK_SVCS_SUPPORTED:
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


def _discover_and_validate_glance_hiera_data(caps_dict):
    # Currently there is no backend specific hiera_data for this backend
    pass


def _discover_and_validate_cinder_hiera_data(caps_dict):
    # Currently there is no backend specific hiera_data for this backend
    pass


def _discover_and_validate_nova_hiera_data(caps_dict):
    # Currently there is no backend specific hiera_data for this backend
    pass


def _check_backend_ceph_rook(req, storage_ceph_rook, confirmed=False):
    # check for the backend parameters
    capabilities = storage_ceph_rook.get('capabilities', {})

    # Discover the latest hiera_data for the supported service
    _discover_and_validate_backend_hiera_data(capabilities)

    for k in HIERA_DATA['backend']:
        if not capabilities.get(k, None):
            raise wsme.exc.ClientSideError("Missing required backend "
                                           "parameter: %s" % k)

    # go through the service list and validate
    req_services = api_helper.getListFromServices(storage_ceph_rook)
    for svc in req_services:
        if svc not in constants.SB_CEPH_ROOK_SVCS_SUPPORTED:
            raise wsme.exc.ClientSideError("Service %s is not supported for the"
                                           " %s backend" %
                                           (svc, constants.SB_TYPE_FILE))

        # Service is valid. Discover the latest hiera_data for the supported service
        discover_func = eval('_discover_and_validate_' + svc + '_hiera_data')
        discover_func(capabilities)

        # Service is valid. Check the params
        for k in HIERA_DATA[svc]:
            if not capabilities.get(k, None):
                raise wsme.exc.ClientSideError("Missing required %s service "
                                                   "parameter: %s" % (svc, k))

    # Update based on any discovered values
    storage_ceph_rook['capabilities'] = capabilities
    storage_ceph_rook['state'] = constants.SB_STATE_CONFIGURED
    storage_ceph_rook['task'] = constants.SB_TASK_NONE

    # Check for confirmation
    if not confirmed:
        _options_str = _get_options_string(storage_ceph_rook)
        raise wsme.exc.ClientSideError(
            _("%s\nWARNING : THIS OPERATION IS NOT REVERSIBLE AND CANNOT BE "
              "CANCELLED. \n\nPlease set the 'confirmed' field to execute "
              "this operation for the %s backend.") % (_options_str,
                                                       constants.SB_TYPE_CEPH_ROOK))


def _apply_backend_changes(op, sb_obj):
    if op == constants.SB_API_OP_CREATE:
        # This is a DB only change => Set the state to configured
        pecan.request.dbapi.storage_ceph_rook_update(
            sb_obj.uuid,
            {'state': constants.SB_STATE_CONFIGURED})

        services = api_helper.getListFromServices(sb_obj.as_dict())
        pecan.request.rpcapi.update_ceph_rook_config(
                                                pecan.request.context,
                                                sb_obj.get('uuid'),
                                                services)

    elif op == constants.SB_API_OP_MODIFY:
        pass

    elif op == constants.SB_API_OP_DELETE:
        pass


#
# Create
#

def _set_default_values(storage_ceph_rook):
    defaults = {
        'backend': constants.SB_TYPE_CEPH_ROOK,
        'name': constants.SB_DEFAULT_NAMES[constants.SB_TYPE_CEPH_ROOK],
        'state': constants.SB_STATE_CONFIGURING,
        'task': constants.SB_TASK_NONE,
        'services': None,
        'capabilities': {}
    }

    sf = api_helper.set_backend_data(storage_ceph_rook,
                                     defaults,
                                     HIERA_DATA,
                                     constants.SB_CEPH_ROOK_SVCS_SUPPORTED)
    return sf


def _create(storage_ceph_rook):
    # Set the default for the storage backend
    storage_ceph_rook = _set_default_values(storage_ceph_rook)

    # Execute the common semantic checks for all backends, if a backend is
    # not present this will not return
    api_helper.common_checks(constants.SB_API_OP_CREATE,
                             storage_ceph_rook)

    # Run the backend specific semantic checks
    _check_backend_ceph_rook(constants.SB_API_OP_CREATE,
                        storage_ceph_rook,
                        storage_ceph_rook.pop('confirmed', False))

    # We have a valid configuration. create it.
    system = pecan.request.dbapi.isystem_get_one()
    storage_ceph_rook['forisystemid'] = system.id
    storage_ceph_rook_obj = pecan.request.dbapi.storage_ceph_rook_create(storage_ceph_rook)

    # Retreive the main StorageBackend object.
    storage_backend_obj = pecan.request.dbapi.storage_backend_get(storage_ceph_rook_obj.id)

    # Only apply runtime manifests if at least one controller is unlocked and
    # available/degraded.
    controller_hosts = pecan.request.dbapi.ihost_get_by_personality(
            constants.CONTROLLER)
    valid_controller_hosts = [h for h in controller_hosts if
                              h['administrative'] == constants.ADMIN_UNLOCKED and
                              h['availability'] in [constants.AVAILABILITY_AVAILABLE,
                                                     constants.AVAILABILITY_DEGRADED]]
    if valid_controller_hosts:
        _apply_backend_changes(constants.SB_API_OP_CREATE, storage_backend_obj)

    return storage_ceph_rook_obj


#
# Update/Modify/Patch
#

def _hiera_data_semantic_checks(caps_dict):
    """ Validate each individual data value to make sure it's of the correct
        type and value.
    """
    pass


def _pre_patch_checks(storage_ceph_rook_obj, patch_obj):
    storage_ceph_rook_dict = storage_ceph_rook_obj.as_dict()

    for p in patch_obj:
        if p['path'] == '/capabilities':
            patch_caps_dict = p['value']

            # Validate the change to make sure it valid
            _hiera_data_semantic_checks(patch_caps_dict)

            current_caps_dict = storage_ceph_rook_dict.get('capabilities', {})
            for k in (set(current_caps_dict.keys()) -
                      set(patch_caps_dict.keys())):
                patch_caps_dict[k] = current_caps_dict[k]

            p['value'] = patch_caps_dict
        elif p['path'] == '/services':
            current_svcs = set([])
            if storage_ceph_rook_obj.services:
                current_svcs = set(storage_ceph_rook_obj.services.split(','))
            updated_svcs = set(p['value'].split(','))

            # Make sure we aren't removing a service.- Not currently Supported.
            if len(current_svcs - updated_svcs):
                raise wsme.exc.ClientSideError(
                        _("Removing %s is not supported.") % ','.join(
                                current_svcs - updated_svcs))
            p['value'] = ','.join(updated_svcs)


def _patch(storcephrook_uuid, patch):

    # Obtain current storage object.
    rpc_storcephrook = objects.storage_ceph_rook.get_by_uuid(
        pecan.request.context,
        storcephrook_uuid)

    patch_obj = jsonpatch.JsonPatch(patch)
    for p in patch_obj:
        if p['path'] == '/capabilities':
            p['value'] = jsonutils.loads(p['value'])

    ostorcephrook = copy.deepcopy(rpc_storcephrook)

    # perform checks based on the current vs.requested modifications
    _pre_patch_checks(rpc_storcephrook, patch_obj)

    # Obtain a storage object with the patch applied.
    try:
        storcephrook_config = StorageCephRook(**jsonpatch.apply_patch(
            rpc_storcephrook.as_dict(),
            patch_obj))

    except utils.JSONPATCH_EXCEPTIONS as e:
        raise exception.PatchError(patch=patch, reason=e)

    # Update current storage object.
    for field in objects.storage_ceph_rook.fields:
        if (field in storcephrook_config.as_dict() and
                rpc_storcephrook[field] != storcephrook_config.as_dict()[field]):
            rpc_storcephrook[field] = storcephrook_config.as_dict()[field]

    # Obtain the fields that have changed.
    delta = rpc_storcephrook.obj_what_changed()
    if len(delta) == 0:
        raise wsme.exc.ClientSideError(
            _("No changes to the existing backend settings were detected."))

    allowed_attributes = ['services', 'capabilities', 'task']
    for d in delta:
        if d not in allowed_attributes:
            raise wsme.exc.ClientSideError(
                _("Can not modify '%s' with this operation." % d))

    LOG.info("SYS_I orig storage_ceph_rook: %s " % ostorcephrook.as_dict())
    LOG.info("SYS_I new  storage_ceph_rook: %s " % storcephrook_config.as_dict())

    # Execute the common semantic checks for all backends, if backend is not
    # present this will not return
    api_helper.common_checks(constants.SB_API_OP_MODIFY,
                             rpc_storcephrook.as_dict())

    # Run the backend specific semantic checks
    _check_backend_ceph_rook(constants.SB_API_OP_MODIFY,
                        rpc_storcephrook.as_dict(),
                        True)

    try:
        rpc_storcephrook.save()

        # Enable the backend changes:
        _apply_backend_changes(constants.SB_API_OP_MODIFY,
                               rpc_storcephrook)

        return StorageCephRook.convert_with_links(rpc_storcephrook)

    except exception.HTTPNotFound:
        msg = _("StorCephRook update failed: storcephrook %s : "
                " patch %s"
                % (storcephrook_config, patch))
        raise wsme.exc.ClientSideError(msg)

#
# Delete
#


def _delete(sb_uuid):
    # LOG.error("sb_uuid %s" % sb_uuid)

    storage_ceph_rook_obj = pecan.request.dbapi.storage_ceph_rook_get(sb_uuid)

    # LOG.error("delete %s" % storage_ceph_rook_obj.as_dict())

    # Execute the common semantic checks for all backends, if backend is not
    # present this will not return
    api_helper.common_checks(constants.SB_API_OP_DELETE,
                             storage_ceph_rook_obj.as_dict())

    # Run the backend specific semantic checks
    _check_backend_ceph_rook(constants.SB_API_OP_DELETE,
                        storage_ceph_rook_obj.as_dict(),
                        True)

    # Enable the backend changes:
    _apply_backend_changes(constants.SB_API_OP_DELETE, storage_ceph_rook_obj)

    try:
        pecan.request.dbapi.storage_backend_destroy(storage_ceph_rook_obj.uuid)
    except exception.HTTPNotFound:
        msg = _("Deletion of backend %s failed" % storage_ceph_rook_obj.uuid)
        raise wsme.exc.ClientSideError(msg)
