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

import copy
import jsonpatch
import pecan
from pecan import rest
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_serialization import jsonutils

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
from sysinv.openstack.common import log
from sysinv.openstack.common import uuidutils

LOG = log.getLogger(__name__)

HIERA_DATA = {
    'backend': [],
    constants.SB_SVC_GLANCE: []
}


class StorageFilePatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class StorageFile(base.APIBase):
    """API representation of a file storage.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a file storage.
    """

    uuid = types.uuid
    "Unique UUID for this file storage backend."

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

    def __init__(self, **kwargs):
        defaults = {'uuid': uuidutils.generate_uuid(),
                    'state': constants.SB_STATE_CONFIGURING,
                    'task': constants.SB_TASK_NONE,
                    'capabilities': {},
                    'services': None,
                    'confirmed': False}

        self.fields = list(objects.storage_file.fields.keys())

        # 'confirmed' is not part of objects.storage_backend.fields
        # (it's an API-only attribute)
        self.fields.append('confirmed')

        # Set the value for any of the field
        for k in self.fields:
            setattr(self, k, kwargs.get(k, defaults.get(k)))

    @classmethod
    def convert_with_links(cls, rpc_storage_file, expand=True):

        stor_file = StorageFile(**rpc_storage_file.as_dict())
        if not expand:
            stor_file.unset_fields_except(['uuid',
                                           'created_at',
                                           'updated_at',
                                           'isystem_uuid',
                                           'backend',
                                           'name',
                                           'state',
                                           'task',
                                           'services',
                                           'capabilities'])

        stor_file.links =\
            [link.Link.make_link('self', pecan.request.host_url,
                                 'storage_file',
                                 stor_file.uuid),
             link.Link.make_link('bookmark', pecan.request.host_url,
                                 'storage_file',
                                 stor_file.uuid,
                                 bookmark=True)]

        return stor_file


class StorageFileCollection(collection.Collection):
    """API representation of a collection of file storage backends."""

    storage_file = [StorageFile]
    "A list containing file storage backend objects."

    def __init__(self, **kwargs):
        self._type = 'storage_file'

    @classmethod
    def convert_with_links(cls, rpc_storage_file, limit, url=None,
                           expand=False, **kwargs):
        collection = StorageFileCollection()
        collection.storage_file = \
                                 [StorageFile.convert_with_links(p, expand)
             for p in rpc_storage_file]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'StorageFileController'


class StorageFileController(rest.RestController):
    """REST controller for file storage backend."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def _get_storage_file_collection(self, marker, limit, sort_key, sort_dir,
                                     expand=False, resource_url=None):

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.storage_file.get_by_uuid(
                pecan.request.context,
                marker)

        file_storage_backends = \
                                pecan.request.dbapi.storage_file_get_list(
                                    limit,
                                    marker_obj,
                                    sort_key=sort_key,
                                    sort_dir=sort_dir)

        return StorageFileCollection \
            .convert_with_links(file_storage_backends,
                                limit,
                                url=resource_url,
                                expand=expand,
                                sort_key=sort_key,
                                sort_dir=sort_dir)

    @wsme_pecan.wsexpose(StorageFileCollection, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of file storage backends."""

        return self._get_storage_file_collection(marker, limit, sort_key,
                                                 sort_dir)

    @wsme_pecan.wsexpose(StorageFile, types.uuid)
    def get_one(self, storage_file_uuid):
        """Retrieve information about the given file storage backend."""

        rpc_storage_file = objects.storage_file.get_by_uuid(
            pecan.request.context,
            storage_file_uuid)
        return StorageFile.convert_with_links(rpc_storage_file)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(StorageFile, body=StorageFile)
    def post(self, storage_file):
        """Create a new file storage backend."""

        try:
            storage_file = storage_file.as_dict()
            new_storage_file = _create(storage_file)

        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data: failed to create "
                                             "a storage_file record."))

        return StorageFile.convert_with_links(new_storage_file)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [StorageFilePatchType])
    @wsme_pecan.wsexpose(StorageFile, types.uuid,
                         body=[StorageFilePatchType])
    def patch(self, storfile_uuid, patch):
        """Update the current file storage configuration."""
        return _patch(storfile_uuid, patch)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, storagefile_uuid):
        """Delete a backend."""

        return _delete(storagefile_uuid)

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
    for svc in constants.SB_FILE_SVCS_SUPPORTED:
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


def _check_backend_file(req, storage_file, confirmed=False):
    # check for the backend parameters
    capabilities = storage_file.get('capabilities', {})

    # Discover the latest hiera_data for the supported service
    _discover_and_validate_backend_hiera_data(capabilities)

    for k in HIERA_DATA['backend']:
        if not capabilities.get(k, None):
            raise wsme.exc.ClientSideError("Missing required backend "
                                           "parameter: %s" % k)

    # go through the service list and validate
    req_services = api_helper.getListFromServices(storage_file)
    for svc in req_services:
        if svc not in constants.SB_FILE_SVCS_SUPPORTED:
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
    storage_file['capabilities'] = capabilities

    # TODO (rchurch): Put this back
    # if req == constants.SB_API_OP_MODIFY or req == constants.SB_API_OP_DELETE:
    #     raise wsme.exc.ClientSideError("API Operation %s is not supported for "
    #                                    "the %s backend" %
    #                                    (req, constants.SB_TYPE_FILE))

    # Check for confirmation
    if not confirmed:
        _options_str = _get_options_string(storage_file)
        raise wsme.exc.ClientSideError(
            _("%s\nWARNING : THIS OPERATION IS NOT REVERSIBLE AND CANNOT BE "
              "CANCELLED. \n\nPlease set the 'confirmed' field to execute "
              "this operation for the %s backend.") % (_options_str,
                                                       constants.SB_TYPE_FILE))


def _apply_backend_changes(op, sb_obj):
    if op == constants.SB_API_OP_CREATE:
        # This is a DB only change => Set the state to configured
        pecan.request.dbapi.storage_file_update(
            sb_obj.uuid,
            {'state': constants.SB_STATE_CONFIGURED})

    elif op == constants.SB_API_OP_MODIFY:
        pass

    elif op == constants.SB_API_OP_DELETE:
        pass


#
# Create
#

def _set_default_values(storage_file):
    defaults = {
        'backend': constants.SB_TYPE_FILE,
        'name': constants.SB_DEFAULT_NAMES[constants.SB_TYPE_FILE],
        'state': constants.SB_STATE_CONFIGURING,
        'task': constants.SB_TASK_NONE,
        'services': None,
        'capabilities': {}
    }

    sf = api_helper.set_backend_data(storage_file,
                                     defaults,
                                     HIERA_DATA,
                                     constants.SB_FILE_SVCS_SUPPORTED)
    return sf


def _create(storage_file):
    # Set the default for the storage backend
    storage_file = _set_default_values(storage_file)

    # Execute the common semantic checks for all backends, if a backend is
    # not present this will not return
    api_helper.common_checks(constants.SB_API_OP_CREATE,
                             storage_file)

    # Run the backend specific semantic checks
    _check_backend_file(constants.SB_API_OP_CREATE,
                        storage_file,
                        storage_file.pop('confirmed', False))

    # We have a valid configuration. create it.
    system = pecan.request.dbapi.isystem_get_one()
    storage_file['forisystemid'] = system.id
    storage_file_obj = pecan.request.dbapi.storage_file_create(storage_file)

    # Retreive the main StorageBackend object.
    storage_backend_obj = pecan.request.dbapi.storage_backend_get(storage_file_obj.id)

    # Enable the backend:
    _apply_backend_changes(constants.SB_API_OP_CREATE, storage_backend_obj)

    return storage_file_obj


#
# Update/Modify/Patch
#

def _hiera_data_semantic_checks(caps_dict):
    """ Validate each individual data value to make sure it's of the correct
        type and value.
    """
    pass


def _pre_patch_checks(storage_file_obj, patch_obj):
    storage_file_dict = storage_file_obj.as_dict()

    for p in patch_obj:
        if p['path'] == '/capabilities':
            patch_caps_dict = p['value']

            # Validate the change to make sure it valid
            _hiera_data_semantic_checks(patch_caps_dict)

            current_caps_dict = storage_file_dict.get('capabilities', {})
            for k in (set(current_caps_dict.keys()) -
                      set(patch_caps_dict.keys())):
                patch_caps_dict[k] = current_caps_dict[k]

            p['value'] = patch_caps_dict
        elif p['path'] == '/services':
            current_svcs = set([])
            if storage_file_obj.services:
                current_svcs = set(storage_file_obj.services.split(','))
            updated_svcs = set(p['value'].split(','))

            # Make sure we aren't removing a service.- Not currently Supported.
            if len(current_svcs - updated_svcs):
                raise wsme.exc.ClientSideError(
                        _("Removing %s is not supported.") % ','.join(
                                current_svcs - updated_svcs))
            p['value'] = ','.join(updated_svcs)


def _patch(storfile_uuid, patch):

    # Obtain current storage object.
    rpc_storfile = objects.storage_file.get_by_uuid(
        pecan.request.context,
        storfile_uuid)

    patch_obj = jsonpatch.JsonPatch(patch)
    for p in patch_obj:
        if p['path'] == '/capabilities':
            p['value'] = jsonutils.loads(p['value'])

    ostorfile = copy.deepcopy(rpc_storfile)

    # perform checks based on the current vs.requested modifications
    _pre_patch_checks(rpc_storfile, patch_obj)

    # Obtain a storage object with the patch applied.
    try:
        storfile_config = StorageFile(**jsonpatch.apply_patch(
            rpc_storfile.as_dict(),
            patch_obj))

    except utils.JSONPATCH_EXCEPTIONS as e:
        raise exception.PatchError(patch=patch, reason=e)

    # Update current storage object.
    for field in objects.storage_file.fields:
        if (field in storfile_config.as_dict() and
                rpc_storfile[field] != storfile_config.as_dict()[field]):
            rpc_storfile[field] = storfile_config.as_dict()[field]

    # Obtain the fields that have changed.
    delta = rpc_storfile.obj_what_changed()
    if len(delta) == 0:
        raise wsme.exc.ClientSideError(
            _("No changes to the existing backend settings were detected."))

    allowed_attributes = ['services', 'capabilities', 'task']
    for d in delta:
        if d not in allowed_attributes:
            raise wsme.exc.ClientSideError(
                _("Can not modify '%s' with this operation." % d))

    LOG.info("SYS_I orig storage_file: %s " % ostorfile.as_dict())
    LOG.info("SYS_I new  storage_file: %s " % storfile_config.as_dict())

    # Execute the common semantic checks for all backends, if backend is not
    # present this will not return
    api_helper.common_checks(constants.SB_API_OP_MODIFY,
                             rpc_storfile.as_dict())

    # Run the backend specific semantic checks
    _check_backend_file(constants.SB_API_OP_MODIFY,
                        rpc_storfile.as_dict(),
                        True)

    try:
        rpc_storfile.save()

        # Enable the backend changes:
        _apply_backend_changes(constants.SB_API_OP_MODIFY,
                               rpc_storfile)

        return StorageFile.convert_with_links(rpc_storfile)

    except exception.HTTPNotFound:
        msg = _("StorFile update failed: storfile %s : "
                " patch %s"
                % (storfile_config, patch))
        raise wsme.exc.ClientSideError(msg)

#
# Delete
#


def _delete(sb_uuid):
    # LOG.error("sb_uuid %s" % sb_uuid)

    storage_file_obj = pecan.request.dbapi.storage_file_get(sb_uuid)

    # LOG.error("delete %s" % storage_file_obj.as_dict())

    # Execute the common semantic checks for all backends, if backend is not
    # present this will not return
    api_helper.common_checks(constants.SB_API_OP_DELETE,
                             storage_file_obj.as_dict())

    # Run the backend specific semantic checks
    _check_backend_file(constants.SB_API_OP_DELETE,
                        storage_file_obj.as_dict(),
                        True)

    # Enable the backend changes:
    _apply_backend_changes(constants.SB_API_OP_DELETE, storage_file_obj)

    try:
        pecan.request.dbapi.storage_backend_destroy(storage_file_obj.uuid)
    except exception.HTTPNotFound:
        msg = _("Deletion of backend %s failed" % storage_file_obj.uuid)
        raise wsme.exc.ClientSideError(msg)
