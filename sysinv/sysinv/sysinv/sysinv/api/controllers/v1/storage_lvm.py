# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright 2016 UnitedStack Inc.
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
# Copyright (c) 2013-2021,2026 Wind River Systems, Inc.
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
}


class StorageLVMPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class StorageLVM(base.APIBase):
    """API representation of a LVM storage.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a lvm storage.
    """

    uuid = types.uuid
    "Unique UUID for this lvm storage backend."

    links = [link.Link]
    "A list containing a self link and associated storage backend links."

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    # Inherited attributes from the base class
    backend = wtypes.text
    "Represents the storage backend (file, lvm, or ceph)."

    name = wtypes.text
    "The name of the backend (to differentiate between multiple common backends)."

    state = wtypes.text
    "The state of the backend. It can be configured or configuring-with-app."

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
                    'state': constants.SB_STATE_CONFIGURING_WITH_APP,
                    'task': constants.SB_TASK_NONE,
                    'capabilities': {},
                    'services': None,
                    'confirmed': False}

        self.fields = list(objects.storage_lvm.fields.keys())

        # 'confirmed' is not part of objects.storage_backend.fields
        # (it's an API-only attribute)
        self.fields.append('confirmed')

        # Set the value for any of the field
        for k in self.fields:
            setattr(self, k, kwargs.get(k, defaults.get(k)))

    @classmethod
    def convert_with_links(cls, rpc_storage_lvm, expand=True):

        stor_lvm = StorageLVM(**rpc_storage_lvm.as_dict())
        if not expand:
            stor_lvm.unset_fields_except(['uuid',
                                          'created_at',
                                          'updated_at',
                                          'isystem_uuid',
                                          'backend',
                                          'name',
                                          'state',
                                          'task',
                                          'services',
                                          'capabilities'])

        stor_lvm.links =\
            [link.Link.make_link('self', pecan.request.host_url,
                                 'storage_lvm',
                                 stor_lvm.uuid),
             link.Link.make_link('bookmark', pecan.request.host_url,
                                 'storage_lvm',
                                 stor_lvm.uuid,
                                 bookmark=True)]

        return stor_lvm


class StorageLVMCollection(collection.Collection):
    """API representation of a collection of lvm storage backends."""

    storage_lvm = [StorageLVM]
    "A list containing lvm storage backend objects."

    def __init__(self, **kwargs):
        self._type = 'storage_lvm'

    @classmethod
    def convert_with_links(cls, rpc_storage_lvm, limit, url=None,
                           expand=False, **kwargs):
        collection = StorageLVMCollection()
        collection.storage_lvm = \
            [StorageLVM.convert_with_links(p, expand)
             for p in rpc_storage_lvm]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'StorageLVMController'


class StorageLVMController(rest.RestController):
    """REST controller for lvm storage backend."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def _get_storage_lvm_collection(self, marker, limit, sort_key, sort_dir,
                                     expand=False, resource_url=None):

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.storage_lvm.get_by_uuid(
                pecan.request.context,
                marker)

        lvm_storage_backends = \
                pecan.request.dbapi.storage_lvm_get_list(
                    limit,
                    marker_obj,
                    sort_key=sort_key,
                    sort_dir=sort_dir)

        return StorageLVMCollection \
            .convert_with_links(lvm_storage_backends,
                                limit,
                                url=resource_url,
                                expand=expand,
                                sort_key=sort_key,
                                sort_dir=sort_dir)

    @wsme_pecan.wsexpose(StorageLVMCollection, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of lvm storage backends."""

        return self._get_storage_lvm_collection(marker, limit, sort_key,
                                                 sort_dir)

    @wsme_pecan.wsexpose(StorageLVM, types.uuid)
    def get_one(self, storage_lvm_uuid):
        """Retrieve information about the given lvm storage backend."""

        rpc_storage_lvm = objects.storage_lvm.get_by_uuid(
            pecan.request.context,
            storage_lvm_uuid)
        return StorageLVM.convert_with_links(rpc_storage_lvm)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(StorageLVM, body=StorageLVM)
    def post(self, storage_lvm):
        """Create a new storage LVM backend."""

        try:
            storage_lvm = storage_lvm.as_dict()
            new_storage_lvm = _create(storage_lvm)

        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data: failed to create "
                                             "a storage_lvm record."))

        return StorageLVM.convert_with_links(new_storage_lvm)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [StorageLVMPatchType])
    @wsme_pecan.wsexpose(StorageLVM, types.uuid,
                         body=[StorageLVMPatchType])
    def patch(self, storlvm_uuid, patch):
        """Update the current lvm storage configuration."""
        return _patch(storlvm_uuid, patch)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, storagelvm_uuid):
        """Delete a backend."""

        _delete(storagelvm_uuid)
#
# Common operation functions
#


def _check_backend_lvm(req, storage_lvm, confirmed=False):
    # check for the backend parameters
    capabilities = storage_lvm.get('capabilities', {})

    for k in HIERA_DATA['backend']:
        if not capabilities.get(k, None):
            raise wsme.exc.ClientSideError("Missing required backend "
                                           "parameter: %s" % k)

    # Update based on any discovered values
    storage_lvm['capabilities'] = capabilities

    if req == constants.SB_API_OP_MODIFY:
        raise wsme.exc.ClientSideError("API Operation %s is not supported for "
                                       "the %s backend" %
                                       (req, constants.SB_TYPE_LVM))
#
# Create
#


def _set_default_values(storage_lvm):

    try:
        app = pecan.request.dbapi.kube_app_get(constants.SB_APP_MAP[
            constants.SB_TYPE_LVM])
        def_task = app.status
    except exception.KubeAppNotFound:
        def_task = constants.APP_NOT_PRESENT

    defaults = {
        'backend': constants.SB_TYPE_LVM,
        'name': constants.SB_DEFAULT_NAMES[constants.SB_TYPE_LVM],
        'state': constants.SB_STATE_CONFIGURING_WITH_APP,
        'task': def_task,
        'services': None,
        'capabilities': {}
    }

    sl = api_helper.set_backend_data(storage_lvm,
                                     defaults,
                                     HIERA_DATA,
                                     constants.SB_LVM_SVCS_SUPPORTED)
    return sl


def _create(storage_lvm):
    # Set the default for the storage backend
    storage_lvm = _set_default_values(storage_lvm)

    # Validate LVM backend uniqueness
    lvm_backend = pecan.request.dbapi.storage_backend_get_list_by_type(
        backend_type=constants.SB_TYPE_LVM
    )
    if lvm_backend:
        raise wsme.exc.ClientSideError(
            _("It's not possible to add the backend. Only one %s backend "
              "is allowed.") % constants.SB_TYPE_LVM)

    # Execute the common semantic checks for all backends, if a specific backend
    # is not specified this will not return
    api_helper.common_checks(constants.SB_API_OP_CREATE,
                             storage_lvm)

    # Run the backend specific semantic checks to validate that we have all the
    # required parameters for manifest application
    _check_backend_lvm(constants.SB_API_OP_CREATE,
                       storage_lvm,
                       storage_lvm.pop('confirmed', False))

    # We have a valid configuration. create it.
    system = pecan.request.dbapi.isystem_get_one()
    storage_lvm['forisystemid'] = system.id
    storage_lvm_obj = pecan.request.dbapi.storage_lvm_create(storage_lvm)

    # Retreive the main StorageBackend object.
    storage_backend_obj = pecan.request.dbapi.storage_backend_get(storage_lvm_obj.id)

    return storage_backend_obj
#
# Delete
#


def _delete(sb_uuid):
    storage_lvm_obj = pecan.request.dbapi.storage_lvm_get(sb_uuid)

    # Execute the common semantic checks for all backends, if backend is not
    # present this will not return
    api_helper.common_checks(constants.SB_API_OP_DELETE,
                             storage_lvm_obj.as_dict())

    # Run the backend specific semantic checks
    _check_backend_lvm(constants.SB_API_OP_DELETE,
                        storage_lvm_obj.as_dict(),
                        True)

    try:
        pecan.request.dbapi.storage_backend_destroy(storage_lvm_obj.uuid)
    except exception.HTTPNotFound:
        msg = _("Deletion of backend %s failed" % storage_lvm_obj.uuid)
        raise wsme.exc.ClientSideError(msg)
#
# Update/Modify/Patch
#


def _hiera_data_semantic_checks(caps_dict):
    """ Validate each individual data value to make sure it's of the correct
        type and value.
    """
    pass


def _pre_patch_checks(storage_lvm_obj, patch_obj):
    storage_lvm_dict = storage_lvm_obj.as_dict()
    for p in patch_obj:
        if p['path'] == '/capabilities':
            patch_caps_dict = p['value']

            # Validate the change to make sure it valid
            _hiera_data_semantic_checks(patch_caps_dict)

            current_caps_dict = storage_lvm_dict.get('capabilities', {})
            for k in (set(current_caps_dict.keys()) -
                      set(patch_caps_dict.keys())):
                patch_caps_dict[k] = current_caps_dict[k]

            p['value'] = patch_caps_dict
        elif p['path'] == '/services':
            current_svcs = set([])
            if storage_lvm_obj.services:
                current_svcs = set(storage_lvm_obj.services.split(','))
            updated_svcs = set(p['value'].split(','))

            # Make sure we aren't removing a service.- Not currently Supported.
            if len(current_svcs - updated_svcs):
                raise wsme.exc.ClientSideError(
                    _("Removing %s is not supported.") % ','.join(
                        current_svcs - updated_svcs))
            p['value'] = ','.join(updated_svcs)


def _patch(storlvm_uuid, patch):

    # Obtain current storage object.
    rpc_storlvm = objects.storage_lvm.get_by_uuid(
        pecan.request.context,
        storlvm_uuid)

    patch_obj = jsonpatch.JsonPatch(patch)
    for p in patch_obj:
        if p['path'] == '/capabilities':
            p['value'] = jsonutils.loads(p['value'])

    ostorlvm = copy.deepcopy(rpc_storlvm)

    # perform checks based on the current vs.requested modifications
    _pre_patch_checks(rpc_storlvm, patch_obj)

    # Obtain a storage object with the patch applied.
    try:
        storlvm_config = StorageLVM(**jsonpatch.apply_patch(
            rpc_storlvm.as_dict(),
            patch_obj))

    except utils.JSONPATCH_EXCEPTIONS as e:
        raise exception.PatchError(patch=patch, reason=e)

    # Update current storage object.
    for field in objects.storage_lvm.fields:
        if (field in storlvm_config.as_dict() and
                rpc_storlvm[field] != storlvm_config.as_dict()[field]):
            rpc_storlvm[field] = storlvm_config.as_dict()[field]

    # Obtain the fields that have changed.
    delta = rpc_storlvm.obj_what_changed()
    if len(delta) == 0 and rpc_storlvm['state'] != constants.SB_STATE_CONFIG_ERR:
        raise wsme.exc.ClientSideError(
            _("No changes to the existing backend settings were detected."))

    allowed_attributes = ['services', 'capabilities', 'task']
    for d in delta:
        if d not in allowed_attributes:
            raise wsme.exc.ClientSideError(
                _("Can not modify '%s' with this operation." % d))

    LOG.info("SYS_I orig storage_lvm: %s " % ostorlvm.as_dict())
    LOG.info("SYS_I new  storage_lvm: %s " % storlvm_config.as_dict())

    # Execute the common semantic checks for all backends, if backend is not
    # present this will not return
    api_helper.common_checks(constants.SB_API_OP_MODIFY,
                             rpc_storlvm.as_dict())

    # Run the backend specific semantic checks
    _check_backend_lvm(constants.SB_API_OP_MODIFY,
                       rpc_storlvm.as_dict(),
                       True)

    try:
        rpc_storlvm.save()
        return StorageLVM.convert_with_links(rpc_storlvm)

    except exception.HTTPNotFound:
        msg = _("Storlvm update failed: storlvm %s : "
                " patch %s"
                % (storlvm_config, patch))
        raise wsme.exc.ClientSideError(msg)
