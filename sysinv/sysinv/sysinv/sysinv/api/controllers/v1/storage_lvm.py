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
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#

import copy
import jsonpatch
import math
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
    constants.SB_SVC_CINDER: []
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


def _get_options_string(storage_lvm):
    opt_str = ""
    caps = storage_lvm.get('capabilities', {})
    services = api_helper.getListFromServices(storage_lvm)

    # get the backend parameters
    backend_dict = caps.get("backend", {})
    be_str = ""
    for key in backend_dict:
        be_str += "\t%s: %s\n" % (key, backend_dict[key])

    # Only show the backend values if any are present
    if len(be_str) > 0:
        opt_str = "Backend:\n%s" % be_str

    # Get any supported service parameters
    for svc in constants.SB_LVM_SVCS_SUPPORTED:
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


def _validate_lvm_data(host):
    ilvgs = pecan.request.dbapi.ilvg_get_by_ihost(host.uuid)

    cinder_lvg = None
    for lvg in ilvgs:
        if lvg.lvm_vg_name == constants.LVG_CINDER_VOLUMES:
            cinder_lvg = lvg
            break

    if not cinder_lvg or cinder_lvg.vg_state == constants.LVG_DEL:
        msg = (_('%s volume group for host %s must be in the "%s" or "%s" state to enable'
                 ' the %s backend.') % (constants.LVG_CINDER_VOLUMES,
                                        host.hostname,
                                        constants.LVG_ADD,
                                        constants.PROVISIONED,
                                        constants.SB_TYPE_LVM))
        raise wsme.exc.ClientSideError(msg)

    # Make sure we have at least one physical volume in the adding/provisioned
    # state
    pvs = pecan.request.dbapi.ipv_get_by_ihost(host.uuid)
    cinder_pv = None
    for pv in pvs:
        if pv.forilvgid == cinder_lvg.id:
            cinder_pv = pv
            break

    if (not cinder_pv or cinder_pv.pv_state == constants.PV_DEL or
            cinder_pv.pv_state == constants.PV_ERR):
        msg = (_('%s volume group for host %s must have physical volumes in the "%s" or'
                 ' "%s" state to enable the %s backend.') %
               (constants.LVG_CINDER_VOLUMES,
                host.hostname,
                constants.PV_ADD,
                constants.PROVISIONED, constants.SB_TYPE_LVM))
        raise wsme.exc.ClientSideError(msg)

    lvg_caps = cinder_lvg.capabilities
    if 'lvm_type' not in lvg_caps:
        # Note: Defensive programming: This should never happen. We set a
        # default on LVG creation
        msg = (_('%s volume group for host %s must have the lvm_type parameter defined') %
               (constants.LVG_CINDER_VOLUMES, host.hostname))
        raise wsme.exc.ClientSideError(msg)


def _discover_and_validate_cinder_hiera_data(caps_dict):
    # Update floating IP details: 'cinder-float-ip', 'cinder-float-ip-mask-length'
    # NOTE: Should check for and reserve the IP info here, then validate the values
    # pecan.request.rpcapi.reserve_ip_for_cinder(pecan.request.context)

    # Check for a cinder-volumes volume group, physical volumes
    ctrls = pecan.request.dbapi.ihost_get_by_personality(constants.CONTROLLER)
    valid_ctrls = [ctrl for ctrl in ctrls if
                   (ctrl.administrative == constants.ADMIN_LOCKED and
                    ctrl.availability == constants.AVAILABILITY_ONLINE) or
                   (ctrl.administrative == constants.ADMIN_UNLOCKED and
                    ctrl.operational == constants.OPERATIONAL_ENABLED)]

    for host in valid_ctrls:
        _validate_lvm_data(host)

    # If multiple controllers are available make sure that PV size is correct
    pv_sizes = []
    for host in valid_ctrls:
        pvs = pecan.request.dbapi.ipv_get_by_ihost(host.uuid)
        cinder_pv = None
        for pv in pvs:
            if pv.lvm_vg_name == constants.LVG_CINDER_VOLUMES:
                cinder_pv = pv
                break
        else:
            msg = (_('Internal error: Error getting %s PV for host %s') %
                   (constants.LVG_CINDER_VOLUMES, host.hostname))
            raise wsme.exc.ClientSideError(msg)
        # cinder's pv is always a single partition
        part = pecan.request.dbapi.partition_get_by_ipv(cinder_pv.uuid)
        pv_sizes.append({"host": host.hostname, "size": part[0].size_mib})

    LOG.debug("storage_lvm PV size: %s" % pv_sizes)

    if len(valid_ctrls) == 2:
        if pv_sizes[0]['size'] != pv_sizes[1]['size']:
            msg = (_('Allocated storage for %s PVs must be equal and greater than '
                     '%s GiB on both controllers. Allocation for %s is %s GiB '
                     'while for %s is %s GiB.') %
                   (constants.LVG_CINDER_VOLUMES,
                    constants.CINDER_LVM_MINIMUM_DEVICE_SIZE_GIB,
                    pv_sizes[0]['host'], math.floor(float(pv_sizes[0]['size']) / 1024 * 1000) / 1000.0,
                    pv_sizes[1]['host'], math.floor(float(pv_sizes[1]['size']) / 1024 * 1000) / 1000.0))
            raise wsme.exc.ClientSideError(msg)

    if pv_sizes[0]['size'] < (constants.CINDER_LVM_MINIMUM_DEVICE_SIZE_GIB * 1024):
        msg = (_('Minimum allocated storage for %s PVs is: %s GiB. '
                 'Current allocation is: %s GiB.') %
               (constants.LVG_CINDER_VOLUMES,
                constants.CINDER_LVM_MINIMUM_DEVICE_SIZE_GIB,
                math.floor(float(pv_sizes[0]['size']) / 1024 * 1000) / 1000.0))
        raise wsme.exc.ClientSideError(msg)

    # Log all the LVM parameters
    for k, v in caps_dict.items():
        LOG.info("Cinder LVM Data %s = %s" % (k, v))


def _check_backend_lvm(req, storage_lvm, confirmed=False):
    # check for the backend parameters
    capabilities = storage_lvm.get('capabilities', {})

    # Discover the latest hiera_data for the supported service
    _discover_and_validate_backend_hiera_data(capabilities)

    for k in HIERA_DATA['backend']:
        if not capabilities.get(k, None):
            raise wsme.exc.ClientSideError("Missing required backend "
                                           "parameter: %s" % k)

    # go through the service list and validate
    req_services = api_helper.getListFromServices(storage_lvm)

    # Cinder is mandatory for lvm backend
    if constants.SB_SVC_CINDER not in req_services:
        raise wsme.exc.ClientSideError("Service %s is mandatory for "
                                       "the %s backend." %
                                       (constants.SB_SVC_CINDER, constants.SB_TYPE_LVM))

    for svc in req_services:
        if svc not in constants.SB_LVM_SVCS_SUPPORTED:
            raise wsme.exc.ClientSideError("Service %s is not supported for the"
                                           " %s backend" %
                                           (svc, constants.SB_TYPE_LVM))

        # Service is valid. Discover the latest hiera_data for the supported service
        discover_func = eval('_discover_and_validate_' + svc + '_hiera_data')
        discover_func(capabilities)

        # Service is valid. Check the params
        for k in HIERA_DATA[svc]:
            if not capabilities.get(k, None):
                raise wsme.exc.ClientSideError("Missing required %s service "
                                               "parameter: %s" % (svc, k))
    # Update based on any discovered values
    storage_lvm['capabilities'] = capabilities

    # TODO (rchurch): Put this back in some form for delivery OR move to specific
    # backend checks to limit operations based on the backend
    #
    # if req == constants.SB_API_OP_MODIFY or req == constants.SB_API_OP_DELETE:
    #     raise wsme.exc.ClientSideError("API Operation %s is not supported for "
    #                                    "the %s backend" %
    #                                    (req, constants.SB_TYPE_LVM))

    # Check for confirmation
    if not confirmed:
        _options_str = _get_options_string(storage_lvm)
        raise wsme.exc.ClientSideError(
            _("%s\nWARNING : THIS OPERATION IS NOT REVERSIBLE AND CANNOT BE CANCELLED. \n"
              "\nBy confirming this operation, the LVM backend will be created.\n\n"
              "Please refer to the system admin guide for minimum spec for LVM\n"
              "storage. Set the 'confirmed' field to execute this operation\n"
              "for the %s backend.") % (_options_str,
                                        constants.SB_TYPE_LVM))


def _apply_backend_changes(op, sb_obj):
    if op == constants.SB_API_OP_CREATE:
        services = api_helper.getListFromServices(sb_obj.as_dict())
        if constants.SB_SVC_CINDER in services:

            # Services are specified: Update backend + service actions
            api_helper.enable_backend(sb_obj,
                                      pecan.request.rpcapi.update_lvm_cinder_config)

    elif op == constants.SB_API_OP_MODIFY:
        if sb_obj.state == constants.SB_STATE_CONFIG_ERR:
            api_helper.enable_backend(sb_obj,
                                      pecan.request.rpcapi.update_lvm_cinder_config)

    elif op == constants.SB_API_OP_DELETE:
        pass


#
# Create
#

def _set_default_values(storage_lvm):
    defaults = {
        'backend': constants.SB_TYPE_LVM,
        'name': constants.SB_DEFAULT_NAMES[constants.SB_TYPE_LVM],
        'state': constants.SB_STATE_CONFIGURING,
        'task': constants.SB_TASK_NONE,
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

    # Enable the backend:
    _apply_backend_changes(constants.SB_API_OP_CREATE, storage_backend_obj)

    return storage_backend_obj


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

        # Enable the backend changes:
        _apply_backend_changes(constants.SB_API_OP_MODIFY,
                               rpc_storlvm)

        return StorageLVM.convert_with_links(rpc_storlvm)

    except exception.HTTPNotFound:
        msg = _("Storlvm update failed: storlvm %s : "
                " patch %s"
                % (storlvm_config, patch))
        raise wsme.exc.ClientSideError(msg)

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

    # Enable the backend changes:
    _apply_backend_changes(constants.SB_API_OP_DELETE, storage_lvm_obj)

    try:
        pecan.request.dbapi.storage_backend_destroy(storage_lvm_obj.uuid)
    except exception.HTTPNotFound:
        msg = _("Deletion of backend %s failed" % storage_lvm_obj.uuid)
        raise wsme.exc.ClientSideError(msg)
