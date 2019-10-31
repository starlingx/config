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
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy
import jsonpatch
import os
import pecan
from pecan import rest
from pecan import expose
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
    constants.SB_SVC_CINDER: ['cinder_pool'],
    constants.SB_SVC_GLANCE: ['glance_pool'],
    constants.SB_SVC_NOVA: ['ephemeral_pool']
}


class StorageCephExternalPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class StorageCephExternal(base.APIBase):
    """API representation of an external ceph storage.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    an external ceph storage.
    """

    uuid = types.uuid
    "Unique UUID for this external storage backend."

    links = [link.Link]
    "A list containing a self link and associated storage backend links."

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    ceph_conf = wtypes.text
    "Path to the configuration file for the external ceph cluster."

    # Inherited attributes from the base class
    backend = wtypes.text
    "Represents the storage backend (file, lvm, ceph, ceph_external or external)."

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
                    'confirmed': False,
                    'ceph_conf': None}

        self.fields = list(objects.storage_ceph_external.fields.keys())

        # 'confirmed' is not part of objects.storage_backend.fields
        # (it's an API-only attribute)
        self.fields.append('confirmed')

        # Set the value for any of the field
        for k in self.fields:
            setattr(self, k, kwargs.get(k, defaults.get(k)))

    @classmethod
    def convert_with_links(cls, rpc_storage_ceph_external, expand=True):

        stor_ceph_external = StorageCephExternal(**rpc_storage_ceph_external.as_dict())
        if not expand:
            stor_ceph_external.unset_fields_except(['uuid',
                                                    'created_at',
                                                    'updated_at',
                                                    'isystem_uuid',
                                                    'backend',
                                                    'name',
                                                    'state',
                                                    'task',
                                                    'services',
                                                    'capabilities',
                                                    'ceph_conf'])

        stor_ceph_external.links =\
            [link.Link.make_link('self', pecan.request.host_url,
                                 'storage_ceph_external',
                                 stor_ceph_external.uuid),
             link.Link.make_link('bookmark', pecan.request.host_url,
                                 'storage_ceph_external',
                                 stor_ceph_external.uuid,
                                 bookmark=True)]

        return stor_ceph_external


class StorageCephExternalCollection(collection.Collection):
    """API representation of a collection of external ceph storage backends."""

    storage_ceph_external = [StorageCephExternal]
    "A list containing ceph external storage backend objects."

    def __init__(self, **kwargs):
        self._type = 'storage_ceph_external'

    @classmethod
    def convert_with_links(cls, rpc_storage_ceph_external, limit, url=None,
                           expand=False, **kwargs):
        collection = StorageCephExternalCollection()
        collection.storage_ceph_external = \
            [StorageCephExternal.convert_with_links(p, expand)
             for p in rpc_storage_ceph_external]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'StorageCephExternalController'


class StorageCephExternalController(rest.RestController):
    """REST controller for ceph external storage backend."""

    _custom_actions = {
        'detail': ['GET'],
        'ceph_conf_upload': ['POST']
    }

    def _get_storage_ceph_external_collection(
            self, marker, limit, sort_key, sort_dir, expand=False,
            resource_url=None):

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.storage_ceph_external.get_by_uuid(
                pecan.request.context,
                marker)

        ceph_external_storage_backends = \
            pecan.request.dbapi.storage_ceph_external_get_list(
                limit, marker_obj, sort_key=sort_key, sort_dir=sort_dir)

        return StorageCephExternalCollection \
            .convert_with_links(ceph_external_storage_backends,
                                limit,
                                url=resource_url,
                                expand=expand,
                                sort_key=sort_key,
                                sort_dir=sort_dir)

    @wsme_pecan.wsexpose(StorageCephExternalCollection, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of ceph external storage backends."""

        return self._get_storage_ceph_external_collection(
            marker, limit, sort_key, sort_dir)

    @wsme_pecan.wsexpose(StorageCephExternal, types.uuid)
    def get_one(self, storage_ceph_external_uuid):
        """Retrieve information about the given ceph external storage
           backend.
        """

        rpc_storage_ceph_external = objects.storage_ceph_external.get_by_uuid(
            pecan.request.context,
            storage_ceph_external_uuid)
        return StorageCephExternal.convert_with_links(
            rpc_storage_ceph_external)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(StorageCephExternal, body=StorageCephExternal)
    def post(self, storage_ceph_external):
        """Create a new external storage backend."""

        try:
            storage_ceph_external = storage_ceph_external.as_dict()
            new_storage_ceph_external = _create(storage_ceph_external)

        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data: failed to create "
                                             "a storage_ceph_external record."))

        return StorageCephExternal.convert_with_links(new_storage_ceph_external)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [StorageCephExternalPatchType])
    @wsme_pecan.wsexpose(StorageCephExternal, types.uuid,
                         body=[StorageCephExternalPatchType])
    def patch(self, storexternal_uuid, patch):
        """Update the current external storage configuration."""
        return _patch(storexternal_uuid, patch)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, storageexternal_uuid):
        """Delete a backend."""

        # return _delete(storageexternal_uuid)

    @expose('json')
    @cutils.synchronized(LOCK_NAME)
    def ceph_conf_upload(self, file):
        """ Upload Ceph Config file
        """
        file = pecan.request.POST['file']
        ceph_conf_fn = pecan.request.POST.get('ceph_conf_fn')

        if ceph_conf_fn == constants.SB_TYPE_CEPH_CONF_FILENAME:
            msg = _("The %s name is reserved for the internally managed Ceph "
                    "cluster.\nPlease use a different name and try again." %
                    constants.SB_TYPE_CEPH_CONF_FILENAME)
            return dict(success="", error=msg)

        if not file.filename:
            return dict(success="", error="Error: No file uploaded")
        try:
            file.file.seek(0, os.SEEK_SET)
            file_content = file.file.read()

            pecan.request.rpcapi.store_ceph_external_config(
                pecan.request.context, file_content, ceph_conf_fn)
        except Exception as e:
            LOG.exception(e)
            return dict(success="", error=str(e))

        return dict(success="Success: ceph config file is uploaded", error="")


def _discover_and_validate_backend_hiera_data(caps_dict):
    pass


def _check_and_update_services(storage_ceph_ext):
    svcs = api_helper.getListFromServices(storage_ceph_ext)

    # If glance/nova is already a service on other rbd backend, remove it from there
    check_svcs = [constants.SB_SVC_GLANCE, constants.SB_SVC_NOVA]
    for s in check_svcs:
        if s in svcs:
            sb_list = pecan.request.dbapi.storage_backend_get_list()

            if sb_list:
                for sb in sb_list:
                    if (sb.uuid != storage_ceph_ext.get("uuid", None) and
                        sb.backend in [constants.SB_TYPE_CEPH,
                                       constants.SB_TYPE_CEPH_EXTERNAL] and
                            s in sb.get('services')):
                        services = api_helper.getListFromServices(sb)
                        services.remove(s)
                        cap = sb.capabilities
                        for k in HIERA_DATA[s]:
                            cap.pop(k, None)
                        values = {'services': ','.join(services),
                                  'capabilities': cap, }
                        pecan.request.dbapi.storage_backend_update(sb.uuid, values)


def _check_backend_ceph_external(storage_ceph_ext):
    """Prechecks for adding an external Ceph backend."""

    # go through the service list and validate
    svcs = api_helper.getListFromServices(storage_ceph_ext)

    for svc in svcs:
        if svc not in constants.SB_CEPH_EXTERNAL_SVCS_SUPPORTED:
            raise wsme.exc.ClientSideError("Service %s is not supported for the"
                                           " %s backend" %
                                           (svc, constants.SB_TYPE_CEPH_EXTERNAL))

    # check for the backend parameters
    capabilities = storage_ceph_ext.get('capabilities', {})

    # Discover the latest hiera_data for the supported service
    _discover_and_validate_backend_hiera_data(capabilities)

    for svc in svcs:
        for k in HIERA_DATA[svc]:
            if not capabilities.get(k, None):
                raise wsme.exc.ClientSideError("Missing required %s service "
                                               "parameter: %s" % (svc, k))

    for svc in constants.SB_CEPH_EXTERNAL_SVCS_SUPPORTED:
        for k in HIERA_DATA[svc]:
            if capabilities.get(k, None) and svc not in svcs:
                raise wsme.exc.ClientSideError("Missing required service %s for "
                                               "parameter: %s" % (svc, k))

    valid_pars = [i for sublist in HIERA_DATA.values() for i in sublist]
    if len(set(capabilities.keys()) - set(valid_pars)) > 0:
        raise wsme.exc.ClientSideError("Parameter %s is not valid "
                                       % list(set(capabilities.keys()) - set(valid_pars)))

    # Check the Ceph configuration file
    ceph_conf_file = storage_ceph_ext.get('ceph_conf')
    if ceph_conf_file:
        if (ceph_conf_file == constants.SB_TYPE_CEPH_CONF_FILENAME):
            msg = _("The %s name is reserved for the internally managed Ceph "
                    "cluster.\nPlease use a different name and try again." %
                    constants.SB_TYPE_CEPH_CONF_FILENAME)
            raise wsme.exc.ClientSideError(msg)
    else:
        # Raise error if the Ceph configuration file is not provided.
        msg = _("A Ceph configuration file must be provided for provisioning "
                "an external Ceph cluster.")
        raise wsme.exc.ClientSideError(msg)

    # If a conf file is specified, make sure the backend's name is not already
    # used / one of the default names for other backends.
    if ceph_conf_file:
        backend_name = storage_ceph_ext.get('name')
        backend_list = pecan.request.dbapi.storage_backend_get_list()
        for backend in backend_list:
            if backend.uuid != storage_ceph_ext.get("uuid", None):
                if backend_name in constants.SB_DEFAULT_NAMES.values():
                    msg = _(
                        "The \"%s\" name is reserved for internally managed "
                        "backends."
                        % backend_name)
                    raise wsme.exc.ClientSideError(msg)
                if backend.name == backend_name:
                    msg = _(
                        "The \"%s\" name is already used for another backend." %
                        backend_name)
                    raise wsme.exc.ClientSideError(msg)


def _apply_ceph_external_backend_changes(op, sb_obj, orig_sb_obj=None):
    if ((op == constants.SB_API_OP_CREATE) or
           (op == constants.SB_API_OP_MODIFY and
            sb_obj.get('ceph_conf') != orig_sb_obj.get('ceph_conf'))):

        values = {'task': constants.SB_TASK_APPLY_CONFIG_FILE}
        pecan.request.dbapi.storage_ceph_external_update(sb_obj.get('uuid'), values)

        try:
            pecan.request.rpcapi.distribute_ceph_external_config(
                pecan.request.context, sb_obj.get('ceph_conf'))
        except Exception as e:
            LOG.exception(e)
            msg = _("Failed to distribute ceph config file.")
            raise wsme.exc.ClientSideError(msg)

        services = api_helper.getListFromServices(sb_obj)

        pecan.request.rpcapi.update_ceph_external_config(
                                                pecan.request.context,
                                                sb_obj.get('uuid'),
                                                services)
    elif op == constants.SB_API_OP_DELETE:
        msg = _("Delete a Ceph external backend is not supported currently.")
        raise wsme.exc.ClientSideError(msg)
    else:
        # Compare ceph pools
        caps = sb_obj.get('capabilities', {})
        orig_caps = orig_sb_obj.get('capabilities', {})
        services = []
        for svc in constants.SB_CEPH_EXTERNAL_SVCS_SUPPORTED:
            for k in HIERA_DATA[svc]:
                if caps.get(k, None) != orig_caps.get(k, None):
                    services.append(svc)

        pecan.request.rpcapi.update_ceph_external_config(
                                                pecan.request.context,
                                                sb_obj.get('uuid'),
                                                services)


def _set_defaults_ceph_external(storage_ceph_ext):
    defaults = {
        'backend': constants.SB_TYPE_CEPH_EXTERNAL,
        'name': constants.SB_DEFAULT_NAMES[constants.SB_TYPE_CEPH_EXTERNAL].format(0),
        'state': constants.SB_STATE_CONFIGURING,
        'task': None,
        'services': None,
        'ceph_conf': None,
        'capabilities': {},
    }
    sc = api_helper.set_backend_data(storage_ceph_ext,
                                     defaults,
                                     HIERA_DATA,
                                     constants.SB_CEPH_EXTERNAL_SVCS_SUPPORTED)

    return sc


def _create(storage_ceph_ext):
    storage_ceph_ext = _set_defaults_ceph_external(storage_ceph_ext)

    # Execute the common semantic checks for all backends, if a specific backend
    # is not specified this will not return
    api_helper.common_checks(constants.SB_API_OP_CREATE,
                             storage_ceph_ext)

    _check_backend_ceph_external(storage_ceph_ext)

    _check_and_update_services(storage_ceph_ext)

    # Conditionally update the DB based on any previous create attempts. This
    # creates the StorageCeph object.
    system = pecan.request.dbapi.isystem_get_one()
    storage_ceph_ext['forisystemid'] = system.id
    storage_ceph_ext_obj = pecan.request.dbapi.storage_ceph_external_create(
        storage_ceph_ext)

    # Retrieve the main StorageBackend object.
    storage_backend_obj = pecan.request.dbapi.storage_backend_get(
        storage_ceph_ext_obj.id)

    _apply_ceph_external_backend_changes(
        constants.SB_API_OP_CREATE, sb_obj=storage_ceph_ext)

    return storage_backend_obj


#
# Update/Modify/Patch
#


def _hiera_data_semantic_checks(caps_dict):
    """ Validate each individual data value to make sure it's of the correct
        type and value.
    """
    pass


def _pre_patch_checks(storage_ceph_ext_obj, patch_obj):
    storage_ceph_ext_dict = storage_ceph_ext_obj.as_dict()
    for p in patch_obj:
        if p['path'] == '/capabilities':
            patch_caps_dict = p['value']

            # Validate the change to make sure it valid
            _hiera_data_semantic_checks(patch_caps_dict)

            current_caps_dict = storage_ceph_ext_dict.get('capabilities', {})
            for k in (set(current_caps_dict.keys()) -
                      set(patch_caps_dict.keys())):
                patch_caps_dict[k] = current_caps_dict[k]

            p['value'] = patch_caps_dict
        elif p['path'] == '/services':
            current_svcs = set([])
            if storage_ceph_ext_obj.services:
                current_svcs = set(storage_ceph_ext_obj.services.split(','))
            updated_svcs = set(p['value'].split(','))

            # WEI: Only support service add. Removing a service is not supported.
            if len(current_svcs - updated_svcs):
                raise wsme.exc.ClientSideError(
                    _("Removing %s is not supported.") % ','.join(
                        current_svcs - updated_svcs))
            p['value'] = ','.join(updated_svcs)
        elif p['path'] == '/ceph_conf':
            pass


def _patch(stor_ceph_ext_uuid, patch):

    # Obtain current storage object.
    rpc_stor_ceph_ext = objects.storage_ceph_external.get_by_uuid(
        pecan.request.context,
        stor_ceph_ext_uuid)

    ostor_ceph_ext = copy.deepcopy(rpc_stor_ceph_ext)

    patch_obj = jsonpatch.JsonPatch(patch)
    for p in patch_obj:
        if p['path'] == '/capabilities':
            p['value'] = jsonutils.loads(p['value'])

    # perform checks based on the current vs.requested modifications
    _pre_patch_checks(rpc_stor_ceph_ext, patch_obj)

    # Obtain a storage object with the patch applied.
    try:
        stor_ceph_ext_config = StorageCephExternal(**jsonpatch.apply_patch(
            rpc_stor_ceph_ext.as_dict(),
            patch_obj))

    except utils.JSONPATCH_EXCEPTIONS as e:
        raise exception.PatchError(patch=patch, reason=e)

    # Update current storage object.
    for field in objects.storage_ceph_external.fields:
        if (field in stor_ceph_ext_config.as_dict() and
                rpc_stor_ceph_ext[field] != stor_ceph_ext_config.as_dict()[field]):
            rpc_stor_ceph_ext[field] = stor_ceph_ext_config.as_dict()[field]

    # Obtain the fields that have changed.
    delta = rpc_stor_ceph_ext.obj_what_changed()
    if len(delta) == 0 and rpc_stor_ceph_ext['state'] != constants.SB_STATE_CONFIG_ERR:
        raise wsme.exc.ClientSideError(
            _("No changes to the existing backend settings were detected."))

    allowed_attributes = ['services', 'ceph_conf', 'capabilities', 'task']
    for d in delta:
        if d not in allowed_attributes:
            raise wsme.exc.ClientSideError(
                _("Can not modify '%s' with this operation." % d))

    LOG.info("SYS_I orig storage_ceph_external: %s " % ostor_ceph_ext.as_dict())
    LOG.info("SYS_I new  storage_ceph_external: %s " % stor_ceph_ext_config.as_dict())

    # Execute the common semantic checks for all backends, if backend is not
    # present this will not return
    api_helper.common_checks(constants.SB_API_OP_MODIFY,
                             rpc_stor_ceph_ext)

    _check_backend_ceph_external(rpc_stor_ceph_ext)

    _check_and_update_services(rpc_stor_ceph_ext)

    rpc_stor_ceph_ext.save()

    _apply_ceph_external_backend_changes(
        constants.SB_API_OP_MODIFY, sb_obj=rpc_stor_ceph_ext, orig_sb_obj=ostor_ceph_ext)

    return StorageCephExternal.convert_with_links(rpc_stor_ceph_ext)
