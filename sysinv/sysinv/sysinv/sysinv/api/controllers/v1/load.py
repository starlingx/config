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
import os
import pecan
from pecan import rest
import six
import shutil
import socket
import sys
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from pecan import expose
from pecan import request
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common.rpc import common
import tsconfig.tsconfig as tsc

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
        'import_load_metadata': ['POST']
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

    @wsme_pecan.wsexpose(Load, six.text_type)
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
        patch['state'] = constants.ACTIVE_LOAD_STATE

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

    @staticmethod
    def _upload_file(file_item):
        dst = None
        try:
            staging_dir = constants.LOAD_FILES_STAGING_DIR
            if not os.path.isdir(staging_dir):
                os.makedirs(staging_dir)

            fn = os.path.join(staging_dir,
                              os.path.basename(file_item.filename))
            if hasattr(file_item.file, 'fileno'):
                # Large iso file
                dst = os.open(fn, os.O_WRONLY | os.O_CREAT)
                src = file_item.file.fileno()
                size = 64 * 1024
                n = size
                while n >= size:
                    s = os.read(src, size)
                    n = os.write(dst, s)
                os.close(dst)
            else:
                # Small signature file
                with open(fn, 'wb') as sigfile:
                    sigfile.write(file_item.file.read())
        except Exception:
            if dst:
                os.close(dst)
            LOG.exception("Failed to upload load file %s" % file_item.filename)
            return None

        return fn

    @expose('json')
    @cutils.synchronized(LOCK_NAME)
    def import_load(self):
        """Import a load from iso/sig files"""
        try:
            return self._import_load()
        except Exception as e:
            # Duplicate the exception handling behavior of the wsmeext.pecan wsexpose decorator
            # This can be moved to a decorator if we need to reuse this in other modules
            exception_code = getattr(e, 'code', None)
            pecan.response.status = exception_code if wsme.utils.is_valid_code(exception_code) else 500
            return wsme.api.format_exception(sys.exc_info())

    def _import_load(self):
        """Create a new load from iso/sig files"""

        LOG.info("Load import request received.")

        system_controller_import_active = False
        data = dict((k, v) for (k, v) in request.POST.items())
        if data.get('active') == 'true':
            if pecan.request.dbapi.isystem_get_one().\
                    distributed_cloud_role == \
                    constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
                LOG.info("System Controller allow start import_load")
                system_controller_import_active = True

        # Only import loads on controller-0. This is required because the load
        # is only installed locally and we will be booting controller-1 from
        # this load during the upgrade.
        if socket.gethostname() != constants.CONTROLLER_0_HOSTNAME:
            raise wsme.exc.ClientSideError(
                _("A load can only be imported when %s is active. ") % constants.CONTROLLER_0_HOSTNAME)
        else:
            self._check_existing_loads(active_import=system_controller_import_active)

        load_files = dict()
        for f in constants.IMPORT_LOAD_FILES:
            if f not in request.POST:
                raise wsme.exc.ClientSideError(_("Missing required file for %s") % f)

            file_item = request.POST[f]
            if not file_item.filename:
                raise wsme.exc.ClientSideError(_("No %s file uploaded") % f)

            fn = self._upload_file(file_item)
            if fn:
                load_files.update({f: fn})
            else:
                raise wsme.exc.ClientSideError(_("Failed to save file %s to disk. Please check "
                            "sysinv logs for details." % file_item.filename))

        LOG.info("Load files: %s saved to disk." % load_files)

        try:
            new_load = pecan.request.rpcapi.start_import_load(
                pecan.request.context,
                load_files[constants.LOAD_ISO],
                load_files[constants.LOAD_SIGNATURE],
                system_controller_import_active)

            if new_load is None:
                raise wsme.exc.ClientSideError(_("Error importing load. Load not found"))

            if not system_controller_import_active:
                # Signature and upgrade path checks have passed, make rpc call
                # to the conductor to run import script in the background.
                pecan.request.rpcapi.import_load(
                    pecan.request.context,
                    load_files[constants.LOAD_ISO],
                    new_load)
        except common.RemoteError as e:
            if os.path.isdir(constants.LOAD_FILES_STAGING_DIR):
                shutil.rmtree(constants.LOAD_FILES_STAGING_DIR)
            raise wsme.exc.ClientSideError(e.value)

        load_data = new_load.as_dict()
        LOG.info("Load import request validated, returning new load data: %s"
                 % load_data)
        return load_data

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Load, body=Load)
    def import_load_metadata(self, load):
        """Import a new load using only the metadata. Only available to SX subcoulds."""

        LOG.info("Load import metadata request received.")
        err_msg = None

        # Enforce system type restrictions
        err_msg = _("Metadata load import is only available to simplex subclouds.")
        if utils.get_system_mode() != constants.SYSTEM_MODE_SIMPLEX:
            raise wsme.exc.ClientSideError(err_msg)
        if utils.get_distributed_cloud_role() != constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
            raise wsme.exc.ClientSideError(err_msg)

        self._check_existing_loads()

        if load.software_version == load.compatible_version:
            raise wsme.exc.ClientSideError(_("Invalid load software_version."))
        if load.compatible_version != tsc.SW_VERSION:
            raise wsme.exc.ClientSideError(_("Load compatible_version does not match SW_VERSION."))

        patch = load.as_dict()
        self._new_load_semantic_checks(patch)
        patch['state'] = constants.IMPORTED_METADATA_LOAD_STATE
        patch['uuid'] = None

        LOG.info("Load import metadata validated, creating new load: %s" % patch)
        try:
            new_load = pecan.request.dbapi.load_create(patch)
        except exception.SysinvException:
            LOG.exception("Failure to create load")
            raise wsme.exc.ClientSideError(_("Failure to create load"))

        return load.convert_with_links(new_load)

    def _check_existing_loads(self, active_import=False):
        loads = pecan.request.dbapi.load_get_list()

        # Only 2 loads are allowed at one time: the active load
        # and an imported load regardless of its current state
        # (e.g. importing, error, deleting).
        load_state = None
        if len(loads) > constants.IMPORTED_LOAD_MAX_COUNT:
            for load in loads:
                if load.state != constants.ACTIVE_LOAD_STATE:
                    load_state = load.state
        else:
            return

        if load_state == constants.ERROR_LOAD_STATE:
            err_msg = _("Please remove the load in error state "
                        "before importing a new one.")
        elif load_state == constants.DELETING_LOAD_STATE:
            err_msg = _("Please wait for the current load delete "
                        "to complete before importing a new one.")
        elif not active_import:
            # Already imported or being imported
            err_msg = _("Max number of loads (2) reached. Please "
                        "remove the old or unused load before "
                        "importing a new one.")
        else:
            return
        raise wsme.exc.ClientSideError(err_msg)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(six.text_type, [LoadPatchType])
    @wsme_pecan.wsexpose(Load, six.text_type,
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
    @wsme_pecan.wsexpose(Load, six.text_type, status_code=200)
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

        return Load.convert_with_links(load)
