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
# Copyright (c) 2015-2021 Wind River Systems, Inc.
#

import json

import os
import pecan
from pecan import rest
import psutil
import six
import shutil
import socket
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from eventlet.green import subprocess
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
from sysinv.openstack.common import rpc
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
        self.fields = list(objects.load.fields.keys())
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
        raise NotImplementedError("This API is deprecated.")

    @wsme_pecan.wsexpose(LoadCollection, types.uuid, int, wtypes.text,
                         wtypes.text)
    def detail(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of loads with detail."""

        raise NotImplementedError("This API is deprecated.")

    @wsme_pecan.wsexpose(Load, six.text_type)
    def get_one(self, load_uuid):
        """Retrieve information about the given Load."""

        raise NotImplementedError("This API is deprecated.")

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
        # TODO(ShawnLi): This will be removed when we remove the Load table
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
        try:
            staging_dir = constants.LOAD_FILES_STAGING_DIR
            if not os.path.isdir(staging_dir):
                os.makedirs(staging_dir)

            source_file = file_item.file
            staging_file = os.path.join(staging_dir,
                              os.path.basename(file_item.filename))

            if source_file is None:
                raise wsme.exc.ClientSideError(_("Failed to upload load file %s,\
                                                 invalid file object" % staging_file))

            # This try block is to get only the iso file size as
            # the signature file object type is different in Debian than CentOS
            # and it has fileno() attribute but is not a supported operation on Debian
            #
            # The check for st_size is required to determine the file size of iso image
            # It is not applicable to its signature file
            try:
                file_size = os.fstat(source_file.fileno()).st_size
            except Exception:
                file_size = -1

            if file_size >= 0:
                # Only proceed if there is space available for copying
                avail_space = psutil.disk_usage('/scratch').free
                if (avail_space < file_size):
                    raise wsme.exc.ClientSideError(_("Failed to upload load file %s, not enough space on /scratch"
                              " partition: %d bytes available "
                              % (staging_file, avail_space)))

                # Large iso file, allocate the required space
                subprocess.check_call(["/usr/bin/fallocate",  # pylint: disable=not-callable
                                       "-l " + str(file_size), staging_file])

            with open(staging_file, 'wb') as destination_file:
                shutil.copyfileobj(source_file, destination_file)

        except subprocess.CalledProcessError as e:
            if os.path.isfile(staging_file):
                os.remove(staging_file)
            raise wsme.exc.ClientSideError(_("Failed to upload load file %s, /usr/bin/fallocate error: %s"
                      % (staging_file, e.output)))
        except Exception:
            if os.path.isfile(staging_file):
                os.remove(staging_file)
            raise wsme.exc.ClientSideError(_("Failed to upload load file %s" % file_item.filename))

        return staging_file

    @expose('json')
    @cutils.synchronized(LOCK_NAME)
    def import_load(self):
        """Import a load from iso/sig files"""
        raise NotImplementedError("This API is deprecated.")

    def _import_load(self):
        """Create a new load from iso/sig files"""

        LOG.info("Load import request received.")

        # Only import loads on controller-0. This is required because the load
        # is only installed locally and we will be booting controller-1 from
        # this load during the upgrade.
        if socket.gethostname() != constants.CONTROLLER_0_HOSTNAME:
            raise wsme.exc.ClientSideError(_("A load can only be imported when"
                                             " %s is active.")
                                             % constants.CONTROLLER_0_HOSTNAME)

        req_content = dict()
        load_files = dict()
        is_multiform_req = True
        import_type = None

        # Request coming from dc-api-proxy is not multiform, file transfer is handled
        # by dc-api-proxy, the request contains only the vault file location
        if request.content_type == "application/json":
            req_content = dict(json.loads(request.body))
            is_multiform_req = False
        else:
            req_content = dict(request.POST.items())

        if not req_content:
            raise wsme.exc.ClientSideError(_("Empty request."))

        active = req_content.get('active')
        inactive = req_content.get('inactive')

        if active == 'true' and inactive == 'true':
            raise wsme.exc.ClientSideError(_("Invalid use of --active and"
                                             " --inactive arguments at"
                                             " the same time."))

        if active == 'true' or inactive == 'true':
            isystem = pecan.request.dbapi.isystem_get_one()

            if isystem.distributed_cloud_role == \
                    constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
                LOG.info("System Controller allow start import_load")

                if active == 'true':
                    import_type = constants.ACTIVE_LOAD_IMPORT
                elif inactive == 'true':
                    import_type = constants.INACTIVE_LOAD_IMPORT

        self._check_existing_loads(import_type=import_type)

        try:
            for file in constants.IMPORT_LOAD_FILES:
                if file not in req_content:
                    raise wsme.exc.ClientSideError(_("Missing required file for %s")
                                                % file)

                if not is_multiform_req:
                    load_files.update({file: req_content[file]})
                else:
                    if file not in request.POST:
                        raise wsme.exc.ClientSideError(_("Missing required file for %s")
                                                        % file)

                    file_item = request.POST[file]
                    if not file_item.filename:
                        raise wsme.exc.ClientSideError(_("No %s file uploaded") % file)

                    file_location = self._upload_file(file_item)
                    if file_location:
                        load_files.update({file: file_location})
        except subprocess.CalledProcessError as ex:
            raise wsme.exc.ClientSideError(str(ex))
        except Exception as ex:
            raise wsme.exc.ClientSideError(_("Failed to save file %s to disk. Error: %s"
                                             " Please check sysinv logs for"
                                             " details." % (file_item.filename, str(ex))))

        LOG.info("Load files: %s saved to disk." % load_files)

        exception_occured = False
        try:
            new_load = pecan.request.rpcapi.start_import_load(
                pecan.request.context,
                load_files[constants.LOAD_ISO],
                load_files[constants.LOAD_SIGNATURE],
                import_type,
            )

            if new_load is None:
                raise wsme.exc.ClientSideError(_("Error importing load. Load not found"))

            if import_type != constants.ACTIVE_LOAD_IMPORT:
                # Signature and upgrade path checks have passed, make rpc call
                # to the conductor to run import script in the background.
                pecan.request.rpcapi.import_load(
                    pecan.request.context,
                    load_files[constants.LOAD_ISO],
                    new_load,
                    import_type,
                )
        except (rpc.common.Timeout, common.RemoteError) as e:
            exception_occured = True
            error = e.value if hasattr(e, 'value') else str(e)
            raise wsme.exc.ClientSideError(error)
        except Exception:
            exception_occured = True
            raise
        finally:
            if exception_occured and os.path.isdir(constants.LOAD_FILES_STAGING_DIR):
                shutil.rmtree(constants.LOAD_FILES_STAGING_DIR)

        load_data = new_load.as_dict()
        LOG.info("Load import request validated, returning new load data: %s"
                 % load_data)
        return load_data

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Load, body=Load)
    def import_load_metadata(self, load):
        """Import a new load using only the metadata. Only available to SX subcoulds."""

        raise NotImplementedError("This API is deprecated.")

    def _check_existing_loads(self, import_type=None):
        # Only are allowed at one time:
        # - the active load
        # - an imported load regardless of its current state
        # - an inactive load.

        loads = pecan.request.dbapi.load_get_list()

        if len(loads) <= constants.IMPORTED_LOAD_MAX_COUNT:
            return

        for load in loads:
            if load.state == constants.ACTIVE_LOAD_STATE:
                continue

            load_state = load.state

            if load_state == constants.ERROR_LOAD_STATE:
                err_msg = _("Please remove the load in error state "
                            "before importing a new one.")

            elif load_state == constants.DELETING_LOAD_STATE:
                err_msg = _("Please wait for the current load delete "
                            "to complete before importing a new one.")

            elif load_state == constants.INACTIVE_LOAD_STATE:
                if import_type != constants.INACTIVE_LOAD_IMPORT:
                    continue

                err_msg = _("An inactived load already exists. "
                        "Please, remove the inactive load "
                        "before trying to import a new one.")

            elif import_type == constants.ACTIVE_LOAD_IMPORT or \
                    import_type == constants.INACTIVE_LOAD_IMPORT:
                continue

            elif not err_msg:
                # Already imported or being imported
                err_msg = _("Max number of loads (2) reached. Please "
                            "remove the old or unused load before "
                            "importing a new one.")

            raise wsme.exc.ClientSideError(err_msg)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(six.text_type, [LoadPatchType])
    @wsme_pecan.wsexpose(Load, six.text_type,
                         body=[LoadPatchType])
    def patch(self, load_id, patch):
        """Update an existing load."""

        raise NotImplementedError("This API is deprecated.")

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Load, six.text_type, status_code=200)
    def delete(self, load_id):
        """Delete a load."""

        raise NotImplementedError("This API is deprecated.")
