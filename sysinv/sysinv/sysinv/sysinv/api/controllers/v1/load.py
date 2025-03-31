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


import os
import pecan
from pecan import rest
import psutil
import six
import shutil
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from eventlet.green import subprocess
from oslo_log import log
from pecan import expose
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.common import constants
from sysinv.common import utils as cutils
from sysinv import objects

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
        raise NotImplementedError("This API is deprecated.")

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Load, body=Load)
    def import_load_metadata(self, load):
        """Import a new load using only the metadata. Only available to SX subcoulds."""

        raise NotImplementedError("This API is deprecated.")

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
