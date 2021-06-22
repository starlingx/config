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
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#

import pecan
from pecan import rest
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import partition
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.agent import rpcapi as agent_rpcapi
from sysinv.common import exception
from sysinv.common import constants
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class DiskPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return ['/ihost_uuid']


class Disk(base.APIBase):
    """API representation of a host disk.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of a disk.
    """

    uuid = types.uuid
    "Unique UUID for this disk"

    device_node = wtypes.text
    "Represent the device node of the idisk. Unique per host"

    device_type = wtypes.text
    "Represent the device type of the idisk"

    device_num = int
    "The device number of the idisk"

    device_id = wtypes.text
    "The device ID of the idisk"

    device_path = wtypes.text
    "The device path of the idisk"

    device_wwn = wtypes.text
    "The device WWN of the idisk"

    size_mib = int
    "The numa node or zone sdevice of the idisk"

    available_mib = int
    "Unallocated space on the disk"

    serial_id = wtypes.text
    "link or duplex mode for this idisk"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                    six.integer_types)}
    "This disk's meta data"

    forihostid = int
    "The ihostid that this idisk belongs to"

    foristorid = int
    "The istorId that this idisk belongs to"

    foripvid = int
    "The ipvid that this idisk belongs to"

    ihost_uuid = types.uuid
    "The UUID of the host this disk belongs to"

    istor_uuid = types.uuid
    "The UUID of the interface this disk belongs to"

    ipv_uuid = types.uuid
    "The UUID of the physical volume this disk belongs to"

    partitions = [link.Link]
    "Links to the collection of partitions on this idisk"

    links = [link.Link]
    "A list containing a self link and associated disk links"

    rpm = wtypes.text
    "Revolutions per minute. 'Undetermined' if not specified. 'N/A', not "
    "applicable for SSDs."

    def __init__(self, **kwargs):
        self.fields = list(objects.disk.fields.keys())
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_disk, expand=True):
        # fields = ['uuid', 'address'] if not expand else None
        # disk = idisk.from_rpc_object(rpc_disk, fields)

        disk = Disk(**rpc_disk.as_dict())
        if not expand:
            disk.unset_fields_except(['uuid', 'device_node', 'device_num',
                               'device_type', 'device_id', 'device_path',
                               'device_wwn', 'size_mib', 'available_mib',
                               'rpm', 'serial_id', 'forihostid', 'foristorid',
                               'foripvid', 'ihost_uuid', 'istor_uuid', 'ipv_uuid',
                               'capabilities', 'created_at', 'updated_at'])

        # never expose the id attribute
        disk.forihostid = wtypes.Unset
        disk.foristorid = wtypes.Unset
        disk.foripvid = wtypes.Unset

        disk.links = [link.Link.make_link('self', pecan.request.host_url,
                                          'idisks', disk.uuid),
                      link.Link.make_link('bookmark',
                                          pecan.request.host_url,
                                          'idisks', disk.uuid,
                                          bookmark=True)
                      ]

        if expand:
            disk.partitions = [link.Link.make_link('self',
                                                   pecan.request.host_url,
                                                   'idisks',
                                                   disk.uuid + "/partitions"),
                               link.Link.make_link(
                                   'bookmark',
                                   pecan.request.host_url,
                                   'idisks',
                                   disk.uuid + "/partitions",
                                   bookmark=True)
                               ]
        return disk


class DiskCollection(collection.Collection):
    """API representation of a collection of disks."""

    idisks = [Disk]
    "A list containing disk objects"

    def __init__(self, **kwargs):
        self._type = 'idisks'

    @classmethod
    def convert_with_links(cls, rpc_disks, limit, url=None,
                           expand=False, **kwargs):
        collection = DiskCollection()
        collection.idisks = [Disk.convert_with_links(
                                      p, expand)
                             for p in rpc_disks]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'DiskController'


class DiskController(rest.RestController):
    """REST controller for idisks."""

    _custom_actions = {
        'detail': ['GET'],
    }

    partitions = partition.PartitionController(from_ihosts=True,
                                               from_idisk=True)
    "Expose partitions as a sub-element of idisks"

    def __init__(self, from_ihosts=False, from_istor=False, from_ipv=False):
        self._from_ihosts = from_ihosts
        self._from_istor = from_istor
        self._from_ipv = from_ipv

    def _get_disks_collection(self, i_uuid, istor_uuid, ipv_uuid,
                              marker, limit, sort_key, sort_dir, expand=False,
                              resource_url=None):

        if self._from_ihosts and not i_uuid:
            raise exception.InvalidParameterValue(_(
                  "Host id not specified."))

        if self._from_istor and not i_uuid:
            raise exception.InvalidParameterValue(_(
                  "Interface id not specified."))

        if self._from_ipv and not i_uuid:
            raise exception.InvalidParameterValue(_(
                "Physical Volume id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.disk.get_by_uuid(
                                        pecan.request.context,
                                        marker)

        if self._from_ihosts:
            disks = pecan.request.dbapi.idisk_get_by_ihost(
                                                    i_uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
        elif self._from_istor:
            disks = pecan.request.dbapi.idisk_get_by_istor(
                                                    i_uuid,
                                                    limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
        elif self._from_ipv:
            disks = pecan.request.dbapi.idisk_get_by_ipv(
                i_uuid,
                limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)
        else:
            if i_uuid and not istor_uuid and not ipv_uuid:
                disks = pecan.request.dbapi.idisk_get_by_ihost(
                                                    i_uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

            elif i_uuid and istor_uuid:   # Need ihost_uuid ?
                disks = pecan.request.dbapi.idisk_get_by_ihost_istor(
                                                    i_uuid,
                                                    istor_uuid,
                                                    limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

            elif istor_uuid:   # Need ihost_uuid ?
                disks = pecan.request.dbapi.idisk_get_by_ihost_istor(
                                                    i_uuid,  # None
                                                    istor_uuid,
                                                    limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

            elif i_uuid and ipv_uuid:   # Need ihost_uuid ?
                disks = pecan.request.dbapi.idisk_get_by_ihost_ipv(
                                                    i_uuid,
                                                    ipv_uuid,
                                                    limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

            elif ipv_uuid:   # Need ihost_uuid ?
                disks = pecan.request.dbapi.idisk_get_by_ihost_ipv(
                                                    i_uuid,  # None
                                                    ipv_uuid,
                                                    limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

            else:
                disks = pecan.request.dbapi.idisk_get_list(
                                                    limit, marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

        return DiskCollection.convert_with_links(disks, limit,
                                                 url=resource_url,
                                                 expand=expand,
                                                 sort_key=sort_key,
                                                 sort_dir=sort_dir)

    @wsme_pecan.wsexpose(DiskCollection, types.uuid, types.uuid, types.uuid,
                         types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, i_uuid=None, istor_uuid=None, ipv_uuid=None,
                marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of disks."""

        return self._get_disks_collection(i_uuid, istor_uuid, ipv_uuid,
                                          marker, limit, sort_key, sort_dir)

    @wsme_pecan.wsexpose(DiskCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, i_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of disks with detail."""
        # NOTE(lucasagomes): /detail should only work agaist collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "idisks":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['disks', 'detail'])
        return self._get_disks_collection(i_uuid, marker, limit, sort_key,
                                          sort_dir, expand, resource_url)

    @wsme_pecan.wsexpose(Disk, types.uuid)
    def get_one(self, disk_uuid):
        """Retrieve information about the given disk."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_disk = objects.disk.get_by_uuid(
                                        pecan.request.context, disk_uuid)
        return Disk.convert_with_links(rpc_disk)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Disk, body=Disk)
    def post(self, disk):
        """Create a new disk."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        try:
            ihost_uuid = disk.ihost_uuid
            new_disk = pecan.request.dbapi.idisk_create(ihost_uuid,
                                                        disk.as_dict())
        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data"))
        return Disk.convert_with_links(new_disk)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, disk_uuid):
        """Delete a disk."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        pecan.request.dbapi.idisk_destroy(disk_uuid)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [DiskPatchType])
    @wsme_pecan.wsexpose(Disk, types.uuid,
                         body=[DiskPatchType])
    def patch(self, idisk_uuid, patch):
        """Update an existing disk."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_idisk = objects.disk.get_by_uuid(
            pecan.request.context, idisk_uuid)

        format_supported = True
        for p in patch:
            if p['path'] == '/skip_formatting':
                skip_format = p['value'].lower() == 'true'
            if p['path'] == '/partition_table':
                value = p['value']
                if value != constants.PARTITION_TABLE_GPT:
                    format_supported = False

        if not format_supported:
            raise wsme.exc.ClientSideError(
                _("Only %s disk formatting is supported." %
                  constants.PARTITION_TABLE_GPT))

        _semantic_checks_format(rpc_idisk.as_dict())

        is_cinder_device = False
        rpcapi = agent_rpcapi.AgentAPI()
        rpcapi.disk_prepare(pecan.request.context,
                            rpc_idisk.get('ihost_uuid'),
                            rpc_idisk.as_dict(),
                            skip_format,
                            is_cinder_device)


def _semantic_checks_format(idisk):
    ihost_uuid = idisk.get('ihost_uuid')
    # Check the disk belongs to a controller or worker host.
    ihost = pecan.request.dbapi.ihost_get(ihost_uuid)
    if ihost.personality not in [constants.CONTROLLER, constants.WORKER]:
        raise wsme.exc.ClientSideError(
            _("ERROR: Host personality must be a one of %s, %s]") %
            (constants.CONTROLLER, constants.WORKER))

    # Check disk is not the rootfs disk.
    capabilities = idisk['capabilities']
    if ('stor_function' in capabilities and
            capabilities['stor_function'] == 'rootfs'):
        raise wsme.exc.ClientSideError(
            _("ERROR: Cannot wipe and GPT format the rootfs disk."))

    # Check the disk is not used by a PV and doesn't have partitions used by
    # a PV.
    ipvs = pecan.request.dbapi.ipv_get_by_ihost(ihost_uuid)
    for ipv in ipvs:
        if idisk.get('device_path') in ipv.disk_or_part_device_path:
            raise wsme.exc.ClientSideError(
                _("ERROR: Can only wipe and GPT format a disk that is not "
                  "used and does not have partitions used by a physical "
                  "volume."))
