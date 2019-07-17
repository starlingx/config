# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
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


import jsonpatch
import six

import pecan
from pecan import rest

import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import disk as disk_api
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common.storage_backend_conf import StorageBackendConfig
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log
from sysinv.openstack.common.rpc import common as rpc_common
from sysinv.openstack.common import uuidutils

LOG = log.getLogger(__name__)


class PVPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return ['/address', '/ihost_uuid']


class PV(base.APIBase):
    """API representation of an LVM Physical Volume.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    an pv.
    """

    uuid = types.uuid
    "Unique UUID for this pv"

    pv_state = wtypes.text
    "Represent the transition state of the ipv"

    pv_type = wtypes.text
    "Represent the type of pv"

    disk_or_part_uuid = types.uuid
    "idisk or partition UUID for this pv"

    disk_or_part_device_node = wtypes.text
    "idisk or partition device node name for this pv on the ihost"

    disk_or_part_device_path = wtypes.text
    "idisk or partition device path for this pv on the ihost"

    lvm_pv_name = wtypes.text
    "LVM physical volume name"

    lvm_vg_name = wtypes.text
    "LVM physical volume's reported volume group name"

    lvm_pv_uuid = wtypes.text
    "LVM physical volume's reported uuid string"

    lvm_pv_size = int
    "LVM physical volume's size"

    lvm_pe_total = int
    "LVM physical volume's PE total"

    lvm_pe_alloced = int
    "LVM physical volume's allocated PEs"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                    six.integer_types)}
    "This pv's meta data"

    forihostid = int
    "The ihostid that this ipv belongs to"

    ihost_uuid = types.uuid
    "The UUID of the host this pv belongs to"

    forilvgid = int
    "The ilvgid that this ipv belongs to"

    ilvg_uuid = types.uuid
    "The UUID of the lvg this pv belongs to"

    links = [link.Link]
    "A list containing a self link and associated pv links"

    idisks = [link.Link]
    "Links to the collection of idisks on this pv"

    partitions = [link.Link]
    "Links to the collection of partitions on this pv"

    def __init__(self, **kwargs):
        self.fields = objects.pv.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        if not self.uuid:
            self.uuid = uuidutils.generate_uuid()

    @classmethod
    def convert_with_links(cls, rpc_pv, expand=True):
        pv = PV(**rpc_pv.as_dict())
        if not expand:
            pv.unset_fields_except([
                'uuid', 'pv_state', 'pv_type', 'capabilities',
                'disk_or_part_uuid', 'disk_or_part_device_node',
                'disk_or_part_device_path', 'lvm_pv_name', 'lvm_vg_name',
                'lvm_pv_uuid', 'lvm_pv_size', 'lvm_pe_alloced', 'lvm_pe_total',
                'ilvg_uuid', 'forilvgid', 'ihost_uuid', 'forihostid',
                'created_at', 'updated_at'])

        # never expose the ihost_id attribute, allow exposure for now
        pv.forihostid = wtypes.Unset
        pv.links = [link.Link.make_link('self', pecan.request.host_url,
                                        'ipvs', pv.uuid),
                      link.Link.make_link('bookmark',
                                          pecan.request.host_url,
                                          'ipvs', pv.uuid,
                                          bookmark=True)
                    ]
        if expand:
            pv.idisks = [link.Link.make_link('self',
                                             pecan.request.host_url,
                                             'ipvs',
                                             pv.uuid + "/idisks"),
                         link.Link.make_link(
                             'bookmark',
                             pecan.request.host_url,
                             'ipvs',
                             pv.uuid + "/idisks",
                             bookmark=True)
                         ]

            pv.partitions = [link.Link.make_link('self',
                                                 pecan.request.host_url,
                                                 'ipvs',
                                                 pv.uuid + "/partitions"),
                             link.Link.make_link(
                                 'bookmark',
                                 pecan.request.host_url,
                                 'ipvs',
                                 pv.uuid + "/partitions",
                                 bookmark=True)
                             ]

        return pv


class PVCollection(collection.Collection):
    """API representation of a collection of pvs."""

    ipvs = [PV]
    "A list containing pv objects"

    def __init__(self, **kwargs):
        self._type = 'ipvs'

    @classmethod
    def convert_with_links(cls, rpc_pvs, limit, url=None,
                           expand=False, **kwargs):
        collection = PVCollection()
        collection.ipvs = [PV.convert_with_links(p, expand)
                           for p in rpc_pvs]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'PVController'


class PVController(rest.RestController):
    """REST controller for ipvs."""

    idisks = disk_api.DiskController(from_ihosts=True, from_ipv=True)
    "Expose idisks as a sub-element of ipvs"

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_ihosts=False, from_ilvg=False):
        self._from_ihosts = from_ihosts
        self._from_ilvg = from_ilvg

    def _get_pvs_collection(self, ihost_uuid, marker, limit, sort_key,
                              sort_dir, expand=False, resource_url=None):
        if self._from_ihosts and not ihost_uuid:
            raise exception.InvalidParameterValue(_(
                  "Host id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.pv.get_by_uuid(
                                        pecan.request.context,
                                        marker)

        if ihost_uuid:
            pvs = pecan.request.dbapi.ipv_get_by_ihost(ihost_uuid, limit,
                                                       marker_obj,
                                                       sort_key=sort_key,
                                                       sort_dir=sort_dir)
        else:
            pvs = pecan.request.dbapi.ipv_get_list(limit, marker_obj,
                                                   sort_key=sort_key,
                                                   sort_dir=sort_dir)

        return PVCollection.convert_with_links(pvs, limit,
                                               url=resource_url,
                                               expand=expand,
                                               sort_key=sort_key,
                                               sort_dir=sort_dir)

    @wsme_pecan.wsexpose(PVCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, ihost_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of pvs."""

        return self._get_pvs_collection(ihost_uuid, marker, limit,
                                          sort_key, sort_dir)

    @wsme_pecan.wsexpose(PVCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, ihost_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of pvs with detail."""
        # NOTE(lucasagomes): /detail should only work against collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "ipvs":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['pvs', 'detail'])
        return self._get_pvs_collection(ihost_uuid,
                                               marker, limit,
                                               sort_key, sort_dir,
                                               expand, resource_url)

    @wsme_pecan.wsexpose(PV, types.uuid)
    def get_one(self, pv_uuid):
        """Retrieve information about the given pv."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_pv = objects.pv.get_by_uuid(
                                        pecan.request.context, pv_uuid)
        return PV.convert_with_links(rpc_pv)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(PV, body=PV)
    def post(self, pv):
        """Create a new pv."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        try:
            pv = pv.as_dict()
            LOG.debug("pv post dict= %s" % pv)

            new_pv = _create(pv)
        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data: failed to create "
                                             "a physical volume object"))

        return PV.convert_with_links(new_pv)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [PVPatchType])
    @wsme_pecan.wsexpose(PV, types.uuid,
                         body=[PVPatchType])
    def patch(self, pv_uuid, patch):
        """Update an existing pv."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        LOG.debug("patch_data: %s" % patch)

        rpc_pv = objects.pv.get_by_uuid(
                       pecan.request.context, pv_uuid)

        # replace ihost_uuid and ipv_uuid with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)
        for p in patch_obj:
            if p['path'] == '/ihost_uuid':
                p['path'] = '/forihostid'
                ihost = objects.host.get_by_uuid(pecan.request.context,
                                                 p['value'])
                p['value'] = ihost.id

        try:
            pv = PV(**jsonpatch.apply_patch(rpc_pv.as_dict(),
                                            patch_obj))
        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Semantic Checks
        _check("modify", pv)
        try:
            # Update only the fields that have changed
            for field in objects.pv.fields:
                if rpc_pv[field] != getattr(pv, field):
                    rpc_pv[field] = getattr(pv, field)

            # Save and return
            rpc_pv.save()
            return PV.convert_with_links(rpc_pv)
        except exception.HTTPNotFound:
            msg = _("PV update failed: host %s pv %s : patch %s"
                    % (ihost['hostname'], pv['lvm_pv_name'], patch))
            raise wsme.exc.ClientSideError(msg)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, pv_uuid):
        """Delete a pv."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        delete_pv(pv_uuid)


# This method allows creating a physical volume through a non-HTTP
# request e.g. through profile.py while still passing
# through physical volume semantic checks and osd configuration
# Hence, not declared inside a class
#
# Param:
#       pv - dictionary of physical volume values
#       iprofile - True when created by a storage profile
def _create(pv, iprofile=None):
    LOG.debug("pv._create with initial params: %s" % pv)
    # Get host
    ihostId = pv.get('forihostid') or pv.get('ihost_uuid')
    ihost = pecan.request.dbapi.ihost_get(ihostId)
    if uuidutils.is_uuid_like(ihostId):
        forihostid = ihost['id']
    else:
        forihostid = ihostId
    pv.update({'forihostid': forihostid})

    pv['ihost_uuid'] = ihost['uuid']

    # Set defaults - before checks to allow for optional attributes
    pv = _set_defaults(pv)

    # Semantic checks
    pv = _check("add", pv)

    LOG.debug("pv._create with validated params: %s" % pv)

    # See if this volume group already exists
    ipvs = pecan.request.dbapi.ipv_get_all(forihostid=forihostid)
    pv_in_db = False
    for ipv in ipvs:
        if ipv['disk_or_part_device_path'] == pv['disk_or_part_device_path']:
            pv_in_db = True
            # TODO(rchurch): Refactor PV_ERR. Still needed?
            # User is adding again so complain
            if (ipv['pv_state'] in [constants.PV_ADD,
                                    constants.PROVISIONED,
                                    constants.PV_ERR]):

                raise wsme.exc.ClientSideError(_("Physical Volume (%s) "
                                                 "already present" %
                                                 ipv['lvm_pv_name']))
            # User changed mind and is re-adding
            if ipv['pv_state'] == constants.PV_DEL:
                values = {'pv_state': constants.PV_ADD}
                try:
                    pecan.request.dbapi.ipv_update(ipv.id, values)
                except exception.HTTPNotFound:
                    msg = _("PV update failed: host (%s) PV (%s)"
                            % (ihost['hostname'], ipv['lvm_pv_name']))
                    raise wsme.exc.ClientSideError(msg)
            ret_pv = ipv
            break

    if not pv_in_db:
        ret_pv = pecan.request.dbapi.ipv_create(forihostid, pv)

    LOG.debug("pv._create final, created, pv: %s" % ret_pv.as_dict())

    # Associate the pv to the disk or partition record.
    values = {'foripvid': ret_pv.id}
    if pv['pv_type'] == constants.PV_TYPE_DISK:
        pecan.request.dbapi.idisk_update(ret_pv.disk_or_part_uuid,
                                         values)
    elif pv['pv_type'] == constants.PV_TYPE_PARTITION:
        pecan.request.dbapi.partition_update(ret_pv.disk_or_part_uuid,
                                             values)

    # semantic check for root disk
    if iprofile is not True and constants.WARNING_MESSAGE_INDEX in pv:
        warning_message_index = pv.get(constants.WARNING_MESSAGE_INDEX)
        raise wsme.exc.ClientSideError(
            constants.PV_WARNINGS[warning_message_index])

    # for CPE nodes we allow extending of cgts-vg to an unused partition.
    # this will inform the conductor and agent to apply the lvm manifest
    # without requiring a lock-unlock cycle.
    # for non-cpe nodes, the rootfs disk is already partitioned to be fully
    # used by the cgts-vg volume group.
    if ret_pv.lvm_vg_name == constants.LVG_CGTS_VG:
        pecan.request.rpcapi.update_lvm_config(pecan.request.context)

    return ret_pv


def _set_defaults(pv):
    defaults = {
        'pv_state': constants.PV_ADD,
        'pv_type': constants.PV_TYPE_DISK,
        'lvm_pv_uuid': None,
        'lvm_pv_size': 0,
        'lvm_pe_total': 0,
        'lvm_pe_alloced': 0,
    }

    pv_merged = pv.copy()
    for key in pv_merged:
        if pv_merged[key] is None and key in defaults:
            pv_merged[key] = defaults[key]

    return pv_merged


def _check_host(pv, ihost, op):
    ilvgid = pv.get('forilvgid') or pv.get('ilvg_uuid')

    ilvgid = pv.get('forilvgid') or pv.get('ilvg_uuid')
    if ilvgid is None:
        LOG.warn("check_host: lvg is None from pv.  return.")
        return

    ilvg = pecan.request.dbapi.ilvg_get(ilvgid)

    if (ilvg.lvm_vg_name == constants.LVG_CGTS_VG):
        if (ihost['personality'] != constants.CONTROLLER and
                ihost['personality'] != constants.WORKER):
            raise wsme.exc.ClientSideError(
                _("Physical volume operations for %s are only "
                  "supported on %s and %s hosts" %
                  (constants.LVG_CGTS_VG,
                   constants.WORKER,
                   constants.CONTROLLER)))

    # semantic check: host must be locked for a nova-local change on
    # a host with a worker subfunction (worker or AIO)
    if (constants.WORKER in ihost['subfunctions'] and
            ilvg.lvm_vg_name == constants.LVG_NOVA_LOCAL and
            (ihost['administrative'] != constants.ADMIN_LOCKED or
             ihost['ihost_action'] == constants.UNLOCK_ACTION)):
        raise wsme.exc.ClientSideError(_("Host must be locked"))

    # semantic check: host must be locked for a CGTS change on
    # a worker host.
    if (ihost['personality'] == constants.WORKER and
            ilvg.lvm_vg_name == constants.LVG_CGTS_VG and
            (ihost['administrative'] != constants.ADMIN_LOCKED or
             ihost['ihost_action'] == constants.UNLOCK_ACTION)):
        raise wsme.exc.ClientSideError(_("Host must be locked"))


def _get_vg_size_from_pvs(lvg, filter_pv=None):
    ipvs = pecan.request.dbapi.ipv_get_by_ihost(lvg['forihostid'])
    if not ipvs:
        raise wsme.exc.ClientSideError(
            _("Volume Group %s does not have any PVs assigned. "
              "Assign PVs first." % lvg['lvm_vg_name']))

    size = 0
    for pv in ipvs:
        # Skip the physical volume. Used to calculate potential new size of a
        # physical volume is deleted
        if filter_pv and pv['uuid'] == filter_pv['uuid']:
            continue

        # Only use physical volumes that belong to this volume group and are
        # not in the removing state
        if ((pv['lvm_vg_name'] == lvg['lvm_vg_name']) and
                (pv['pv_state'] != constants.LVG_DEL)):

            idisks = pecan.request.dbapi.idisk_get_by_ipv(pv['uuid'])
            partitions = pecan.request.dbapi.partition_get_by_ipv(pv['uuid'])

            if not idisks and not partitions:
                raise wsme.exc.ClientSideError(
                    _("Internal Error: PV %s does not have an associated idisk"
                      " or partition" % pv.uuid))

            if len(idisks) > 1:
                raise wsme.exc.ClientSideError(
                    _("Internal Error: More than one idisk associated with PV "
                      "%s " % pv.uuid))
            elif len(partitions) > 1:
                raise wsme.exc.ClientSideError(
                    _("Internal Error: More than one partition associated with"
                      "PV %s " % pv.uuid))
            elif len(idisks) + len(partitions) > 1:
                raise wsme.exc.ClientSideError(
                    _("Internal Error: At least one disk and one partition "
                      "associated with PV %s " % pv.uuid))

            if idisks:
                size += idisks[0]['size_mib']
            elif partitions:
                size += partitions[0]['size_mib']

    # Might have the case of a single PV being added, then removed.
    # Or on the combo node we have other VGs with PVs present.
    if size == 0:
        raise wsme.exc.ClientSideError(
            _("Volume Group %s must contain physical volumes. "
              % lvg['lvm_vg_name']))

    return size


def _check_lvg(op, pv):
    # semantic check whether idisk is associated
    ilvgid = pv.get('forilvgid') or pv.get('ilvg_uuid')
    if ilvgid is None:
        LOG.warn("check_lvg: lvg is None from pv.  return.")
        return

    # Get the associated volume group record
    ilvg = pecan.request.dbapi.ilvg_get(ilvgid)

    # In a combo node we also have cinder and drbd physical volumes.
    if ilvg.lvm_vg_name not in constants.LVG_ALLOWED_VGS:
        raise wsme.exc.ClientSideError(_("This operation can not be performed"
                                         " on Local Volume Group %s"
                                         % ilvg.lvm_vg_name))

    # Make sure that the volume group is in the adding/provisioned state
    if ilvg.vg_state == constants.LVG_DEL:
        raise wsme.exc.ClientSideError(
            _("Local volume Group. %s set to be deleted. Add it again to allow"
              " adding physical volumes. " % ilvg.lvm_vg_name))

    # Semantic Checks: Based on PV operations
    if op == "add":
        if ilvg.lvm_vg_name == constants.LVG_CGTS_VG:
            controller_fs_list = pecan.request.dbapi.controller_fs_get_list()
            for controller_fs in controller_fs_list:
                if controller_fs.state == constants.CONTROLLER_FS_RESIZING_IN_PROGRESS:
                    msg = _(
                        "Filesystem (%s) resize is in progress. Wait fot the resize "
                        "to finish before adding a physical volume to the cgts-vg "
                        "volume group." % controller_fs.name)
                    raise wsme.exc.ClientSideError(msg)

    elif op == "delete":
        if (ilvg.lvm_vg_name == constants.LVG_CGTS_VG):
            raise wsme.exc.ClientSideError(
                _("Physical volumes cannot be removed from the cgts-vg volume "
                  "group."))
        if ilvg.lvm_vg_name == constants.LVG_CINDER_VOLUMES:
            if ((pv['pv_state'] in
                [constants.PROVISIONED, constants.PV_ADD]) and
                StorageBackendConfig.has_backend(
                    pecan.request.dbapi, constants.CINDER_BACKEND_LVM)):
                raise wsme.exc.ClientSideError(
                    _("Physical volume %s cannot be removed from cinder-volumes LVG once "
                      "it is provisioned and LVM backend is added." % pv['lvm_pv_name']))

    elif op == "modify":
        pass
    else:
        raise wsme.exc.ClientSideError(
            _("Internal Error: Invalid Physical Volume operation: %s" % op))

    # LVG check passes
    pv['lvm_vg_name'] = ilvg.lvm_vg_name

    return


def _check_parameters(pv):

    # Disk/Partition should be provided for all cases
    if 'disk_or_part_uuid' not in pv:
        LOG.error(_("Missing idisk_uuid."))
        raise wsme.exc.ClientSideError(_("Invalid data: Missing "
                                         "disk_or_part_uuid. Failed to create a"
                                         " physical volume object"))

    # LVG should be provided for all cases
    if 'ilvg_uuid' not in pv and 'forilvgid' not in pv:
        LOG.error(_("Missing ilvg_uuid."))
        raise wsme.exc.ClientSideError(_("Invalid data: Missing ilvg_uuid."
                                         " Failed to create a physical "
                                         "volume object"))


def _check_device(new_pv, ihost):
    """Check that the PV is not requesting a device that is already used."""

    # derive the correct pv_type based on the UUID provided
    try:
        new_pv_device = pecan.request.dbapi.idisk_get(
            new_pv['disk_or_part_uuid'])
        new_pv['pv_type'] = constants.PV_TYPE_DISK
    except exception.DiskNotFound:
        try:
            new_pv_device = pecan.request.dbapi.partition_get(
                new_pv['disk_or_part_uuid'])
            new_pv['pv_type'] = constants.PV_TYPE_PARTITION
        except exception.DiskPartitionNotFound:
            raise wsme.exc.ClientSideError(
                _("Invalid data: The device %s associated with %s does not "
                  "exist.") % new_pv['disk_or_part_uuid'])

    # Fill in the volume group info
    ilvgid = new_pv.get('forilvgid') or new_pv.get('ilvg_uuid')
    ilvg = pecan.request.dbapi.ilvg_get(ilvgid)
    new_pv['forilvgid'] = ilvg['id']
    new_pv['lvm_vg_name'] = ilvg['lvm_vg_name']

    if new_pv['pv_type'] == constants.PV_TYPE_DISK:
        # semantic check: Can't associate cinder-volumes to a disk
        if ilvg.lvm_vg_name == constants.LVG_CINDER_VOLUMES:
            raise wsme.exc.ClientSideError(
                _("Invalid data: cinder-volumes PV has to be partition based."))

        capabilities = new_pv_device['capabilities']

        # semantic check: Can't associate the rootfs disk with a physical volume
        if ('stor_function' in capabilities and
                capabilities['stor_function'] == 'rootfs'):
            raise wsme.exc.ClientSideError(_("Cannot assign the rootfs disk "
                                             "to a physical volume."))

        # semantic check: Can't add the disk if it's already associated
        # with a physical volume
        if new_pv_device.foripvid is not None:
            raise wsme.exc.ClientSideError(_("Disk already assigned to a "
                                             "physical volume."))

        # semantic check: Can't add the disk if it's already associated
        # with a storage volume
        if new_pv_device.foristorid is not None:
            raise wsme.exc.ClientSideError(_("Disk already assigned to a "
                                             "storage volume."))

        # semantic check: Make sure that partitions do not exist on the
        # disk
        partitions = pecan.request.dbapi.partition_get_by_idisk(
            new_pv['disk_or_part_uuid'])
        if partitions:
            raise wsme.exc.ClientSideError(_(
                "Cannot assign disk to a physical volume because disk "
                "contains other partitions."))

        # semantic check: whether idisk_uuid belongs to another host
        if new_pv_device.forihostid != new_pv['forihostid']:
            raise wsme.exc.ClientSideError(_("Disk is attached to a different "
                                             "host"))
    else:
        # Perform a quick validation check on this partition as it may be added
        # immediately.
        if (ilvg.lvm_vg_name == constants.LVG_CGTS_VG and
            ((ihost['invprovision'] in [constants.PROVISIONED,
                                        constants.PROVISIONING]) and
             (new_pv_device.status != constants.PARTITION_READY_STATUS)) or
            ((ihost['invprovision'] not in [constants.PROVISIONED,
                                            constants.PROVISIONING]) and
             (new_pv_device.status not in [
                 constants.PARTITION_CREATE_ON_UNLOCK_STATUS,
                 constants.PARTITION_READY_STATUS]))):
            raise wsme.exc.ClientSideError(
                _("The partition %s is not in an acceptable state to be added "
                  "as a physical volume: %s.") %
                (new_pv_device.device_path,
                 constants.PARTITION_STATUS_MSG[new_pv_device.status]))

    new_pv['disk_or_part_device_path'] = new_pv_device.device_path

    # Since physical volumes are reported as device nodes and not device
    # paths, we need to translate this, but not for local storage profiles.
    if ihost['recordtype'] != 'profile':
        if new_pv_device.device_node:
            new_pv['disk_or_part_device_node'] = new_pv_device.device_node
            new_pv['lvm_pv_name'] = new_pv['disk_or_part_device_node']

    # relationship checks
    # - Only one pv for cinder-volumes
    # - if the PV is using a disk, make sure there is no other PV using
    #   a partition on that disk.
    # - if the PV is using a partition, make sure there is no other PV
    #   using the entire disk

    # perform relative PV checks

    pvs = pecan.request.dbapi.ipv_get_by_ihost(ihost['uuid'])
    for pv in pvs:

        # semantic check: cinder_volumes supports a single physical volume
        if (pv['lvm_vg_name'] ==
                new_pv['lvm_vg_name'] ==
                constants.LVG_CINDER_VOLUMES):
            msg = _("A physical volume is already configured "
                    "for %s." % constants.LVG_CINDER_VOLUMES)
            raise wsme.exc.ClientSideError(msg)

        if (pv.disk_or_part_device_path in new_pv_device.device_path or
                new_pv_device.device_path in pv.disk_or_part_device_path):

            # Guard against reusing a partition PV and adding a disk PV if
            # currently being used
            if pv.pv_state != constants.PV_DEL:
                if new_pv['pv_type'] == constants.PV_TYPE_DISK:
                    raise wsme.exc.ClientSideError(
                        _("Invalid data: This disk is in use by another "
                          "physical volume. Cannot use this disk: %s") %
                        new_pv_device.device_path)
                else:
                    raise wsme.exc.ClientSideError(
                        _("Invalid data: The device requested for this Physical "
                          "Volume is already in use by another physical volume"
                          ": %s") %
                        new_pv_device.device_path)

    # Guard against a second partition on a cinder disk from being used in
    # another volume group. This will potentially prevent cinder volume
    # resizes. The exception is the root disk for 1-disk installs.
    if new_pv['pv_type'] == constants.PV_TYPE_PARTITION:
        # Get the disk associated with the new partition, if it exists.
        idisk = pecan.request.dbapi.idisk_get(new_pv_device.idisk_uuid)
        capabilities = idisk['capabilities']

        # see if this is the root disk
        if not ('stor_function' in capabilities and
                capabilities['stor_function'] == 'rootfs'):
            # Not a root disk so look for other cinder PVs and check for conflict
            for pv in pvs:
                if (pv['lvm_vg_name'] == constants.LVG_CINDER_VOLUMES and
                        idisk.device_path in pv.disk_or_part_device_path):
                    msg = (
                        _("Cannot use this partition. A partition (%s) on this "
                          "disk is already in use by %s.") % (
                              pv.disk_or_part_device_path,
                              constants.LVG_CINDER_VOLUMES))
                    raise wsme.exc.ClientSideError(msg)


def _check(op, pv):
    # Semantic checks
    LOG.debug("Semantic check for %s operation" % op)

    # Check parameters
    _check_parameters(pv)

    # Get the host record
    ihost = pecan.request.dbapi.ihost_get(pv['forihostid']).as_dict()

    # Check host and host state
    _check_host(pv, ihost, op)

    if op == "add":
        # Check that the device is available:
        _check_device(pv, ihost)
    elif op == "delete":
        if pv['pv_state'] == constants.PV_DEL:
            raise wsme.exc.ClientSideError(
                _("Physical Volume (%s) "
                  "already marked for removal." %
                  pv['lvm_pv_name']))
    elif op == "modify":
        pass
    else:
        raise wsme.exc.ClientSideError(
            _("Internal Error: Invalid Physical Volume operation: %s" % op))

    # Add additional checks here
    _check_lvg(op, pv)

    return pv


def _prepare_cinder_db_for_volume_restore():
    """
    Send a request to cinder to remove all volume snapshots and set all volumes
    to error state in preparation for restoring all volumes.

    This is needed for cinder disk replacement.
    """
    try:
        pecan.request.rpcapi.cinder_prepare_db_for_volume_restore(
            pecan.request.context)
    except rpc_common.RemoteError as e:
        raise wsme.exc.ClientSideError(str(e.value))


def _update_disk_or_partition(func, pv):
    ihost = pecan.request.dbapi.ihost_get(pv.get('forihostid'))
    get_method = getattr(pecan.request.dbapi, func + '_get')
    get_all_method = getattr(pecan.request.dbapi, func + '_get_all')
    update_method = getattr(pecan.request.dbapi, func + '_update')

    # Find the disk or partitions and update the foripvid field.
    disks_or_partitions = get_all_method(foripvid=pv['id'])
    for phys in disks_or_partitions:
        if phys['uuid'] == pv['disk_or_part_uuid']:
            values = {'foripvid': None}
            try:
                update_method(phys.id, values)
            except exception.HTTPNotFound:
                msg = _("%s update of foripvid failed: "
                        "host %s PV %s"
                        % (func, ihost['hostname'], pv.lvm_pv_name))
                raise wsme.exc.ClientSideError(msg)

    phys = None
    if pv['disk_or_part_uuid']:
        phys = get_method(pv['disk_or_part_uuid'])

    # Mark the pv for deletion
    if pv['pv_state'] == constants.PV_ADD:
        err_msg = "Failed to delete pv %s on host %s"
    else:
        err_msg = "Marking pv %s for deletion failed on host %s"
        values = {'pv_state': constants.PV_DEL}

    try:
        # If the PV will be created on unlock it is safe to remove the DB
        # entry for this PV instead of putting it to removing(on unlock).
        if pv['pv_state'] == constants.PV_ADD:
            pecan.request.dbapi.ipv_destroy(pv['id'])
        else:
            pecan.request.dbapi.ipv_update(pv['id'], values)
    except exception.HTTPNotFound:
        msg = _(err_msg % (pv['lvm_pv_name'], ihost['hostname']))
        raise wsme.exc.ClientSideError(msg)

    # Return the disk or partition
    return phys


def delete_pv(pv_uuid, force=False):
    """Delete a PV"""

    pv = objects.pv.get_by_uuid(pecan.request.context, pv_uuid)
    pv = pv.as_dict()

    # Semantic checks
    if not force:
        _check("delete", pv)

    # Update disk
    if pv['pv_type'] == constants.PV_TYPE_DISK:
        _update_disk_or_partition('idisk', pv)

    elif pv['pv_type'] == constants.PV_TYPE_PARTITION:
        _update_disk_or_partition('partition', pv)
        # If the partition already exists, don't modify its status. Wait
        # for when the PV is actually deleted to do so.
        # If the host hasn't been provisioned yet, then the partition will
        # be created on unlock, so it's status should remain the same.


# TODO (rchurch): Fix system host-pv-add 1 cinder-volumes <disk uuid> => no error message
# TODO (rchurch): Fix system host-pv-add -t disk 1 cinder-volumes <disk uuid> => confusing message
# TODO (rchurch): remove the -t options and use path/node/uuid to derive the type of PV
