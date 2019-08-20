#
# Copyright (c) 2017-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import jsonpatch
import math
import six

import pecan
from pecan import rest

import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log
from sysinv.openstack.common import uuidutils

LOG = log.getLogger(__name__)


class PartitionPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return ['/address', '/ihost_uuid']


class Partition(base.APIBase):
    uuid = types.uuid
    "Unique UUID for this partition"

    start_mib = int
    "Partition start"

    end_mib = int
    "Partition end"

    size_mib = int
    "The size of the partition"

    device_node = wtypes.text
    "The device node of the partition"

    device_path = wtypes.text
    "The device path of the partition"

    type_guid = types.uuid
    "Unique type UUID for this partition"

    type_name = wtypes.text
    "The type name for this partition"

    idisk_id = int
    "The disk's id on which the partition resides"

    idisk_uuid = types.uuid
    "The disk's id on which the partition resides"

    status = int
    "Shows the status of the partition"

    foripvid = int
    "The ipvid that this partition belongs to"

    forihostid = int
    "The ihostid that this partition belongs to"

    ihost_uuid = types.uuid
    "The UUID of the host this partition belongs to"

    ipv_uuid = types.uuid
    "The UUID of the physical volume this partition belongs to"

    links = [link.Link]
    "A list containing a self link and associated partition links"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                                                  six.integer_types)}
    "This partition's meta data"

    def __init__(self, **kwargs):
        self.fields = objects.partition.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_partition, expand=True):
        partition = Partition(**rpc_partition.as_dict())
        if not expand:
            partition.unset_fields_except(
                ['uuid', 'start_mib', 'end_mib', 'size_mib', 'device_path',
                 'device_node', 'type_guid', 'type_name', 'idisk_id',
                 'foripvid', 'ihost_uuid', 'idisk_uuid', 'ipv_uuid', 'status',
                 'created_at', 'updated_at', 'capabilities'])

        # Never expose the id attribute.
        partition.forihostid = wtypes.Unset
        partition.idisk_id = wtypes.Unset
        partition.foripvid = wtypes.Unset

        partition.links = [link.Link.make_link('self', pecan.request.host_url,
                                               'partitions', partition.uuid),
                           link.Link.make_link('bookmark',
                                               pecan.request.host_url,
                                               'partitions', partition.uuid,
                                               bookmark=True)
                           ]
        return partition


class PartitionCollection(collection.Collection):
    """API representation of a collection of partitions."""

    partitions = [Partition]
    "A list containing partition objects"

    def __init__(self, **kwargs):
        self._type = 'partitions'

    @classmethod
    def convert_with_links(cls, rpc_partitions, limit, url=None,
                           expand=False, **kwargs):
        collection = PartitionCollection()
        collection.partitions = [Partition.convert_with_links(
                                      p, expand)
                             for p in rpc_partitions]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'PartitionController'


class PartitionController(rest.RestController):
    """REST controller for partitions."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_ihosts=False, from_idisk=False, from_ipv=False):
        self._from_ihosts = from_ihosts
        self._from_idisk = from_idisk
        self._from_ipv = from_ipv

    def _get_partitions_collection(self, ihost_uuid, disk_uuid, ipv_uuid,
                                   marker, limit, sort_key, sort_dir,
                                   expand=False, resource_url=None):

        if self._from_ihosts and not ihost_uuid:
            raise exception.InvalidParameterValue(_(
                  "Host id not specified."))

        if self._from_idisk and not disk_uuid:
            raise exception.InvalidParameterValue(_(
                  "Disk id not specified."))

        if self._from_ipv and not ipv_uuid:
            raise exception.InvalidParameterValue(_(
                "Physical Volume id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.partition.get_by_uuid(
                                        pecan.request.context,
                                        marker)

        partitions = []
        if self._from_ihosts and self._from_idisk:
            partitions = pecan.request.dbapi.partition_get_by_idisk(
                disk_uuid,
                limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)
        elif self._from_ihosts:
            partitions = pecan.request.dbapi.partition_get_by_ihost(
                ihost_uuid, limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)
        elif self._from_ipv:
            partitions = pecan.request.dbapi.partition_get_by_ipv(
                ipv_uuid,
                limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)

        # Only return user created partitions.
        partitions = [
            p for p in partitions
            if p.type_guid == constants.USER_PARTITION_PHYSICAL_VOLUME]

        return PartitionCollection.convert_with_links(partitions, limit,
                                                      url=resource_url,
                                                      expand=expand,
                                                      sort_key=sort_key,
                                                      sort_dir=sort_dir)

    @wsme_pecan.wsexpose(PartitionCollection, types.uuid, types.uuid,
                         types.uuid, types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, ihost_uuid=None, idisk_uuid=None, ipv_uuid=None,
                marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of partitions."""

        return self._get_partitions_collection(ihost_uuid, idisk_uuid, ipv_uuid,
                                               marker, limit, sort_key,
                                               sort_dir)

    @wsme_pecan.wsexpose(PartitionCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, ihost_uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of partitions with detail."""
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "partitions":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['partitions', 'detail'])
        return self._get_partitions_collection(ihost_uuid, marker, limit, sort_key,
                                               sort_dir, expand, resource_url)

    @wsme_pecan.wsexpose(Partition, types.uuid)
    def get_one(self, partition_uuid):
        """Retrieve information about the given partition."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_partition = objects.partition.get_by_uuid(
                                        pecan.request.context, partition_uuid)
        return Partition.convert_with_links(rpc_partition)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [PartitionPatchType])
    @wsme_pecan.wsexpose(Partition, types.uuid,
                         body=[PartitionPatchType])
    def patch(self, partition_uuid, patch):
        """Update an existing partition."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        LOG.info("Partition patch_data: %s" % patch)

        rpc_partition = objects.partition.get_by_uuid(
            pecan.request.context, partition_uuid)

        # replace ihost_uuid and partition_uuid with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)
        ihost = None
        for p in patch_obj:
            if p['path'] == '/ihost_uuid':
                p['path'] = '/forihostid'
                ihost = objects.host.get_by_uuid(pecan.request.context,
                                                 p['value'])
                p['value'] = ihost.id

        # Perform checks based on the current vs.requested modifications.
        if not ihost:
            ihost = pecan.request.dbapi.ihost_get(rpc_partition.forihostid)
            LOG.info("from partition get ihost=%s" % ihost.hostname)
        _partition_pre_patch_checks(rpc_partition, patch_obj, ihost)

        try:
            partition = Partition(**jsonpatch.apply_patch(
                rpc_partition.as_dict(), patch_obj))
        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Perform post patch semantic checks.
        _semantic_checks(constants.PARTITION_CMD_MODIFY, partition.as_dict())
        partition.status = constants.PARTITION_MODIFYING_STATUS
        try:
            # Update only the fields that have changed
            for field in objects.partition.fields:
                if rpc_partition[field] != getattr(partition, field):
                    rpc_partition[field] = getattr(partition, field)

            # Save.
            rpc_partition.save()

            # Instruct puppet to implement the change.
            pecan.request.rpcapi.update_partition_config(pecan.request.context,
                                                         rpc_partition)
            return Partition.convert_with_links(rpc_partition)
        except exception.HTTPNotFound:
            msg = _("Partition update failed: host %s partition %s : patch %s"
                    % (ihost['hostname'], partition.device_path, patch))
            raise wsme.exc.ClientSideError(msg)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Partition, body=Partition)
    def post(self, partition):
        """Create a new partition."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        try:
            partition = partition.as_dict()
            LOG.debug("partition post dict= %s" % partition)

            new_partition = _create(partition)
        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data"))
        return Partition.convert_with_links(new_partition)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, partition_uuid):
        """Delete a partition."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        partition = objects.partition.get_by_uuid(
            pecan.request.context,
            partition_uuid)
        _delete(partition)


def _check_host(partition, ihost, idisk):
    """Semantic checks for valid host"""
    # Partitions should only be created on workers/controllers.
    if not ihost.personality:
        raise wsme.exc.ClientSideError(_("Host %s has uninitialized "
                                         "personality.") %
                                       ihost.hostname)
    elif ihost.personality not in [constants.CONTROLLER, constants.WORKER]:
        raise wsme.exc.ClientSideError(_("Host personality must be a one of "
                                         "[%s, %s]") %
                                       (constants.CONTROLLER,
                                        constants.WORKER))

    # The disk must be present on the specified host.
    if ihost['id'] != idisk['forihostid']:
        raise wsme.exc.ClientSideError(_("The requested disk (%s) for the partition "
                                         "is not present on host %s.") %
                                         (idisk.uuid, ihost.hostname))


def _check_disk(idisk):
    """Semantic check for valid disk"""
    # Check if the disk is not already assigned for storage function"
    if idisk.istor_uuid:
        raise wsme.exc.ClientSideError(_(
            "Cannot create partition on a disk that is assigned as "
            "a storage volume."))

    # Check if the disk is not assigned as a physical volume to a
    # volume group.
    if idisk.ipv_uuid:
        raise wsme.exc.ClientSideError(_(
            "Cannot create partition on a disk that is already "
            "assigned as a physical volume to a volume group."))


def _partition_pre_patch_checks(partition_obj, patch_obj, host_obj):
    """Check current vs. updated parameters."""
    # Reject operation if we are upgrading the system.
    cutils._check_upgrade(pecan.request.dbapi, host_obj)
    for p in patch_obj:
        if p['path'] == '/size_mib':
            if not cutils.is_int_like(p['value']):
                raise wsme.exc.ClientSideError(
                    _("Requested partition size must be an integer "
                      "greater than 0: %s ") % p['value'])
            if int(p['value']) <= 0:
                raise wsme.exc.ClientSideError(
                    _("Requested partition size must be an integer "
                      "greater than 0: %s GiB") % (int(p['value']) / 1024))
            if int(p['value']) <= partition_obj.size_mib:
                raise wsme.exc.ClientSideError(
                    _("Requested partition size must be larger than current "
                      "size: %s GiB <= %s GiB") % (int(p['value']) / 1024,
                      math.floor(float(partition_obj.size_mib) / 1024 * 1000) / 1000.0))


def _is_user_created_partition(guid):
    """Check if a GUID is of LVM PV type."""
    if guid == constants.USER_PARTITION_PHYSICAL_VOLUME or guid is None:
        return True
    return False


def _build_device_node_path(partition):
    """Builds the partition device path and device node based on last
       partition number and assigned disk.
    """
    idisk_uuid = partition.get('idisk_uuid')
    idisk = pecan.request.dbapi.idisk_get(idisk_uuid)
    partitions = pecan.request.dbapi.partition_get_by_idisk(
        idisk_uuid, sort_key='device_path')
    if partitions:
        if constants.DEVICE_NAME_NVME in idisk.device_node:
            device_node = "%sp%s" %\
                          (idisk.device_node, len(partitions) + 1)
        else:
            device_node = "%s%s" % (idisk.device_node, len(partitions) + 1)
        device_path = "%s-part%s" % (idisk.device_path, len(partitions) + 1)
    else:
        if constants.DEVICE_NAME_NVME in idisk.device_node:
            device_node = idisk.device_node + "p1"
        else:
            device_node = idisk.device_node + '1'
        device_path = idisk.device_path + '-part1'

    return device_node, device_path


def _enough_avail_space_on_disk(partition_size_mib, idisk):
    """Checks that there is enough space on the disk to accommodate the
    required partition.
    :returns None if the disk can't accommodate the partition
             The disk's ID if the disk can accommodate the partition
    """
    return idisk.available_mib >= partition_size_mib


def _check_partition_type(partition):
    """Checks that a partition is a user created partition and raises Client
    Error if not.
    """
    if not _is_user_created_partition(partition.get('type_guid')):
        raise wsme.exc.ClientSideError(_("This type of partition does not "
                                         "support the requested operation."))


def _check_for_outstanding_requests(partition, idisk):
    """Checks that a requested partition change isn't on a host/disk that
    already has an outstanding request.
    """
    # TODO(rchurch): Check existing partitions and make sure we don't have any
    # partitions being changed for an existing host/disk pairing. If
    # so => reject request.
    pass


def _are_partition_operations_simultaneous(ihost, partition, operation):
    """Check that Create and Delete requests are serialized per host.
    :param ihost       the ihost object
    :param partition   dict partition request
    :param operation   Delete/Create
    :return ClientSideError if there is another partition operation processed
    """
    host_partitions = pecan.request.dbapi.partition_get_all(
        forihostid=partition['forihostid'])

    if (ihost.invprovision in
            [constants.PROVISIONED, constants.PROVISIONING]):
        if not (all(host_partition.get('status') in
                [constants.PARTITION_READY_STATUS,
                constants.PARTITION_IN_USE_STATUS,
                constants.PARTITION_CREATE_ON_UNLOCK_STATUS,
                constants.PARTITION_ERROR_STATUS,
                constants.PARTITION_ERROR_STATUS_INTERNAL]
                for host_partition in host_partitions)):
            raise wsme.exc.ClientSideError(
                "Cannot %s a partition while another partition "
                "is being %sd. Wait for all other partitions to "
                "finish %sing." % (operation, operation, operation[:-1]))


def _semantic_checks(operation, partition):
    # Semantic checks
    LOG.debug("PART Partition semantic checks for %s operation" % operation)
    ihost = pecan.request.dbapi.ihost_get(partition['forihostid'])

    # Get disk.
    idiskid = partition.get('idisk_id') or partition.get('idisk_uuid')
    idisk = pecan.request.dbapi.idisk_get(idiskid)

    # Check host and host state.
    _check_host(partition, ihost, idisk)

    # Make sure this partition's type is valid.
    _check_partition_type(partition)

    # Check existing partitions and make sure we don't have any partitions
    # being changed for an existing host/disk pairing. If so => reject request.
    _check_for_outstanding_requests(partition, idisk)

    # Make sure the disk on which we create the partition is valid.
    _check_disk(idisk)

    # Semantic checks based on operation.
    if operation == constants.PARTITION_CMD_CREATE:
        ############
        # CREATING #
        ############
        if int(partition['size_mib']) <= 0:
            raise wsme.exc.ClientSideError(
                _("Partition size must be greater than 0."))

        # Check if there is enough space on the disk to accommodate the
        # partition.
        if not _enough_avail_space_on_disk(partition.get('size_mib'), idisk):
            raise wsme.exc.ClientSideError(
                _("Requested size %s GiB is larger than the %s GiB "
                  "available.") % (partition['size_mib'] / 1024,
                                   math.floor(float(idisk.available_mib) / 1024 * 1000) / 1000.0))

        _are_partition_operations_simultaneous(ihost, partition,
                                               constants.PARTITION_CMD_CREATE)

        # Enough space is availabe, save the disk ID.
        if uuidutils.is_uuid_like(idiskid):
            idisk_id = idisk['id']
        else:
            idisk_id = idiskid
        partition.update({'idisk_id': idisk_id})

    elif operation == constants.PARTITION_CMD_MODIFY:
        #############
        # MODIFYING #
        #############
        # Only allow in-service modify of partitions. If the host isn't
        # provisioned just limit operations to create/delete.
        if ihost.invprovision != constants.PROVISIONED:
            raise wsme.exc.ClientSideError(
                _("Only partition Add/Delete operations are allowed on an "
                  "unprovisioned host."))

        # Allow modification of in-use PVs only for cinder-volumes
        ipv_uuid = partition.get('ipv_uuid')
        ipv_lvg_name = None
        if ipv_uuid:
            ipv_lvg_name = pecan.request.dbapi.ipv_get(ipv_uuid)['lvm_vg_name']
        if (ipv_lvg_name != constants.LVG_CINDER_VOLUMES and
                (ipv_uuid or
                 partition.get('status') == constants.PARTITION_IN_USE_STATUS)):
            raise wsme.exc.ClientSideError(
                _("Can not modify partition. A physical volume (%s) is "
                  "currently associated with this partition.") %
                partition.get('device_node'))

        if (ipv_lvg_name == constants.LVG_CINDER_VOLUMES):
            if (utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX):
                if ihost['administrative'] != constants.ADMIN_LOCKED:
                    raise wsme.exc.ClientSideError(
                        _("Cannot modify the partition (%(dev_node)s) associated with "
                          "the physical volume (%(PV)s) while the host is unlocked.") %
                        {'dev_node': partition.get('device_node'), 'PV': ipv_uuid})
                # TODO(oponcea) Deny modifications if instances are still running.
            elif utils.is_host_active_controller(ihost):
                raise wsme.exc.ClientSideError(
                    _("Can only modify the partition (%(dev_node)s) associated with the physical "
                      "volume (%(PV)s) if the personality is 'Controller-Standby'") %
                    {'dev_node': partition.get('device_node'), 'PV': ipv_uuid})

        # Prevent modifying a partition that is in creating state.
        allowed_states = [constants.PARTITION_READY_STATUS]
        if ipv_lvg_name == constants.LVG_CINDER_VOLUMES:
            allowed_states.append(constants.PARTITION_IN_USE_STATUS)
        status = partition.get('status')
        if status not in allowed_states:
            raise wsme.exc.ClientSideError(
                _("Can not modify partition. Only partitions in the %s state "
                  "can be modified.") %
                constants.PARTITION_STATUS_MSG[
                    constants.PARTITION_READY_STATUS])

        # Check that the partition to modify is the last partition.
        if not cutils.is_partition_the_last(pecan.request.dbapi,
                                            partition):
            raise wsme.exc.ClientSideError(
                _("Can not modify partition. Only the last partition on disk "
                  "can be modified."))

        # Obtain the current partition info.
        crt_part = pecan.request.dbapi.partition_get(partition.get('uuid'))
        crt_part_size = crt_part.size_mib
        new_part_size = partition.get('size_mib')
        extra_size = new_part_size - crt_part_size

        # Check if there is enough space to enlarge the partition.
        if not _enough_avail_space_on_disk(extra_size, idisk):
            raise wsme.exc.ClientSideError(
                _("Requested extra size %s GiB is larger than the %s GiB "
                  "available.") % (extra_size / 1024,
                                   math.floor(float(idisk.available_mib) / 1024 * 1000) / 1000.0))

    elif operation == constants.PARTITION_CMD_DELETE:
        ############
        # DELETING #
        ############
        # Make sure that there is no PV associated with this partition
        if (partition.get('ipv_uuid') or
                partition.get('status') == constants.PARTITION_IN_USE_STATUS):
            raise wsme.exc.ClientSideError(
                _("Can not delete partition. A physical volume (%s) is "
                  "currently associated with this partition") %
                partition.get('device_node'))

        _are_partition_operations_simultaneous(ihost, partition,
                                               constants.PARTITION_CMD_DELETE)

        status = partition.get('status')
        if status == constants.PARTITION_READY_STATUS:
            # Check that the partition to delete is the last partition.
            if not cutils.is_partition_the_last(pecan.request.dbapi,
                                                partition):
                raise wsme.exc.ClientSideError(
                    _("Can not delete partition. Only the last partition on "
                      "disk can be deleted."))
        elif status not in constants.PARTITION_STATUS_OK_TO_DELETE:
            raise wsme.exc.ClientSideError(
                _("Can not delete partition. Only partitions in one of these "
                  "states can be deleted: %s") % ", ".join(
                      map(constants.PARTITION_STATUS_MSG.get,
                          constants.PARTITION_STATUS_OK_TO_DELETE)))
    else:
        raise wsme.exc.ClientSideError(
            _("Internal Error: Invalid Partition operation: %s" % operation))

    return partition


def _create(partition, iprofile=None, applyprofile=None):
    # Reject operation if we are upgrading the system.
    ihostid = partition.get('forihostid') or partition.get('ihost_uuid')
    ihost = pecan.request.dbapi.ihost_get(ihostid)
    cutils._check_upgrade(pecan.request.dbapi, ihost)

    if uuidutils.is_uuid_like(ihostid):
        forihostid = ihost['id']
    else:
        forihostid = ihostid
    partition.update({'forihostid': forihostid})

    # Add any additional default values

    # Semantic Checks
    _semantic_checks(constants.PARTITION_CMD_CREATE, partition)

    # Set the proposed device_path
    partition['device_node'], partition['device_path'] =\
        _build_device_node_path(partition)

    # Set the status of the new partition
    if (ihost.invprovision in [constants.PROVISIONED,
                               constants.PROVISIONING] and
            not iprofile):
        partition['status'] = constants.PARTITION_CREATE_IN_SVC_STATUS
    else:
        partition['status'] = constants.PARTITION_CREATE_ON_UNLOCK_STATUS
        # If the host is unprovisioned, reflect the size of this partition
        # in the available space reported for the disk.
        idiskid = partition.get('idisk_id') or partition.get('idisk_uuid')
        idisk = pecan.request.dbapi.idisk_get(idiskid)
        new_available_mib = idisk.available_mib - partition['size_mib']
        pecan.request.dbapi.idisk_update(
            idiskid,
            {'available_mib': new_available_mib})

    try:
        # Update the database
        new_partition = pecan.request.dbapi.partition_create(forihostid,
                                                             partition)
        # Check if this host has been provisioned. If so, attempt an in-service
        # action. If not, we'll just stage the DB changes to and let the unlock
        # apply the manifest changes
        #  - PROVISIONED: standard controller/worker (after config_controller)
        #  - PROVISIONING: AIO (after config_controller) and before worker
        #                  configuration
        if (ihost.invprovision in [constants.PROVISIONED,
                                   constants.PROVISIONING] and
                not iprofile):
            # Instruct puppet to implement the change
            pecan.request.rpcapi.update_partition_config(pecan.request.context,
                                                         partition)
    except exception.HTTPNotFound:
        msg = _("Creating partition failed for host %s ") % (ihost['hostname'])
        raise wsme.exc.ClientSideError(msg)
    except exception.PartitionAlreadyExists:
        msg = _("Disk partition %s already exists." % partition.get('device_path'))
        raise wsme.exc.ClientSideError(msg)

    return new_partition


def _delete(partition):
    # Reject operation if we are upgrading the system unless it is a new host.
    ihostid = partition.get('forihostid') or partition.get('ihost_uuid')
    ihost = pecan.request.dbapi.ihost_get(ihostid)
    cutils._check_upgrade(pecan.request.dbapi, ihost)

    # Semantic Checks.
    _semantic_checks(constants.PARTITION_CMD_DELETE, partition)

    if partition.get('status') in constants.PARTITION_STATUS_SEND_DELETE_RPC:

        # Set the status of the partition
        part_dict = {'status': constants.PARTITION_DELETING_STATUS}

        # Mark the partition as deleting and send the request to the host.
        try:

            pecan.request.dbapi.partition_update(partition['uuid'], part_dict)

            # Instruct puppet to implement the change
            pecan.request.rpcapi.update_partition_config(pecan.request.context,
                                                         partition)

        except exception.HTTPNotFound:
            msg = _("Marking partition for deletion failed: host %s") %\
                  (ihost['hostname'])
            raise wsme.exc.ClientSideError(msg)
    else:
        if (partition.get('status') ==
                constants.PARTITION_CREATE_ON_UNLOCK_STATUS):
            idiskid = partition.get('idisk_id') or partition.get('idisk_uuid')
            idisk = pecan.request.dbapi.idisk_get(idiskid)
            new_available_mib = idisk.available_mib + partition['size_mib']
            pecan.request.dbapi.idisk_update(
                idiskid,
                {'available_mib': new_available_mib})
        # Handle the delete case where the create failed (partitioning issue or
        # puppet issue) and we don't have a valid device_path or when the
        # partition will be created on unlock. Just delete the partition entry.
        try:
            pecan.request.dbapi.partition_destroy(partition['uuid'])
        except exception.HTTPNotFound:
            msg = _("Partition deletion failed for host %s") %\
                  (ihost['hostname'])
            raise wsme.exc.ClientSideError(msg)
