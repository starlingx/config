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
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#


import jsonpatch
import six
import re

import pecan
from pecan import rest

import subprocess
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import disk
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import ceph
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common import log
from sysinv.openstack.common import uuidutils
from sysinv.openstack.common.gettextutils import _
from sysinv.common.storage_backend_conf import StorageBackendConfig

from oslo_config import cfg

journal_opts = [
                cfg.IntOpt('journal_max_size',
                           default=10240,
                           help='Maximum size of a journal.'),
                cfg.IntOpt('journal_min_size',
                           default=200,
                           help='Minimum size of a journal.'),
                cfg.IntOpt('journal_default_size',
                           default=400,
                           help='Default size of a journal.'),
               ]

CONF = cfg.CONF
CONF.register_opts(journal_opts, 'journal')

LOG = log.getLogger(__name__)


class StoragePatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return ['/address', '/ihost_uuid']


class Storage(base.APIBase):
    """API representation of host storage.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    an stor.
    """

    uuid = types.uuid
    "Unique UUID for this stor"

    osdid = int
    "The osdid assigned to this istor. osd function only."

    function = wtypes.text
    "Represent the function of the istor"

    state = wtypes.text
    "Represent the operational state of the istor"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                    six.integer_types)}
    "This stor's meta data"

    forihostid = int
    "The ihostid that this istor belongs to"

    ihost_uuid = types.uuid
    "The UUID of the host this stor belongs to"

    idisk_uuid = types.uuid
    "The UUID of the disk this stor belongs to. API-only attribute"

    links = [link.Link]
    "A list containing a self link and associated stor links"

    idisks = [link.Link]
    "Links to the collection of idisks on this stor"

    journal_location = wtypes.text
    "The stor UUID of the journal disk"

    journal_size_mib = int
    "The size in MiB of the journal for this stor"

    journal_path = wtypes.text
    "The partition's path on which the stor's journal is kept"

    journal_node = wtypes.text
    "The partition's name on which the stor's journal is kept"

    fortierid = int
    "The id of the tier that uses this stor."

    tier_uuid = types.uuid
    "The tier UUID of the tier that uses this stor."

    tier_name = wtypes.text
    "The name of the tier that uses this stor."

    def __init__(self, **kwargs):
        self.fields = list(objects.storage.fields.keys())
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        if not self.uuid:
            self.uuid = uuidutils.generate_uuid()

        self.fields.append('journal_node')
        setattr(self, 'journal_node', kwargs.get('journal_node', None))

    @classmethod
    def convert_with_links(cls, rpc_stor, expand=True):
        stor = Storage(**rpc_stor.as_dict())
        if not expand:
            stor.unset_fields_except([
                'uuid', 'osdid', 'function',
                'state', 'capabilities', 'created_at', 'updated_at',
                'ihost_uuid', 'idisk_uuid', 'forihostid',
                'journal_location', 'journal_size_mib', 'journal_path',
                'journal_node', 'tier_uuid', 'tier_name'])

        # never expose the ihost_id attribute
        # stor.ihost_id = wtypes.Unset  # this should be forihostid
        if stor.function == constants.STOR_FUNCTION_OSD:
            disks = pecan.request.dbapi.idisk_get_by_ihost(stor.forihostid)
            if disks is not None:
                for d in disks:
                    if (stor.journal_path is not None and
                            d.device_path is not None and
                            d.device_path in stor.journal_path):
                        partition_number = (re.match('.*?([0-9]+)$',
                                                     stor.journal_path).group(1))
                        if (d.device_node is not None and
                                constants.DEVICE_NAME_NVME in d.device_node):
                            stor.journal_node = "{}p{}".format(d.device_node,
                                                               partition_number)
                        else:
                            stor.journal_node = "{}{}".format(d.device_node,
                                                              partition_number)
                        break

        # never expose the ihost_id attribute, allow exposure for now
        stor.forihostid = wtypes.Unset
        stor.links = [link.Link.make_link('self', pecan.request.host_url,
                                          'istors', stor.uuid),
                      link.Link.make_link('bookmark',
                                          pecan.request.host_url,
                                          'istors', stor.uuid,
                                          bookmark=True)
                      ]
        if expand:
            stor.idisks = [link.Link.make_link('self',
                                               pecan.request.host_url,
                                               'istors',
                                               stor.uuid + "/idisks"),
                           link.Link.make_link('bookmark',
                                               pecan.request.host_url,
                                               'istors',
                                               stor.uuid + "/idisks",
                                               bookmark=True)
                           ]

        return stor


class StorageCollection(collection.Collection):
    """API representation of a collection of stors."""

    istors = [Storage]
    "A list containing stor objects"

    def __init__(self, **kwargs):
        self._type = 'istors'

    @classmethod
    def convert_with_links(cls, rpc_stors, limit, url=None,
                           expand=False, **kwargs):
        collection = StorageCollection()
        collection.istors = [Storage.convert_with_links(p, expand)
                             for p in rpc_stors]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'StorageController'


class StorageController(rest.RestController):
    """REST controller for istors."""

    idisks = disk.DiskController(from_ihosts=True, from_istor=True)
    "Expose idisks as a sub-element of istors"

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_ihosts=False, from_tier=False):
        self._from_ihosts = from_ihosts
        self._from_tier = from_tier

    def _get_stors_collection(self, uuid, marker, limit, sort_key, sort_dir,
                              expand=False, resource_url=None):

        if self._from_ihosts and not uuid:
            raise exception.InvalidParameterValue(_(
                  "Host id not specified."))

        if self._from_tier and not uuid:
            raise exception.InvalidParameterValue(_(
                "Storage tier id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.storage.get_by_uuid(
                                        pecan.request.context,
                                        marker)

        if self._from_ihosts:
            stors = pecan.request.dbapi.istor_get_by_ihost(uuid, limit,
                                                           marker_obj,
                                                           sort_key=sort_key,
                                                           sort_dir=sort_dir)
        elif self._from_tier:
            stors = pecan.request.dbapi.istor_get_by_tier(uuid, limit,
                                                          marker_obj,
                                                          sort_key=sort_key,
                                                          sort_dir=sort_dir)
        else:
            stors = pecan.request.dbapi.istor_get_list(limit, marker_obj,
                                                       sort_key=sort_key,
                                                       sort_dir=sort_dir)

        return StorageCollection.convert_with_links(stors, limit,
                                                    url=resource_url,
                                                    expand=expand,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

    @wsme_pecan.wsexpose(StorageCollection, types.uuid, types.uuid,
                         int, wtypes.text, wtypes.text)
    def get_all(self, uuid=None, marker=None, limit=None, sort_key='id',
                sort_dir='asc'):
        """Retrieve a list of stors."""
        return self._get_stors_collection(uuid, marker, limit, sort_key,
                                          sort_dir)

    @wsme_pecan.wsexpose(StorageCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, ihost_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of stors with detail."""
        # NOTE(lucasagomes): /detail should only work agaist collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "istors":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['stors', 'detail'])
        return self._get_stors_collection(ihost_uuid,
                                               marker, limit,
                                               sort_key, sort_dir,
                                               expand, resource_url)

    @wsme_pecan.wsexpose(Storage, types.uuid)
    def get_one(self, stor_uuid):
        """Retrieve information about the given stor."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        if self._from_tier:
            raise exception.OperationNotPermitted

        rpc_stor = objects.storage.get_by_uuid(
                                        pecan.request.context, stor_uuid)
        return Storage.convert_with_links(rpc_stor)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Storage, body=Storage)
    def post(self, stor):
        """Create a new stor."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        if self._from_tier:
            raise exception.OperationNotPermitted

        try:
            stor = stor.as_dict()
            LOG.debug("stor post dict= %s" % stor)

            new_stor = _create(stor)
        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_(
                "Invalid data: failed to create a storage object"))
        except subprocess.CalledProcessError as esub:
            LOG.exception(esub)
            raise wsme.exc.ClientSideError(_(
                "Internal error: failed to create a storage object"))

        return Storage.convert_with_links(new_stor)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [StoragePatchType])
    @wsme_pecan.wsexpose(Storage, types.uuid,
                         body=[StoragePatchType])
    def patch(self, stor_uuid, patch):
        """Update an existing stor."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        if self._from_tier:
            raise exception.OperationNotPermitted

        try:
            rpc_stor = objects.storage.get_by_uuid(
                           pecan.request.context, stor_uuid)
        except exception.ServerNotFound:
            raise wsme.exc.ClientSideError(_("No stor with the provided"
                                             " uuid: %s" % stor_uuid))
        # replace ihost_uuid and istor_uuid with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)
        for p in patch_obj:
            if p['path'] == '/ihost_uuid':
                p['path'] = '/forihostid'
                ihost = objects.host.get_by_uuid(pecan.request.context,
                                                 p['value'])
                p['value'] = ihost.id
            elif p['path'] == '/tier_uuid':
                p['path'] = '/fortierid'
                tier = objects.tier.get_by_uuid(pecan.request.context,
                                                p['value'])
                p['value'] = tier.id

        try:
            stor = Storage(**jsonpatch.apply_patch(
                                               rpc_stor.as_dict(),
                                               patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Semantic Checks
        _check_host(stor.as_dict())
        _check_disk(stor.as_dict())

        if (hasattr(stor, 'journal_size_mib') or
                hasattr(stor, 'journal_location')):
            _check_journal(rpc_stor, stor.as_dict())

        # Journal partitions can be either collocated with the OSD or external.
        # Any location change requires that the device_nodes of the remaining
        # journals of the external journal disk to be updated, therefore we back
        # up the external journal stor before updating it with the new value
        journal_stor_uuid = None
        if rpc_stor['journal_location'] != getattr(stor, 'journal_location'):
            if rpc_stor['uuid'] == getattr(stor, 'journal_location'):
                # journal partition becomes collocated, backup the prev journal
                journal_stor_uuid = rpc_stor['journal_location']
                setattr(stor, 'journal_size_mib',
                        CONF.journal.journal_default_size)
            else:
                # journal partition moves to external journal disk
                journal_stor_uuid = getattr(stor, 'journal_location')
        else:
            if (hasattr(stor, 'journal_size_mib') and
                    rpc_stor['uuid'] == rpc_stor['journal_location']):
                raise wsme.exc.ClientSideError(_(
                    "Invalid update: Size of collocated journal is fixed."))

        # Update only the fields that have changed
        updated = False
        for field in objects.storage.fields:
            if rpc_stor[field] != getattr(stor, field):
                rpc_stor[field] = getattr(stor, field)
                updated = True

        if not updated:
            # None of the data fields have been updated, return!
            return Storage.convert_with_links(rpc_stor)

        # Set status for newly created OSD.
        if rpc_stor['function'] == constants.STOR_FUNCTION_OSD:
            ihost_id = rpc_stor['forihostid']
            ihost = pecan.request.dbapi.ihost_get(ihost_id)
            if ihost['operational'] == constants.OPERATIONAL_ENABLED:
                # We are running live manifests
                rpc_stor['state'] = constants.SB_STATE_CONFIGURING
            else:
                rpc_stor['state'] = constants.SB_STATE_CONFIGURING_ON_UNLOCK

        # Save istor
        rpc_stor.save()

        # Update device nodes for the journal disk
        if journal_stor_uuid:
            try:
                pecan.request.dbapi.journal_update_dev_nodes(journal_stor_uuid)
                # Refresh device node for current stor, if changed by prev call
                st = pecan.request.dbapi.istor_get(rpc_stor['id'])
                rpc_stor['journal_path'] = st.journal_path
            except Exception as e:
                LOG.exception(e)

        # Run runtime manifests to update configuration
        runtime_manifests = False
        if (rpc_stor['state'] == constants.SB_STATE_CONFIGURING and
                rpc_stor['function'] == constants.STOR_FUNCTION_OSD):
            runtime_manifests = True

        pecan.request.rpcapi.update_ceph_osd_config(pecan.request.context,
                                                    ihost, rpc_stor['uuid'],
                                                    runtime_manifests)

        return Storage.convert_with_links(rpc_stor)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, stor_uuid):
        """Delete a stor."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        if self._from_tier:
            raise exception.OperationNotPermitted

        try:
            stor = pecan.request.dbapi.istor_get(stor_uuid)
        except Exception as e:
            LOG.exception(e)
            raise

        # Make sure that we are allowed to delete
        _check_host(stor)

        # Delete the stor if supported
        if stor.function == constants.STOR_FUNCTION_JOURNAL:
            # Host must be locked
            ihost_id = stor['forihostid']
            ihost = pecan.request.dbapi.ihost_get(ihost_id)
            if ihost['administrative'] != constants.ADMIN_LOCKED:
                raise wsme.exc.ClientSideError(_("Host %s must be locked." %
                                                ihost['hostname']))
            self.delete_stor(stor_uuid)
        else:
            raise wsme.exc.ClientSideError(_(
                   "Deleting a Storage Function other than %s is not "
                   "supported on this setup") % constants.STOR_FUNCTION_JOURNAL)

    def delete_stor(self, stor_uuid):
        """Delete a stor"""

        stor = objects.storage.get_by_uuid(pecan.request.context, stor_uuid)

        try:
            # The conductor will handle removing the stor, not all functions
            # need special handling
            if stor.function == constants.STOR_FUNCTION_OSD:
                pecan.request.rpcapi.unconfigure_osd_istor(pecan.request.context,
                                                           stor)
            elif stor.function == constants.STOR_FUNCTION_JOURNAL:
                pecan.request.dbapi.istor_disable_journal(stor_uuid)
            # Now remove the stor from DB
            pecan.request.dbapi.istor_remove_disk_association(stor_uuid)
            pecan.request.dbapi.istor_destroy(stor_uuid)
        except Exception as e:
            LOG.exception(e)
            raise


def _check_profile(stor):
    # semantic check: whether system has a ceph backend
    if not StorageBackendConfig.has_backend_configured(
        pecan.request.dbapi,
        constants.SB_TYPE_CEPH
    ):
        raise wsme.exc.ClientSideError(_(
            "System must have a %s backend" % constants.SB_TYPE_CEPH))


def _check_host(stor):
    ihost_id = stor['forihostid']
    ihost = pecan.request.dbapi.ihost_get(ihost_id)
    stor_model = ceph.get_ceph_storage_model()

    # semantic check: whether OSD can be added to this host.
    if stor_model == constants.CEPH_STORAGE_MODEL:
        if ihost.personality != constants.STORAGE:
            msg = ("Storage model is '%s'. Storage devices can only be added "
                   "to storage nodes." % stor_model)
            raise wsme.exc.ClientSideError(_(msg))
    elif stor_model == constants.CEPH_CONTROLLER_MODEL:
        if ihost.personality != constants.CONTROLLER:
            msg = ("Storage model is '%s'. Storage devices can only be added "
                   "to controller nodes." % stor_model)
            raise wsme.exc.ClientSideError(_(msg))
    elif stor_model == constants.CEPH_UNDEFINED_MODEL:
        msg = ("Please install storage-0 or configure a Ceph monitor "
               "on a worker node before adding storage devices.")
        raise wsme.exc.ClientSideError(_(msg))

    # semantic check: whether host is operationally acceptable
    if (stor_model == constants.CEPH_CONTROLLER_MODEL or
            stor_model == constants.CEPH_AIO_SX_MODEL):
        if (ihost['administrative'] == constants.ADMIN_UNLOCKED and
                ihost['operational'] != constants.OPERATIONAL_ENABLED):
            msg = _("Host %s must be unlocked and operational state "
                    "enabled." % ihost['hostname'])
            raise wsme.exc.ClientSideError(msg)
    else:
        if ihost['administrative'] != constants.ADMIN_LOCKED:
            raise wsme.exc.ClientSideError(_("Host %s must be locked." %
                                             ihost['hostname']))

    # semantic check: only storage nodes are allowed without k8s
    if (not utils.is_kubernetes_config(pecan.request.dbapi) and
            ihost['personality'] != constants.STORAGE):
        msg = ("Host personality must be 'storage' or kubernetes enabled.")
        raise wsme.exc.ClientSideError(_(msg))

    # semantic check: whether system has a ceph backend
    if not StorageBackendConfig.has_backend_configured(
            pecan.request.dbapi,
            constants.SB_TYPE_CEPH
    ):
        raise wsme.exc.ClientSideError(_(
            "System must have a %s backend" % constants.SB_TYPE_CEPH))

    # semantic check: whether at least 2 unlocked hosts are monitors
    if not utils.is_aio_system(pecan.request.dbapi):
        ceph_helper = ceph.CephApiOperator()
        num_monitors, required_monitors, quorum_names = \
            ceph_helper.get_monitors_status(pecan.request.dbapi)
        # CGTS 503 for now update monitors requirement until controller-0 is
        # inventoried
        # CGTS 1448
        if num_monitors < required_monitors:
            raise wsme.exc.ClientSideError(_(
                "Only %d storage monitor available. "
                "At least %s unlocked and enabled hosts with monitors are "
                "required. Please ensure hosts with monitors are unlocked "
                "and enabled.") % (num_monitors, required_monitors))


def _check_disk(stor):
    # semantic check whether idisk is associated
    if 'idisk_uuid' in stor and stor['idisk_uuid']:
        idisk_uuid = stor['idisk_uuid']
    else:
        LOG.error(_("Missing idisk_uuid."))
        raise wsme.exc.ClientSideError(_(
            "Invalid data: failed to create a storage object"))

    idisk = pecan.request.dbapi.idisk_get(idisk_uuid)

    if idisk.foristorid is not None:
        if idisk.foristorid != stor['id']:
            raise wsme.exc.ClientSideError(_("Disk already assigned."))

    # semantic check: whether idisk_uuid belongs to another host
    if idisk.forihostid != stor['forihostid']:
        raise wsme.exc.ClientSideError(_(
            "Disk is attached to a different host"))

    # semantic check: whether idisk is a rootfs disk
    capabilities = idisk['capabilities']
    if ('stor_function' in capabilities and
         capabilities['stor_function'] == 'rootfs'):
            raise wsme.exc.ClientSideError(_(
                "Can not associate to a rootfs disk"))

    return idisk_uuid


def _check_journal_location(journal_location, stor, action):
    """Chooses a valid journal location or returns a corresponding error."""

    if journal_location:
        if not uuidutils.is_uuid_like(journal_location):
            raise exception.InvalidUUID(uuid=journal_location)

    # If a journal location is provided by the user.
    if journal_location:
        # Check that the journal location is that of an existing stor object.
        try:
            requested_journal_onistor = pecan.request.dbapi.istor_get(
                journal_location)
        except exception.ServerNotFound:
            raise wsme.exc.ClientSideError(_(
                "No journal stor with the provided uuid: %s" %
                journal_location))

        # Check that the provided stor is assigned to the same host as the OSD.
        if (requested_journal_onistor.forihostid != stor['forihostid']):
            raise wsme.exc.ClientSideError(_(
                "The provided stor belongs to another "
                "host."))

        # If the action is journal create, don't let the journal be
        # collocated.
        if action == constants.ACTION_CREATE_JOURNAL:
            if (requested_journal_onistor.function !=
                    constants.STOR_FUNCTION_JOURNAL):
                raise wsme.exc.ClientSideError(_(
                    "The provided uuid belongs to a stor "
                    "that is not of journal type."))

        # If the action is journal update:
        # - if the new journal location is not collocated, check that the
        #   location is of journal type.
        # - if the new journal location is collocated, allow it.
        if action == constants.ACTION_UPDATE_JOURNAL:
            if requested_journal_onistor.uuid != stor['uuid']:
                if (requested_journal_onistor.function !=
                        constants.STOR_FUNCTION_JOURNAL):
                    raise wsme.exc.ClientSideError(_(
                        "The provided uuid belongs to a stor "
                        "that is not of journal type."))

    # If no journal location is provided by the user.
    else:
        # Check if there is a journal storage designated for the present host.
        existing_journal_stors = pecan.request.dbapi.istor_get_by_ihost_function(
            stor['forihostid'], constants.STOR_FUNCTION_JOURNAL)

        # If more than one journal stor is assigned to the host, the user
        # should choose only one journal location.
        #
        # If there is only one journal stor assigned to the host, then that's
        # where the journal will reside.
        #
        # If there are no journal stors assigned to the host, then the journal
        # is collocated.
        if 'uuid' in stor:
            if len(existing_journal_stors) > 1:
                available_journals = ""
                for stor_obj in existing_journal_stors:
                    available_journals = (available_journals +
                                         stor_obj.uuid + "\n")
                raise wsme.exc.ClientSideError(_(
                      "Multiple journal stors are available. Choose from:\n%s"
                      % available_journals))
            elif len(existing_journal_stors) == 1:
                journal_location = existing_journal_stors[0].uuid
            elif len(existing_journal_stors) == 0:
                journal_location = stor['uuid']

    return journal_location


def _check_journal_space(idisk_uuid, journal_location,
                         journal_size_mib, prev_journal_size_mib=0):

    if journal_size_mib > CONF.journal.journal_max_size:
        raise wsme.exc.ClientSideError(_(
            "The journal size you have provided is greater than the "
            "maximum accepted: %s " % CONF.journal.journal_max_size))
    elif journal_size_mib < CONF.journal.journal_min_size:
        raise wsme.exc.ClientSideError(_(
            "The journal size you have provided is smaller than the "
            "minimum accepted: %s " % CONF.journal.journal_min_size))

    idisk = pecan.request.dbapi.idisk_get(idisk_uuid)

    # Obtain total size of disk.
    provided_size = idisk.size_mib

    # Obtain the size occupied by the journals on the current stor.
    journals_onistor = pecan.request.dbapi.journal_get_all(journal_location)

    used_size = 0
    if journals_onistor:
        for journal in journals_onistor:
            used_size += journal.size_mib

    # Space used by the previous journal partition is released,
    # therefore we need to mark it as free
    used_size -= prev_journal_size_mib

    # Find out if there is enough space for the current journal.
    # Note: 2 MiB are not used, one at the beginning of the disk and
    # another one at the end.
    if used_size + journal_size_mib + 2 > provided_size:
        free_space = provided_size - used_size - 2
        raise wsme.exc.ClientSideError(_(
            "Failed to create journal for the OSD.\nNot enough "
            "space on journal storage %s. Remaining space: %s out of %s"
            % (journal_location, free_space, provided_size)))


def _check_journal(old_foristor, new_foristor):

    check_journal = False

    # If required, update the new journal size.
    if 'journal_size_mib' in new_foristor:
        journal_size = new_foristor['journal_size_mib']
        check_journal = True
    else:
        journal_size = old_foristor['journal_size_mib']

    # If required, update the new journal location.
    if 'journal_location' in new_foristor:
        if not uuidutils.is_uuid_like(new_foristor['journal_location']):
            raise exception.InvalidUUID(uuid=new_foristor['journal_location'])
        journal_location = new_foristor['journal_location']
        check_journal = True
    else:
        journal_location = old_foristor['journal_location']

    # If modifications to the journal location or size have been made,
    # verify that they are valid.
    if check_journal:
        try:
            journal_istor = pecan.request.dbapi.istor_get(journal_location)
        except exception.ServerNotFound:
            raise wsme.exc.ClientSideError(_(
                "No journal stor with the provided uuid: %s" %
                journal_location))

        idisk = pecan.request.dbapi.idisk_get(journal_istor.idisk_uuid)

        _check_journal_location(journal_location,
                                new_foristor,
                                constants.ACTION_UPDATE_JOURNAL)

        if new_foristor['journal_location'] == \
                old_foristor['journal_location']:
            # journal location is the same - we are just updating the size.
            # In this case the old journal is removed and a new one is created.
            _check_journal_space(idisk.uuid, journal_location, journal_size,
                                 old_foristor['journal_size_mib'])
        elif new_foristor['journal_location'] != new_foristor['uuid']:
            # If a journal becomes external, check that the journal stor can
            # accommodate it.
            _check_journal_space(idisk.uuid, journal_location, journal_size)


# This method allows creating a stor through a non-HTTP
# request e.g. through profile.py while still passing
# through istor semantic checks and osd configuration
# Hence, not declared inside a class
#
# Param:
#       stor - dictionary of stor values
#       iprofile - True when created by a storage profile
def _create(stor, iprofile=None):

    LOG.debug("storage._create stor with params: %s" % stor)
    # Init
    osd_create = False

    # Get host
    ihostId = stor.get('forihostid') or stor.get('ihost_uuid')
    if not ihostId:
        raise wsme.exc.ClientSideError(_("No host provided for stor creation."))

    ihost = pecan.request.dbapi.ihost_get(ihostId)
    if uuidutils.is_uuid_like(ihostId):
        forihostid = ihost['id']
    else:
        forihostid = ihostId
    stor.update({'forihostid': forihostid})

    # SEMANTIC CHECKS
    if iprofile:
        _check_profile(stor)
    else:
        _check_host(stor)

    try:
        idisk_uuid = _check_disk(stor)
    except exception.ServerNotFound:
        raise wsme.exc.ClientSideError(_("No disk with the provided "
                                         "uuid: %s" % stor['idisk_uuid']))

    # Assign the function if necessary.
    function = stor['function']
    if function:
        if function == constants.STOR_FUNCTION_OSD and not iprofile:
            osd_create = True
    else:
        function = stor['function'] = constants.STOR_FUNCTION_OSD
        if not iprofile:
            osd_create = True

    create_attrs = {}
    create_attrs.update(stor)

    # Set status for newly created OSD.
    if function == constants.STOR_FUNCTION_OSD:
        ihost_id = stor['forihostid']
        ihost = pecan.request.dbapi.ihost_get(ihost_id)
        if ihost['operational'] == constants.OPERATIONAL_ENABLED:
            # We are running live manifests
            create_attrs['state'] = constants.SB_STATE_CONFIGURING
        else:
            create_attrs['state'] = constants.SB_STATE_CONFIGURING_ON_UNLOCK
    else:
        create_attrs['state'] = constants.SB_STATE_CONFIGURED

    if function == constants.STOR_FUNCTION_OSD:
        # Get the tier the stor should be associated with
        tierId = stor.get('fortierid') or stor.get('tier_uuid')
        if not tierId:
            # Get the available tiers. If only one exists (the default tier)
            # then add it.
            default_ceph_tier_name = constants.SB_TIER_DEFAULT_NAMES[
                constants.SB_TIER_TYPE_CEPH]
            tier_list = pecan.request.dbapi.storage_tier_get_list()
            if (len(tier_list) == 1 and
                    tier_list[0].name == default_ceph_tier_name):
                tierId = tier_list[0].uuid
            else:
                raise wsme.exc.ClientSideError(
                    _("Multiple storage tiers are present. A tier is required "
                      "for stor creation."))

        try:
            tier = pecan.request.dbapi.storage_tier_get(tierId)
        except exception.StorageTierNotFound:
            raise wsme.exc.ClientSideError(_("No tier with id %s found.") % tierId)

        create_attrs['fortierid'] = tier.id

        if not iprofile:
            try:
                journal_location = \
                    _check_journal_location(stor['journal_location'],
                                            stor,
                                            constants.ACTION_CREATE_JOURNAL)
            except exception.InvalidUUID as e:
                raise wsme.exc.ClientSideError(_(str(e)))

            # If the journal is collocated, make sure its size is set to the
            # default one.
            if 'uuid' in stor and journal_location == stor['uuid']:
                stor['journal_size_mib'] = CONF.journal.journal_default_size
            elif journal_location:
                if not stor['journal_size_mib']:
                    stor['journal_size_mib'] = \
                        CONF.journal.journal_default_size

                journal_istor = pecan.request.dbapi.istor_get(journal_location)
                journal_idisk_uuid = journal_istor.idisk_uuid

                # Find out if there is enough space to keep the journal on the
                # journal stor.
                _check_journal_space(journal_idisk_uuid,
                                     journal_location,
                                     stor['journal_size_mib'])

    elif function == constants.STOR_FUNCTION_JOURNAL:
        # Check that the journal stor resides on a device of SSD type.
        idisk = pecan.request.dbapi.idisk_get(idisk_uuid)
        if (idisk.device_type != constants.DEVICE_TYPE_SSD and
                idisk.device_type != constants.DEVICE_TYPE_NVME):
            raise wsme.exc.ClientSideError(_(
                "Invalid stor device type: only SSD and NVME devices are supported"
                " for journal functions."))

    new_stor = pecan.request.dbapi.istor_create(forihostid,
                                                create_attrs)

    # Create an osd associated with disk.
    if osd_create is True:
        try:
            new_stor = pecan.request.rpcapi.configure_osd_istor(
                pecan.request.context, new_stor)
        except Exception as cpe:
            LOG.exception(cpe)
            # Delete the partially configure istor
            pecan.request.dbapi.istor_destroy(new_stor.uuid)
            raise wsme.exc.ClientSideError(_(
                "Internal error: failed to create a storage object. "
                "Make sure storage cluster is up and healthy."))

        if iprofile:
            new_stor = pecan.request.dbapi.istor_update(new_stor.uuid,
                                                        {'osdid': None})
        else:
            # Update the database record
            new_stor.save(pecan.request.context)

    # Associate the disk to db record
    values = {'foristorid': new_stor.id}
    pecan.request.dbapi.idisk_update(idisk_uuid,
                                     values)

    # Journals are created only for OSDs
    if new_stor.get("function") == constants.STOR_FUNCTION_OSD:
        if iprofile or not journal_location:
            # iprofile either provides a valid location or assumes
            # collocation. For collocation: stor['journal_location'] =
            # stor['uuid'], since sometimes we get the UUID of the newly
            # created stor late, we can only set it late.
            journal_location = stor['journal_location'] if \
                                stor.get('journal_location') else new_stor['uuid']
        new_journal = _create_journal(journal_location,
                                      stor['journal_size_mib'],
                                      new_stor)

        # Update the attributes of the journal partition for the current stor.
        setattr(new_stor, "journal_path", new_journal.get("device_path"))
        setattr(new_stor, "journal_location", new_journal.get("onistor_uuid"))
        setattr(new_stor, "journal_size", new_journal.get("size_mib"))

        if not iprofile:
            # Update the state of the storage tier
            try:
                pecan.request.dbapi.storage_tier_update(
                    tier.id,
                    {'status': constants.SB_TIER_STATUS_IN_USE})
            except exception.StorageTierNotFound as e:
                # Shouldn't happen. Log exception. Stor is created but tier status
                # is not updated.
                LOG.exception(e)

        # Apply runtime manifests for OSDs on "available" nodes.
        runtime_manifests = False
        if ihost['operational'] == constants.OPERATIONAL_ENABLED:
            runtime_manifests = True

        pecan.request.rpcapi.update_ceph_osd_config(pecan.request.context,
                                                    ihost, new_stor['uuid'],
                                                    runtime_manifests)

    return new_stor


def _create_journal(journal_location, journal_size_mib, stor):

    # Obtain the journal stor on which the journal partition will reside.
    journal_onistor = pecan.request.dbapi.istor_get(journal_location)

    # Obtain the disk on which the journal stor resides
    journal_onistor_idisk = pecan.request.dbapi.idisk_get(
        journal_onistor.idisk_uuid)

    # Determine if the journal partition is collocated or not.
    if stor.uuid == journal_location:
        # The collocated journal is always on /dev/sdX2.
        journal_device_path = journal_onistor_idisk.device_path + "-part" + "2"
    else:
        # Obtain the last partition index on which the journal will reside.
        last_index = len(pecan.request.dbapi.journal_get_all(journal_location))
        journal_device_path = (journal_onistor_idisk.device_path + "-part" +
                               str(last_index + 1))

    journal_values = {'device_path': journal_device_path,
                      'size_mib': journal_size_mib,
                      'onistor_uuid': journal_location,
                      'foristorid': stor.id
                      }

    create_attrs = {}
    create_attrs.update(journal_values)

    # Create the journal for the new stor.
    new_journal = pecan.request.dbapi.journal_create(stor.id, create_attrs)

    return new_journal
