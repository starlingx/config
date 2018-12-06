# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright 2017 UnitedStack Inc.
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


import copy
import jsonpatch
import os
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
from sysinv.api.controllers.v1 import storage as storage_api

from sysinv.common import ceph
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log
from sysinv.openstack.common import uuidutils

LOG = log.getLogger(__name__)


class StorageTierPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return ['/cluster_uuid']


class StorageTier(base.APIBase):
    """API representation of a Storage Tier.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a storage tier.
    """

    uuid = types.uuid
    "Unique UUID for this storage tier"

    name = wtypes.text
    "Storage tier name"

    type = wtypes.text
    "Storage tier type"

    status = wtypes.text
    "Storage tier status"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                    six.integer_types)}
    "Storage tier meta data"

    forbackendid = int
    "The storage backend that is using this storage tier"

    backend_uuid = types.uuid
    "The UUID of the storage backend that is using this storage tier"

    forclusterid = int
    "The storage cluster that this storage tier belongs to"

    cluster_uuid = types.uuid
    "The UUID of the storage cluster this storage tier belongs to"

    stors = types.MultiType([list])
    "List of OSD ids associated with this tier"

    links = [link.Link]
    "A list containing a self link and associated storage tier links"

    istors = [link.Link]
    "Links to the collection of OSDs on this storage tier"

    def __init__(self, **kwargs):
        self.fields = objects.storage_tier.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        if not self.uuid:
            self.uuid = uuidutils.generate_uuid()

    @classmethod
    def convert_with_links(cls, rpc_tier, expand=True):
        tier = StorageTier(**rpc_tier.as_dict())
        if not expand:
            tier.unset_fields_except([
                'uuid', 'name', 'type', 'status', 'capabilities',
                'backend_uuid', 'cluster_uuid', 'stors', 'created_at',
                'updated_at'])

        # Don't expose ID attributes.
        tier.forbackendid = wtypes.Unset
        tier.forclusterid = wtypes.Unset

        tier.links = [link.Link.make_link('self', pecan.request.host_url,
                                          'storage_tiers', tier.uuid),
                      link.Link.make_link('bookmark',
                                          pecan.request.host_url,
                                          'storage_tiers', tier.uuid,
                                          bookmark=True)
                      ]
        if expand:
            tier.istors = [link.Link.make_link('self',
                                               pecan.request.host_url,
                                               'storage_tiers',
                                               tier.uuid + "/istors"),
                           link.Link.make_link(
                               'bookmark',
                               pecan.request.host_url,
                               'storage_tiers',
                               tier.uuid + "/istors",
                               bookmark=True)
                           ]
        return tier


class StorageTierCollection(collection.Collection):
    """API representation of a collection of StorageTier."""

    storage_tiers = [StorageTier]
    "A list containing StorageTier objects"

    def __init__(self, **kwargs):
        self._type = 'storage_tiers'

    @classmethod
    def convert_with_links(cls, rpc_tiers, limit, url=None,
                           expand=False, **kwargs):
        collection = StorageTierCollection()
        collection.storage_tiers = [StorageTier.convert_with_links(p, expand)
                                    for p in rpc_tiers]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'StorageTierController'


class StorageTierController(rest.RestController):
    """REST controller for storage tiers."""

    istors = storage_api.StorageController(from_tier=True)
    "Expose istors as a sub-element of storage_tier"

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_cluster=False, **kwargs):
        self._from_cluster = from_cluster
        self._ceph = ceph.CephApiOperator()

    def _get_tiers_collection(self, uuid, marker, limit, sort_key,
                              sort_dir, expand=False, resource_url=None):

        if self._from_cluster and not uuid:
            raise exception.InvalidParameterValue(_(
                "Cluster id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.storage_tier.get_by_uuid(pecan.request.context,
                                                          marker)

        if self._from_cluster:
            storage_tiers = pecan.request.dbapi.storage_tier_get_by_cluster(
                uuid, limit=limit, marker=marker_obj,
                sort_key=sort_key, sort_dir=sort_dir)

        else:
            storage_tiers = pecan.request.dbapi.storage_tier_get_list(limit, marker_obj,
                                                                      sort_key=sort_key,
                                                                      sort_dir=sort_dir)

        return StorageTierCollection.convert_with_links(
            storage_tiers, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    @wsme_pecan.wsexpose(StorageTierCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, uuid=None, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of storage tiers."""

        return self._get_tiers_collection(uuid, marker, limit, sort_key,
                                          sort_dir)

    @wsme_pecan.wsexpose(StorageTierCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, tier_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of storage tiers with detail."""

        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != 'storage_tiers':
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['storage_tiers', 'detail'])
        return self._get_tiers_collection(tier_uuid, marker, limit,
                                          sort_key, sort_dir, expand,
                                          resource_url)

    @wsme_pecan.wsexpose(StorageTier, types.uuid)
    def get_one(self, tier_uuid):
        """Retrieve information about the given storage tier."""

        if self._from_cluster:
            raise exception.OperationNotPermitted

        rpc_tier = objects.storage_tier.get_by_uuid(pecan.request.context,
                                                    tier_uuid)
        return StorageTier.convert_with_links(rpc_tier)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(StorageTier, body=StorageTier)
    def post(self, tier):
        """Create a new storage tier."""

        if self._from_cluster:
            raise exception.OperationNotPermitted

        try:
            tier = tier.as_dict()
            LOG.debug("storage tier post dict= %s" % tier)

            new_tier = _create(self, tier)
        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data: failed to create "
                                             "a storage tier object"))

        return StorageTier.convert_with_links(new_tier)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [StorageTierPatchType])
    @wsme_pecan.wsexpose(StorageTier, types.uuid,
                         body=[StorageTierPatchType])
    def patch(self, tier_uuid, patch):
        """Update an existing storage tier."""

        if self._from_cluster:
            raise exception.OperationNotPermitted

        LOG.debug("patch_data: %s" % patch)

        rpc_tier = objects.storage_tier.get_by_uuid(pecan.request.context,
                                                    tier_uuid)

        patch_obj = jsonpatch.JsonPatch(patch)
        for p in patch_obj:
            if p['path'] == '/backend_uuid':
                p['path'] = '/forbackendid'
                backend = objects.storage_backend.get_by_uuid(pecan.request.context,
                                                              p['value'])
                p['value'] = backend.id
            elif p['path'] == '/cluster_uuid':
                p['path'] = '/forclusterid'
                cluster = objects.cluster.get_by_uuid(pecan.request.context,
                                                      p['value'])
                p['value'] = cluster.id
        otier = copy.deepcopy(rpc_tier)

        # Validate provided patch data meets validity checks
        _pre_patch_checks(rpc_tier, patch_obj)

        try:
            tier = StorageTier(**jsonpatch.apply_patch(rpc_tier.as_dict(),
                                                       patch_obj))
        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Semantic Checks
        _check("modify", tier.as_dict())
        try:
            # Update only the fields that have changed
            for field in objects.storage_tier.fields:
                if rpc_tier[field] != getattr(tier, field):
                    rpc_tier[field] = getattr(tier, field)

            # Obtain the fields that have changed.
            delta = rpc_tier.obj_what_changed()
            if len(delta) == 0:
                raise wsme.exc.ClientSideError(
                    _("No changes to the existing tier settings were detected."))

            allowed_attributes = ['name']
            for d in delta:
                if d not in allowed_attributes:
                    raise wsme.exc.ClientSideError(
                        _("Cannot modify '%s' with this operation." % d))

            LOG.info("SYS_I orig    storage_tier: %s " % otier.as_dict())
            LOG.info("SYS_I new     storage_tier: %s " % rpc_tier.as_dict())

            # Save and return
            rpc_tier.save()
            return StorageTier.convert_with_links(rpc_tier)
        except exception.HTTPNotFound:
            msg = _("Storage Tier update failed: backend %s storage tier %s : patch %s"
                    % (backend['name'], tier['name'], patch))
            raise wsme.exc.ClientSideError(msg)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, tier_uuid):
        """Delete a storage tier."""

        if self._from_cluster:
            raise exception.OperationNotPermitted

        _delete(self, tier_uuid)


def _check_parameters(tier):

    # check and fill in the cluster information
    clusterId = tier.get('forclusterid') or tier.get('cluster_uuid')
    if not clusterId:
        raise wsme.exc.ClientSideError(_("No cluster information was provided "
                                         "for tier creation."))

    cluster = pecan.request.dbapi.cluster_get(clusterId)
    if uuidutils.is_uuid_like(clusterId):
        forclusterid = cluster['id']
    else:
        forclusterid = clusterId
    tier.update({'forclusterid': forclusterid})

    # Make sure that the default system tier is present
    default_tier_name = constants.SB_TIER_DEFAULT_NAMES[constants.SB_TIER_TYPE_CEPH]
    if 'name' not in tier or tier['name'] != default_tier_name:
        tiers = pecan.request.dbapi.storage_tier_get_all(name=default_tier_name)
        if len(tiers) == 0:
            raise wsme.exc.ClientSideError(
                _("Default system storage tier (%s) must be present before "
                  "adding additional tiers." % default_tier_name))


def _pre_patch_checks(tier_obj, patch_obj):
    for p in patch_obj:
        if p['path'] == '/name':
            if tier_obj.name == constants.SB_TIER_DEFAULT_NAMES[
                    constants.SB_TIER_TYPE_CEPH]:
                raise wsme.exc.ClientSideError(
                    _("Storage Tier %s cannot be renamed.") % tier_obj.name)
            if tier_obj.status == constants.SB_TIER_STATUS_IN_USE:
                raise wsme.exc.ClientSideError(
                    _("Storage Tier %s cannot be renamed. It is %s") %
                    (tier_obj.name, constants.SB_TIER_STATUS_IN_USE))
        elif p['path'] == '/capabilities':
                raise wsme.exc.ClientSideError(
                    _("The capabilities of storage tier %s cannot be "
                      "changed.") % tier_obj.name)
        elif p['path'] == '/backend_uuid':
                raise wsme.exc.ClientSideError(
                    _("The storage_backend associated with storage tier %s "
                      "cannot be changed.") % tier_obj.name)
        elif p['path'] == '/cluster_uuid':
                raise wsme.exc.ClientSideError(
                    _("The storage_backend associated with storage tier %s "
                      "cannot be changed.") % tier_obj.name)


def _check(op, tier):
    # Semantic checks
    LOG.debug("storage_tier: Semantic check for %s operation".format(op))

    # Check storage tier parameters
    _check_parameters(tier)

    if op == "add":
        # See if this storage tier already exists
        tiers = pecan.request.dbapi.storage_tier_get_all(name=tier['name'])
        if len(tiers) != 0:
            raise wsme.exc.ClientSideError(_("Storage tier (%s) "
                                             "already present." %
                                             tier['name']))
        if utils.is_aio_system(pecan.request.dbapi):
            # Deny adding secondary tiers if primary tier backend is not configured
            # for cluster. When secondary tier is added we also query ceph to create
            # pools and set replication therefore cluster has to be up.
            clusterId = tier.get('forclusterid') or tier.get('cluster_uuid')
            cluster_tiers = pecan.request.dbapi.storage_tier_get_by_cluster(clusterId)
            configured = False if cluster_tiers else True
            for t in cluster_tiers:
                if t.forbackendid:
                    bk = pecan.request.dbapi.storage_backend_get(t.forbackendid)
                    if bk.state != constants.SB_STATE_CONFIGURED:
                        msg = _("Operation denied. Storage backend '%s' "
                                "of tier '%s' must be in '%s' state."
                                % (bk.name, t['name'], constants.SB_STATE_CONFIGURED))
                        raise wsme.exc.ClientSideError(msg)
                    configured = True
            if not configured:
                msg = _("Operation denied. Adding secondary tiers to a cluster requires "
                        "primary tier storage backend of this cluster to be configured.")
                raise wsme.exc.ClientSideError(msg)

    elif op == "delete":

        if tier['name'] == constants.SB_TIER_DEFAULT_NAMES[
                constants.SB_TIER_TYPE_CEPH]:
            raise wsme.exc.ClientSideError(_("Storage Tier %s cannot be "
                                             "deleted.") % tier['name'])

        if tier['status'] != constants.SB_TIER_STATUS_DEFINED:
            raise wsme.exc.ClientSideError(_("Storage Tier %s cannot be "
                                             "deleted. It is %s") % (
                                                 tier['name'],
                                                 tier['status']))
    elif op == "modify":
        pass
    else:
        raise wsme.exc.ClientSideError(
            _("Internal Error: Invalid storage tier operation: %s" % op))

    return tier


def _set_defaults(tier):
    defaults = {
        'name': constants.SB_TIER_DEFAULT_NAMES[constants.SB_TIER_TYPE_CEPH],
        'type': constants.SB_TIER_TYPE_CEPH,
        'status': constants.SB_TIER_STATUS_DEFINED,
        'capabilities': {},
        'stors': [],
    }

    tier_merged = tier.copy()
    for key in tier_merged:
        if tier_merged[key] is None and key in defaults:
            tier_merged[key] = defaults[key]

    return tier_merged


# This method allows creating a storage tier through a non-HTTP
# request e.g. through profile.py while still passing
# through physical volume semantic checks and osd configuration
# Hence, not declared inside a class
#
# Param:
#       tier - dictionary of storage tier values
#       iprofile - True when created by a storage profile
def _create(self, tier, iprofile=None):
    LOG.info("storage_tier._create with initial params: %s" % tier)

    # Set defaults - before checks to allow for optional attributes
    tier = _set_defaults(tier)

    # Semantic checks
    tier = _check("add", tier)

    LOG.info("storage_tier._create with validated params: %s" % tier)

    ret_tier = pecan.request.dbapi.storage_tier_create(tier)

    LOG.info("storage_tier._create final, created, tier: %s" %
             ret_tier.as_dict())

    # update the crushmap with the new tier
    try:
        # If we are adding a tier where the crushmap file has yet to be applied,
        # then set the crushmap first. This will also add this new tier to the
        # crushmap, otherwise just add the new tier.
        crushmap_flag_file = os.path.join(constants.SYSINV_CONFIG_PATH,
                                          constants.CEPH_CRUSH_MAP_APPLIED)
        if not os.path.isfile(crushmap_flag_file):
            try:
                self._ceph.set_crushmap()
            except exception.CephCrushMapNotApplied as e:
                LOG.warning("Crushmap not applied, seems like ceph cluster is not ""configured. "
                            "Operation will be retried with first occasion. "
                            "Reason: %s" % str(e))
        else:
            self._ceph.crushmap_tiers_add()
    except (exception.CephCrushMaxRecursion,
            exception.CephCrushInvalidTierUse) as e:
        pecan.request.dbapi.storage_tier_destroy(ret_tier.id)
        raise wsme.exc.ClientSideError(_("Failed to update the crushmap for "
                                         "tier: %s - %s") % (ret_tier.name, e))

    return ret_tier


def _delete(self, tier_uuid):
    """Delete a storage tier"""

    tier = objects.storage_tier.get_by_uuid(pecan.request.context, tier_uuid)

    # Semantic checks
    _check("delete", tier.as_dict())

    # update the crushmap by removing the tier
    try:
        self._ceph.crushmap_tier_delete(tier.name)
    except exception.CephCrushMapNotApplied:
        # If crushmap has not been applied then there is no rule to update.
        pass

    try:
        pecan.request.dbapi.storage_tier_destroy(tier.id)
    except exception.HTTPNotFound:
        msg = _("Failed to delete storage tier %s." % tier.name)
        raise wsme.exc.ClientSideError(msg)
