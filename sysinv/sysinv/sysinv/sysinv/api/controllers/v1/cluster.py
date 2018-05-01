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
# Copyright (c) 2016-2017 Wind River Systems, Inc.
#


import uuid

import pecan
import wsme
import wsmeext.pecan as wsme_pecan
import os
from oslo_utils._i18n import _
from pecan import rest
from sysinv import objects
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.api.controllers.v1 import storage_tier as storage_tier_api
from sysinv.api.controllers.v1.query import Query
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.openstack.common import log

from wsme import types as wtypes

LOG = log.getLogger(__name__)


class ClusterPatchType(types.JsonPatchType):
    """A complex type that represents a single json-patch operation."""

    value = types.MultiType([wtypes.text, [list]])

    @staticmethod
    def mandatory_attrs():
        """These attributes cannot be removed."""
        result = (super(ClusterPatchType, ClusterPatchType).
                  mandatory_attrs())
        result.append(['/name', '/peers'])
        return result

    @staticmethod
    def readonly_attrs():
        """These attributes cannot be updated."""
        return ['/name', '/type']

    @staticmethod
    def validate(patch):
        result = (super(ClusterPatchType, ClusterPatchType).
                  validate(patch))
        if patch.op in ['add', 'remove']:
            msg = _("Attributes cannot be added or removed")
            raise wsme.exc.ClientSideError(msg % patch.path)
        if patch.path in patch.readonly_attrs():
            msg = _("'%s' is a read-only attribute and can not be updated")
            raise wsme.exc.ClientSideError(msg % patch.path)
        return result


class Cluster(base.APIBase):
    """API representation of a Cluster.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of a Cluster.
    """

    id = int
    "Unique ID for this cluster"

    uuid = types.uuid
    "Unique UUID for this cluster representation"

    cluster_uuid = types.uuid
    "The Unique UUID of the cluster"

    type = wtypes.text
    "Defined type of the cluster"

    name = wtypes.text
    "User defined name of the cluster"

    peers = types.MultiType([list])
    "List of peers info in the cluster"

    tiers = types.MultiType([list])
    "List of storage tier info in the cluster"

    links = [link.Link]
    "A list containing a self link and associated cluster links"

    storage_tiers = [link.Link]
    "Links to the collection of storage tiers on this cluster"

    def __init__(self, **kwargs):
        self.fields = objects.cluster.fields.keys()
        for k in self.fields:
            if not hasattr(self, k):
                # Skip fields that we choose to hide
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    def as_dict(self):
        """
        Sets additional DB only attributes when converting from an API object
        type to a dictionary that will be used to populate the DB.
        """
        data = super(Cluster, self).as_dict()
        return data

    @classmethod
    def convert_with_links(cls, rpc_cluster, expand=True):
        cluster = Cluster(**rpc_cluster.as_dict())
        if not expand:
            cluster.unset_fields_except(['uuid', 'cluster_uuid',
                                         'type', 'name', 'peers',
                                         'tiers'])

        cluster.links = [link.Link.make_link('self', pecan.request.host_url,
                                          'clusters', cluster.uuid),
                         link.Link.make_link('bookmark',
                                             pecan.request.host_url,
                                             'clusters', cluster.uuid,
                                             bookmark=True)
                         ]
        if expand:
            cluster.storage_tiers = [link.Link.make_link('self',
                                                         pecan.request.host_url,
                                                         'clusters',
                                                         cluster.uuid + "/storage_tiers"),
                                     link.Link.make_link(
                                         'bookmark',
                                         pecan.request.host_url,
                                         'clusters',
                                         cluster.uuid + "/storage_tiers",
                                         bookmark=True)
                                     ]

        return cluster

    @classmethod
    def _validate_name(cls, name):
        if len(name) < 1:
            raise ValueError(_("Name must not be an empty string"))

    @classmethod
    def _validate_type(cls, type):
        if type and len(type) < 1:
            raise ValueError(_("Cluster type must not be an empty string"))

    def validate_syntax(self):
        """
        Validates the syntax of each field.
        """
        self._validate_name(self.name)
        self._validate_type(self.type)


class ClusterCollection(collection.Collection):
    """API representation of a collection of Clusters."""

    clusters = [Cluster]
    "A list containing Cluster objects"

    def __init__(self, **kwargs):
        self._type = 'clusters'

    @classmethod
    def convert_with_links(cls, rpc_cluster, limit, url=None,
                           expand=False, **kwargs):
        collection = ClusterCollection()
        collection.clusters = [Cluster.convert_with_links(p, expand)
                               for p in rpc_cluster]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'ClusterController'


class ClusterController(rest.RestController):
    """REST controller for Clusters."""

    storage_tiers = storage_tier_api.StorageTierController(from_cluster=True)
    "Expose storage tiers as a sub-element of clusters"

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    def _get_cluster_collection(self, parent_uuid,
                                marker=None, limit=None, sort_key=None,
                                sort_dir=None, expand=False,
                                resource_url=None,
                                q=None):
        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        kwargs = {}
        if q is not None:
            for i in q:
                if i.op == 'eq':
                    kwargs[i.field] = i.value

        marker_obj = None
        if marker:
            marker_obj = objects.cluster.get_by_uuid(
                pecan.request.context, marker)

            clusters = pecan.request.dbapi.clusters_get_list(
                limit=limit, marker=marker_obj,
                sort_key=sort_key, sort_dir=sort_dir)
        else:
            clusters = pecan.request.dbapi.clusters_get_all(**kwargs)

        return ClusterCollection.convert_with_links(
            clusters, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    def _query_cluster(self, cluster):
        try:
            result = pecan.request.dbapi.cluster_query(cluster)
        except exception.ClusterNotFoundByName:
            return None
        return result

    def _check_name_conflict(self, cluster):
        try:
            pool = pecan.request.dbapi.cluster_get(cluster['name'])
            raise exception.ClusterAlreadyExists(name=cluster['name'])
        except exception.ClusterNotFound:
            pass

    def _check_valid_peer(self, name, status):
        # TODO: check if name in valid hostnames
        return

    def _check_valid_peers(self, cluster):
        for name, status in cluster['peers']:
            self._check_valid_peer(name, status)

    def _check_allocated_peers(self, cluster_obj):
        peers = cluster_obj.peers
        if peers:
            hosts_unlocked = []
            for peer in peers:
                hosts = peer.get('hosts') or []
                for host in hosts:
                    h = pecan.request.dbapi.ihost_get(host)
                    if h.administrative == constants.ADMIN_UNLOCKED:
                        hosts_unlocked.append(h.hostname)

            if hosts_unlocked:
                raise exception.ClusterInUseByPeers(
                    hosts_unlocked=hosts_unlocked)

    def _set_defaults(self, cluster):
        cluster['uuid'] = str(uuid.uuid4())
        if 'system_id' not in cluster:
            isystem = pecan.request.dbapi.isystem_get_one()
            cluster['system_id'] = isystem.id
        if 'type' not in cluster:
            cluster['type'] = constants.CINDER_BACKEND_CEPH

    def _validate_peer_updates(self, cluster, updates):
        peers = pecan.request.dbapi.peers_get_by_cluster(cluster.id)
        if not peers:
            return

    def _validate_updates(self, cluster, updates):
        if 'name' in updates:
            Cluster._validate_name(updates['name'])

        if 'peers' in updates:
            self._validate_peer_updates(cluster, updates)
        return

    def _create_cluster(self, cluster):
        cluster.validate_syntax()
        cluster_dict = cluster.as_dict()
        self._set_defaults(cluster_dict)
        LOG.info("Create cluster cluster_dict=%s" % cluster_dict)
        self._set_defaults(cluster_dict)

        # Check for semantic conflicts
        self._check_name_conflict(cluster_dict)
        self._check_valid_peers(cluster_dict)

        # Attempt to create the new cluster record
        return pecan.request.dbapi.cluster_create(cluster_dict)

    def _get_updates(self, patch):
        """Retrieve the updated attributes from the patch request."""
        updates = {}
        for p in patch:
            attribute = p['path'] if p['path'][0] != '/' else p['path'][1:]
            updates[attribute] = p['value']
        return updates

    def _get_one(self, cluster_uuid):
        rpc_cluster = objects.cluster.get_by_uuid(
            pecan.request.context, cluster_uuid)
        return Cluster.convert_with_links(rpc_cluster)

    @wsme_pecan.wsexpose(ClusterCollection, [Query], types.uuid, types.uuid,
                         int, wtypes.text, wtypes.text)
    def get_all(self, q=[], parent_uuid=None,
                marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of Clusters."""
        return self._get_cluster_collection(parent_uuid, marker, limit,
                                            sort_key, sort_dir, q=q)

    @wsme_pecan.wsexpose(Cluster, types.uuid)
    def get_one(self, cluster_uuid):
        return self._get_one(cluster_uuid)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Cluster, body=Cluster)
    def post(self, cluster):
        """Create a new Cluster."""
        if not os.path.exists(constants.SYSINV_RUNNING_IN_LAB):
            msg = _("Cluster cannot be created: %s")
            raise wsme.exc.ClientSideError(msg % cluster.as_dict())
        return self._create_cluster(cluster)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [ClusterPatchType])
    @wsme_pecan.wsexpose(Cluster, types.uuid, body=[ClusterPatchType])
    def patch(self, cluster_uuid, patch):
        """Updates attributes of a Cluster."""
        if not os.path.exists(constants.SYSINV_RUNNING_IN_LAB):
            msg = _("Cluster attributes cannot be modified: %s")
            raise wsme.exc.ClientSideError(msg % patch.path)

        cluster = self._get_one(cluster_uuid)
        updates = self._get_updates(patch)
        self._validate_updates(cluster, updates)
        return pecan.request.dbapi.cluster_update(cluster_uuid, updates)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, cluster_uuid):
        """Delete a Cluster."""
        if not os.path.exists(constants.SYSINV_RUNNING_IN_LAB):
            msg = _("Cluster cannot be deleted: %s")
            raise wsme.exc.ClientSideError(msg % cluster_uuid)

        cluster = self._get_one(cluster_uuid)
        self._check_allocated_peers(cluster)
        pecan.request.dbapi.cluster_destroy(cluster_uuid)
