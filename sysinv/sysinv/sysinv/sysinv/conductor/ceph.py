# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright (c) 2016-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" System Inventory Ceph Utilities and helper functions."""

from __future__ import absolute_import

import os
import uuid
import copy
import six
import tsconfig.tsconfig as tsc
from requests.exceptions import RequestException
from requests.exceptions import ReadTimeout

from cephclient import wrapper as ceph
from fm_api import fm_api
from oslo_log import log as logging
from oslo_utils import uuidutils
from sysinv._i18n import _
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.common.storage_backend_conf import StorageBackendConfig

LOG = logging.getLogger(__name__)
CEPH_POOLS = copy.deepcopy(constants.CEPH_POOLS)


class CephOperator(object):
    """Class to encapsulate Ceph operations for System Inventory
       Methods on object-based storage devices (OSDs).
    """

    executed_default_quota_check = False
    executed_default_quota_check_by_tier = {}

    def __init__(self, db_api):
        self._fm_api = fm_api.FaultAPIs()
        self._db_api = db_api
        self._ceph_api = ceph.CephWrapper(
            endpoint='http://localhost:{}'.format(constants.CEPH_MGR_PORT))
        self._db_cluster = None
        self._db_primary_tier = None
        self._cluster_name = 'ceph_cluster'
        self._init_db_cluster_and_tier()

    # Properties: During config_controller we will not initially have a cluster
    # DB record. Make sure we handle this exception
    @property
    def cluster_id(self):
        try:
            return self._db_cluster.id
        except AttributeError:
            return None

    @property
    def cluster_ceph_uuid(self):
        try:
            return self._db_cluster.cluster_uuid
        except AttributeError:
            return None

    @property
    def cluster_db_uuid(self):
        try:
            return self._db_cluster.uuid
        except AttributeError:
            return None

    @property
    def primary_tier_uuid(self):
        try:
            return self._db_primary_tier.uuid
        except AttributeError:
            return None

    def ceph_status_ok(self, timeout=10):
        """
            returns rc bool. True if ceph ok, False otherwise
            :param timeout: ceph api timeout
        """
        rc = True

        try:
            response, body = self._ceph_api.status(body='json',
                                                   timeout=timeout)
            if (body['output']['health']['status'] !=
                    constants.CEPH_HEALTH_OK):
                rc = False
        except Exception as e:
            rc = False
            LOG.warn("ceph status exception: %s " % e)

        return rc

    def _get_fsid(self, timeout=10):
        try:
            response, fsid = self._ceph_api.fsid(body='text', timeout=timeout)
        except Exception as e:
            LOG.warn("ceph_api.fsid failed: " + str(e))
            return None
        if not response.ok:
            LOG.warn("CEPH health check failed: %s", response.reason)
            return None
        return str(fsid.strip())

    def _init_db_cluster_and_tier(self):
        # Ensure that on every conductor start/restart we have an initial
        # cluster UUID value that is valid and consistent for the state of the
        # installation. Also make sure that we have a cluster DB entry
        # established
        try:
            self._db_cluster = self._db_api.clusters_get_all(
                type=constants.CINDER_BACKEND_CEPH)[0]
            if not self.cluster_ceph_uuid:
                # Retrieve ceph cluster fsid and update database
                fsid = self._get_fsid()
                if uuidutils.is_uuid_like(fsid):
                    LOG.info("Update cluster record: fsid=%s." % fsid)
                    self._db_cluster.cluster_uuid = fsid
                    self._db_api.cluster_update(
                        self.cluster_db_uuid,
                        {'cluster_uuid': fsid})
            self._db_primary_tier = self._db_api.storage_tier_get_all(
                name=constants.SB_TIER_DEFAULT_NAMES[
                    constants.SB_TIER_TYPE_CEPH])[0]
        except IndexError:
            # No existing DB record for the cluster, try to create one
            self._create_db_ceph_cluster()

    def _create_db_ceph_cluster(self):
        # Make sure the system has been configured
        try:
            isystem = self._db_api.isystem_get_one()
        except exception.NotFound:
            LOG.info('System is not configured. Cannot create Cluster '
                     'DB entry')
            return

        # Try to use ceph cluster fsid
        fsid = self._get_fsid()
        LOG.info("Create new ceph cluster record: fsid=%s." % fsid)
        # Create the default primary cluster
        self._db_cluster = self._db_api.cluster_create(
            {'uuid': fsid if uuidutils.is_uuid_like(fsid) else str(uuid.uuid4()),
             'cluster_uuid': fsid,
             'type': constants.CINDER_BACKEND_CEPH,
             'name': self._cluster_name,
             'system_id': isystem.id})

        # Create the default primary ceph storage tier
        LOG.info("Create primary ceph tier record.")
        self._db_primary_tier = self._db_api.storage_tier_create(
            {'forclusterid': self.cluster_id,
             'name': constants.SB_TIER_DEFAULT_NAMES[constants.SB_TIER_TYPE_CEPH],
             'type': constants.SB_TIER_TYPE_CEPH,
             'status': constants.SB_TIER_STATUS_DEFINED,
             'capabilities': {}})

    class GroupStats(object):
        def __init__(self):
            self.peer_count = 0
            self.incomplete_peers = []

    def _get_db_peer_groups(self, replication):
        # Process all existing peer records and extract view of the peer groups
        host_to_peer = {}
        stats = CephOperator.GroupStats()

        peers = self._db_api.peers_get_all_by_cluster(self.cluster_id)
        for peer in peers:
            for host in peer.hosts:
                # Update host mapping
                host_to_peer[host] = peer

            stats.peer_count += 1
            if len(peer.hosts) < replication:
                stats.incomplete_peers.append(peer)
        return host_to_peer, stats

    def assign_host_to_peer_group(self, host_obj):
        # Prevent re-running the peer assignment logic if the host already has a
        # peer
        if host_obj.peer_id:
            LOG.debug('Host:%s is already assigned to a peer group. Keeping '
                      'current group assignemnt.' % host_obj.hostname)
            return

        hostname = host_obj.hostname

        # Get configured ceph base replication
        replication, _ = StorageBackendConfig.get_ceph_max_replication(self._db_api)

        host_to_peer, stats = self._get_db_peer_groups(replication)

        # Sanity Check #2: Is this host already assigned?
        peer = host_to_peer.get(hostname)
        if peer:
            raise exception.PeerAlreadyContainsThisHost(
                host=hostname,
                peer_name=peer.name)

        try:
            peer_obj = stats.incomplete_peers[0]
            peer_name = peer_obj.name
        except IndexError:
            peer_obj = None
            peer_name = '%s%s' % (constants.PEER_PREFIX,
                                  str(stats.peer_count))

        if not peer_obj:
            peer_obj = self._db_api.peer_create({
                'name': peer_name,
                'status': constants.PROVISIONED,
                'cluster_id': self.cluster_id})

        # associate the host to the peer
        self._db_api.ihost_update(host_obj.uuid, {'peer_id': peer_obj.id})
        LOG.info("Storage Host: %s assigned to Peer Group %s" %
                 (hostname, peer_obj.name))

    def update_ceph_cluster(self, host):
        # We get here when a storage host is unlocked.
        #
        # For a new install, the DB cluster record is not created at this point
        # due to chicken vs egg of conductor start and isystem record creation.
        if not self._db_cluster:
            self._init_db_cluster_and_tier()
        elif not self.cluster_ceph_uuid:
            # When the CephOperator is instantiated and the system has been
            # configured we are guaranteed a cluster db uuid, but not a cluster
            # ceph uuid if the Ceph REST API is not operational. Everytime we
            # unlock, if the cluster uuid is not present, then check to see if
            # it's available via the Ceph REST API and update accordingly
            #
            # TiC currently only supports one cluster and the UUID will not
            # change so once it's saved in the DB we will no longer check for an
            # update on subsequent unlocks
            #
            # Check the cluster via the REST API
            fsid = self._get_fsid()
            if uuidutils.is_uuid_like(fsid):
                # we have a valid cluster uuid, update the DB and the internal
                # Ceph Operator tracking variable
                self._db_api.cluster_update(
                    self.cluster_db_uuid,
                    {'cluster_uuid': fsid})
                self._db_cluster.cluster_uuid = fsid

        self.assign_host_to_peer_group(host)

    def osd_pool_get(self, pool_name, param):
        response, body = self._ceph_api.osd_pool_get(
            pool_name, param, body='json')
        if not response.ok:
            raise exception.CephPoolGetParamFailure(
                pool_name=pool_name,
                param=param,
                reason=response.reason)
        return response, body

    # TODO(CephPoolsDecouple): remove
    def osd_set_pool_param(self, pool_name, param, value):
        response, body = self._ceph_api.osd_set_pool_param(
            pool_name, param, value,
            force=None, body='json')
        if response.ok:
            LOG.info('OSD set pool param: pool={}, name={}, value={}'.format(pool_name, param, value))
        else:
            raise exception.CephPoolSetParamFailure(
                pool_name=pool_name,
                param=param,
                value=str(value),
                reason=response.reason)
        return response, body

    def osd_create(self, stor_uuid, **kwargs):
        """ Create osd via ceph api
        :param stor_uuid: uuid of stor object
        """
        response, body = self._ceph_api.osd_create(stor_uuid, **kwargs)
        return response, body

    def rebuild_osdmap(self):
        """Rebuild osdmap if it is empty.
        """
        stors = self._db_api.istor_get_list(sort_key='osdid', sort_dir='asc')

        if not stors:
            return True

        for stor in stors:
            if stor['osdid'] >= 0:
                LOG.info("Creating osd.%s uuid %s"
                         % (stor['osdid'], stor['uuid']))
                response, body = self.osd_create(stor['uuid'], body='json',
                                                 params={'id': stor['osdid']})
                if not response.ok:
                    LOG.error("OSD create failed for osd.%s, uuid %s: %s"
                              % (stor['osdid'], stor['uuid'], response.reason))
                    return False

        LOG.info("osdmap is rebuilt.")
        return True

    # TODO(CephPoolsDecouple): remove
    def _pool_create(self, name, pg_num, pgp_num, ruleset,
                     size, min_size):
        """Create Ceph pool and ruleset.

        :param name:  pool name
        :param pg_num:   number of placement groups
        :param pgp_num:  number of placement groups for placement
        :param size:     number of replicas for objects in the pool
        :param min_size:  minimum number of replicas required for I/O
        """
        # Check if the pool exists
        response, body = self._ceph_api.osd_pool_get(
            name, "pg_num", body='json')

        if not response.ok:
            # Pool doesn't exist - create it

            response, body = self._ceph_api.osd_pool_create(
                name, pg_num, pgp_num, pool_type="replicated",
                ruleset=ruleset, body='json')
            if response.ok:
                LOG.info(_("Created OSD pool: pool_name={}, pg_num={}, "
                           "pgp_num={}, pool_type=replicated, ruleset={}, "
                           "size={}, min_size={}").format(name, pg_num,
                                                          pgp_num, ruleset,
                                                          size, min_size))
            else:
                e = exception.CephPoolCreateFailure(
                    name=name, reason=response.reason)
                LOG.error(e)
                raise e

            # Set replication factor (size)
            response, body = self.osd_set_pool_param(name, "size", size)
            if response.ok:
                LOG.info(_("Assigned size (replication factor) to OSD pool: "
                           "pool_name={}, size={}").format(name, size))

                # Set minimum number of replicas required for I/O (min_size)
                response, body = self.osd_set_pool_param(name,
                                                         "min_size", min_size)

            if response.ok:
                LOG.info(_("Assigned min_size (replication) to OSD pool: "
                           "pool_name={}, size={}").format(name, size))

                # Explicitly assign the ruleset to the pool on creation since it is
                # ignored in the create call
                response, body = self._ceph_api.osd_set_pool_param(
                    name, "crush_ruleset", ruleset, body='json')

            if response.ok:
                LOG.info(_("Assigned crush ruleset to OSD pool: "
                           "pool_name={}, ruleset={}").format(
                               name, ruleset))
            else:
                msg = _("Failed to complete parameter assignment on OSD pool"
                        ": {0}. reason: {1}").format(name, response.reason)
                e = exception.CephFailure(reason=msg)
                LOG.error(e)
                self.delete_osd_pool(name)
                raise e

        else:
            # Pool exists, just resize
            # Set replication factor (size)
            response, body = self.osd_set_pool_param(name, "size", size)

            if response.ok:
                LOG.debug(_("Assigned size (replication factor) to OSD pool: "
                            "pool_name={}, size={}").format(name, size))

                # Set minimum number of replicas required for I/O (min_size)
                response, body = self.osd_set_pool_param(name,
                                                         "min_size", min_size)

            if response.ok:
                LOG.debug(_("Assigned min_size (min replicas) to OSD pool: "
                            "pool_name={}, min_size={}").format(name,
                                                                min_size))
            else:
                msg = _("Failed to complete parameter assignment on existing "
                        "OSD pool: {0}. reason: {1}").format(name,
                                                             response.reason)
                e = exception.CephFailure(reason=msg)
                LOG.error(e)
                raise e

    # TODO(CephPoolsDecouple): remove
    def create_or_resize_osd_pool(self, pool_name, pg_num, pgp_num,
                                  size, min_size):
        """Create or resize an osd pool as needed
        :param pool_name:  pool name
        :param pg_num:   number of placement groups
        :param pgp_num:  number of placement groups for placement
        :param size:     number of replicas for objects in the pool
        :param min_size:  minimum number of replicas required for I/O
        """

        # ruleset 0: is the default ruleset if no crushmap is loaded or
        # the ruleset for the backing tier if loaded:
        # Name: storage_tier_ruleset
        ruleset = 0

        # Create the pool if not present
        self._pool_create(pool_name, pg_num, pgp_num, ruleset, size, min_size)

    def delete_osd_pool(self, pool_name):
        """Delete an osd pool
        :param pool_name:  pool name
        """
        response, body = self._ceph_api.osd_pool_delete(
            pool_name, pool_name,
            sure='--yes-i-really-really-mean-it',
            body='json')
        if response.ok:
            LOG.info(_("Deleted OSD pool {}").format(pool_name))
        else:
            e = exception.CephPoolDeleteFailure(
                name=pool_name, reason=response.reason)
            LOG.warn(e)
            raise e

    def list_osd_pools(self):
        """List all osd pools
        """
        resp, pools = self._ceph_api.osd_pool_ls(body='json')
        if not resp.ok:
            e = exception.CephPoolListFailure(
                reason=resp.reason)
            LOG.error(e)
            raise e
        else:
            return pools['output']

    def get_ceph_object_pool_name(self):
        response, body = self._ceph_api.osd_pool_get(
            constants.CEPH_POOL_OBJECT_GATEWAY_NAME_JEWEL,
            "pg_num",
            body='json')

        if response.ok:
            return constants.CEPH_POOL_OBJECT_GATEWAY_NAME_JEWEL

        response, body = self._ceph_api.osd_pool_get(
            constants.CEPH_POOL_OBJECT_GATEWAY_NAME_HAMMER,
            "pg_num",
            body='json')

        if response.ok:
            return constants.CEPH_POOL_OBJECT_GATEWAY_NAME_HAMMER

        return None

    def update_ceph_object_pool_name(self, pool):
        """
           Check whether JEWEL or HAMMER pool should be used
        """
        if pool['pool_name'] == constants.CEPH_POOL_OBJECT_GATEWAY_NAME_JEWEL:
            # Check if Hammer version pool exists. If it does, it means it is an
            # upgrade from R3; otherwise, it is a fresh R4+ installation
            response, body = self._ceph_api.osd_pool_get(
                constants.CEPH_POOL_OBJECT_GATEWAY_NAME_HAMMER,
                "pg_num",
                body='json')

            if response.ok:
                # Now check if Swift was enabled in R3. If it was, the Hammer pool
                # will be kept; otherwise, the Hammer pool will be deleted and a
                # Jewel pool will be created.
                storage_ceph = self._db_api.storage_ceph_get_list()[0]
                if storage_ceph['object_gateway'] is True:
                    # Make sure Swift/Radosgw is really enabled
                    response, body = self._ceph_api.osd_pool_get(
                        constants.CEPH_POOL_OBJECT_GATEWAY_ROOT_NAME,
                        "pg_num",
                        body='json')
                    if response.ok:
                        LOG.info("Hammer-->Jewel upgrade: keep Hammer object data pool %s",
                                 constants.CEPH_POOL_OBJECT_GATEWAY_NAME_HAMMER)
                        pool['pool_name'] = constants.CEPH_POOL_OBJECT_GATEWAY_NAME_HAMMER
                    else:
                        if body['status'].find("unrecognized pool") != -1:
                            LOG.warn("Swift is enabled but pool %s does not exist.",
                                     constants.CEPH_POOL_OBJECT_GATEWAY_ROOT_NAME)
                            LOG.info("Hammer-->Jewel upgrade: delete inactive Hammer object data pool %s",
                                     constants.CEPH_POOL_OBJECT_GATEWAY_NAME_HAMMER)
                            self.delete_osd_pool(constants.CEPH_POOL_OBJECT_GATEWAY_NAME_HAMMER)
                        else:
                            LOG.warn("Failed to query pool %s ",
                                     constants.CEPH_POOL_OBJECT_GATEWAY_ROOT_NAME)

                else:
                    LOG.info("Hammer-->Jewel upgrade: delete inactive Hammer object data pool %s",
                             constants.CEPH_POOL_OBJECT_GATEWAY_NAME_HAMMER)
                    self.delete_osd_pool(constants.CEPH_POOL_OBJECT_GATEWAY_NAME_HAMMER)

    def _configure_pool_key(self, pool_name):
        """Get CEPH key for a certain pool."""
        response, body = ("", "")
        caps_dict = {'mon': 'allow r',
                     'osd': 'allow rwx pool=%s' % pool_name}
        entity = "client.%s" % pool_name
        try:
            response, body = ("", "")
            response, body = self._ceph_api.auth_get_or_create(
                entity, caps_dict, body='json', timeout=10)
            auth_result = body['output']
            rc = auth_result[0].get('key')
        except Exception as e:
            rc = None
            LOG.info("CEPH auth exception: %s response: %s body: %s" %
                     (str(e), str(response), str(body)))

        return rc

    # TODO(CephPoolsDecouple): remove
    def _configure_secondary_tier_pools(self, tier_obj, size, min_size):
        """Configure the service pools that are allowed for additional ceph tiers.
        """
        # Get the backend object if there is one attached.

        backend = None
        if tier_obj.forbackendid:
            backend = self._db_api.storage_ceph_get(tier_obj.forbackendid)

        # Make sure OSD exist for this tier before creating ceph pools
        LOG.info("Calling _configure_secondary_tier_pools "
                 "to create/update ceph pools for tier: %s" % tier_obj.name)

        for p in constants.SB_TIER_CEPH_POOLS:
            # If we have a backend for the tier, then set the quota
            if backend:
                # if the quota is not set, set the default value
                quota_gib_value = backend.get(p['be_quota_attr'], None)
                if quota_gib_value is None:
                    self._db_api.storage_ceph_update(backend.uuid,
                                                     {p['be_quota_attr']:
                                                      p['quota_default']})
                    quota_gib_value = p['quota_default']

            # get the pool name
            pool_name = "%s-%s" % (p['pool_name'], tier_obj.name)
            rule_name = "{0}{1}{2}".format(
                tier_obj.name,
                constants.CEPH_CRUSH_TIER_SUFFIX,
                "-ruleset").replace('-', '_')

            # get the rule for the tier, if present then create the pool if
            # required.
            response, body = self._ceph_api.osd_crush_rule_dump(name=rule_name,
                                                                body='json')
            if response.ok:
                ruleset = body['output']['ruleset']

                # create/update the pool
                self._pool_create(pool_name, p['pg_num'], p['pgp_num'],
                                  ruleset, size, min_size)

            else:
                e = exception.CephPoolRulesetFailure(
                    name=rule_name, reason=body['status'])
                raise e

    def _update_db_capabilities(self, bk, new_storceph):
        # Avoid updating DB for all capabilities in new_storceph as we
        # don't manage them. Leave the callers deal with it.
        if (not new_storceph or
                (new_storceph and bk['name'] != new_storceph['name'])):
            self._db_api.storage_backend_update(
                bk['id'],
                {'capabilities': bk['capabilities']}
            )

    def get_osd_tree(self):
        """Get OSD tree info
           return: list of nodes and a list of stray osds e.g.:
             [{u'type_id': 10, u'type': u'root', u'id': -6, u'name': u'gold-tier',
               u'children': [-7]},
              {u'type_id': 2, u'type': u'chassis', u'id': -7, u'name': u'group-0-gold',
               u'children': [-9, -8]},
              {u'status': u'up', u'name': u'osd.2', u'exists': 1, u'type_id': 0,
               u'reweight': 1.0, u'crush_weight': 0.008789, u'primary_affinity': 1.0,
               u'depth': 3, u'type': u'osd', u'id': 2}, ...]
             [{u'status': u'up', u'name': u'osd.1', u'exists': 1, u'reweight': 1.0,
               u'type_id': 0, u'crush_weight': 0.0, u'primary_affinity': 1.0, u'depth': 0,
               u'type': u'osd', u'id': 1}, ...]
        """

        resp, body = self._ceph_api.osd_tree(body='json')
        if not resp.ok:
            LOG.error("Failed to get OSD tree info")
            return resp, None, None
        else:
            return resp, body['output']['nodes'], body['output']['stray']

    def set_osd_down(self, osdid):
        """Set an osd to down state
           :param osdid: OSD id
        """

        response, body = self._ceph_api.osd_down(
            osdid, body='json')
        if response.ok:
            LOG.info("Set OSD %d to down state.", osdid)
        else:
            LOG.error("Set OSD down failed for OSD %d: %s",
                      osdid, response.reason)
            response.raise_for_status()

    def mark_osd_down(self, osdid):
        """Mark the object store device down
           :param osdid: object based storage id
        """

        to_mark_osd_down = False
        resp, nodes, stray = self.get_osd_tree()
        if not resp.ok:
            # We would still try to mark the osd down
            to_mark_osd_down = True
        else:
            osdid_str = "osd." + str(osdid)
            for entry in nodes + stray:
                if entry['name'] == osdid_str:
                    if entry['status'] == 'up':
                        LOG.info("OSD %s is still up. Mark it down.", osdid_str)
                        to_mark_osd_down = True
                    break

        if to_mark_osd_down:
            self.set_osd_down(osdid)

    def osd_remove_crush_auth(self, osdid):
        """ Remove the object store device from ceph
            osdid: object based storage id
            :param osdid:
        """

        osdid_str = "osd." + str(osdid)
        # Remove the OSD from the crush map
        response, body = self._ceph_api.osd_crush_remove(
            osdid_str, body='json')
        if not response.ok:
            LOG.error("OSD crush remove failed for OSD %s: %s",
                      osdid_str, response.reason)
            response.raise_for_status()

        # Remove the OSD authentication key
        response, body = self._ceph_api.auth_del(
            osdid_str, body='json')
        if not response.ok:
            LOG.error("Auth delete failed for OSD %s: %s",
                      osdid_str, response.reason)
            response.raise_for_status()

    def osd_remove(self, *args, **kwargs):
        return self._ceph_api.osd_remove(*args, **kwargs)

    def get_cluster_df_stats(self, timeout=10):
        """Get the usage information for the ceph cluster.
        :param timeout:
        """

        resp, body = self._ceph_api.df(body='json',
                                       timeout=timeout)
        if not resp.ok:
            e = exception.CephGetClusterUsageFailure(reason=resp.reason)
            LOG.error(e)
            raise e
        else:
            return body["output"]["stats"]

    def get_pools_df_stats(self, timeout=10):
        resp, body = self._ceph_api.df(body='json',
                                       timeout=timeout)
        if not resp.ok:
            e = exception.CephGetPoolsUsageFailure(reason=resp.reason)
            LOG.error(e)
            raise e
        else:
            return body["output"]["pools"]

    # TODO(CephPoolsDecouple): remove
    # This function is only called from audit_osd_quotas_for_tier() which
    # will be removed by CephPoolsDecouple.
    def get_osd_stats(self, timeout=30):
        try:
            resp, body = self._ceph_api.osd_stat(body='json',
                                                 timeout=timeout)
        except ReadTimeout:
            resp = type('Response', (),
                        dict(ok=False,
                             reason=('Ceph API osd_stat() timeout '
                                     'after {} seconds').format(timeout)))
        if not resp.ok:
            e = exception.CephGetOsdStatsFailure(reason=resp.reason)
            LOG.error(e)
            raise e
        else:
            return body["output"]

    def have_ceph_monitor_access(self, timeout=5):
        """ Verify that ceph monitor access will not timeout.

        :param timeout: Time in seconds to wait for the REST API request to
            respond.
        """
        available_mons = 0
        monitors = self._db_api.ceph_mon_get_list()
        for m in monitors:
            try:
                ihost = self._db_api.ihost_get_by_hostname(m.hostname)
            except exception.NodeNotFound:
                LOG.error("Monitor host %s not found" % m.hostname)
                continue

            if (ihost['administrative'] == constants.ADMIN_UNLOCKED and
                    ihost['operational'] == constants.OPERATIONAL_ENABLED):
                available_mons += 1

        # Avoid calling the ceph rest_api until we have a minimum configuration
        check_access = False
        if cutils.is_aio_system(self._db_api) and available_mons > 0:
            # one monitor: need it available
            check_access = True
        elif available_mons > 1:
            # three monitors: need two available
            check_access = True

        LOG.debug("Checking ceph monitors. Available: %s. Check cluster: "
                 "access %s" % (available_mons, check_access))
        if check_access:
            return True if self._get_fsid(timeout) else False
        return False

    def get_ceph_cluster_info_availability(self):
        # TODO(CephPoolsDecouple): rework
        # Check if the ceph cluster is ready to return statistics
        storage_hosts = self._db_api.ihost_get_by_personality(
            constants.STORAGE)

        is_aio = tsc.system_type == constants.TIS_AIO_BUILD

        if not storage_hosts and is_aio:
            storage_hosts = self._db_api.ihost_get_by_personality(
                constants.CONTROLLER)

        # If there is no storage node present, ceph usage
        # information is not relevant
        if not storage_hosts:
            return False

        # At least one storage node must be in available state
        for host in storage_hosts:
            if host['availability'] == constants.AVAILABILITY_AVAILABLE:
                break
        else:
            # No storage node is available
            return False
        return True

    # TODO(CephPoolsDecouple): remove
    # This used to be a rpc call to ceph-manager, however after
    # Ceph Pools Decouple task its return value is always 0.
    # Returning 0 here, but a cleanup must be performed to remove
    # this method and the others related to CephPoolsDecouple
    def get_ceph_primary_tier_size(self):
        return 0

    # TODO(CephPoolsDecouple): remove
    # This used to be a rpc call to ceph-manager, however after
    # Ceph Pools Decouple task its return value is always {}.
    # This method is still called by StorageBackendConfig through
    # conductor rpcapi
    def get_ceph_tiers_size(self):
        return {}

    def reset_storage_backend_task(self):
        backend = StorageBackendConfig.get_configured_backend(
            self._db_api,
            constants.CINDER_BACKEND_CEPH
        )
        if not backend:
            return
        self._db_api.storage_backend_update(backend.uuid, {
            'task': constants.SB_TASK_NONE
        })

    def check_storage_upgrade_finished(self, upgrade):
        storage_hosts_upgraded = True

        new_target_load = upgrade.to_load
        storage_hosts = self._db_api.ihost_get_by_personality(
            constants.STORAGE)

        for host in storage_hosts:
            host_upgrade = self._db_api.host_upgrade_get_by_host(
                host.id)
            if (host_upgrade.target_load != new_target_load or
                    host_upgrade.software_load != new_target_load):
                LOG.info("Host %s not yet upgraded" % host.id)
                storage_hosts_upgraded = False
                break

        return storage_hosts_upgraded

    # TODO(CephPoolsDecouple): remove
    # TIER SUPPORT
    def _calculate_target_pg_num_for_tier_pool(self, tiers_obj, pool_name,
                                               storage_hosts):
        """
        Calculate target pg_num based upon storage hosts, OSDs, and tier

        storage_hosts: storage host objects
        tier_obj: storage tier object
        returns target_pg_num  calculated target policy group number
                osds_raw       actual osds

        Primary Tier:
            Minimum: <= 2 storage applies minimum. (512, 512, 256, 256, 128)
                Assume max 8 OSD for first pair to set baseline.

                cinder_volumes:  512 * 2
                ephemeral_vms:   512 * 2
                glance_images:   256 * 2
                .rgw.buckets:    256 * 2
                kube-rbd:        128 * 2
                rbd:             64 (this is created by Ceph)
                --------------------
                Total:          3392

            Note: for a single OSD the value has to be less than 2048, formula:
            [Total] / [total number of OSD] = [PGs/OSD]
            3392    / 2 = 1696 < 2048
            See constants.CEPH_POOLS for up to date values

        Secondary Tiers:
            Minimum: <= 2 storage applies minimum. (512)
                Assume max 4 OSD (i.e. 4 for primary and 4 for secondary) for
                    first pair to set baseline.

                cinder_volumes:  512 * 2
                kube_rbd:        128 * 2
                rbd:             64 (this is created by Ceph)
                --------------------
                Total:          1344

            Note: for a single OSD the value has to be less than 2048, formula:
            [Total] / [total number of OSD] = [PGs/OSD]
            1344    / 2 = 672 < 2048
            See constants.SB_TIER_CEPH_POOLS for up to date values

        Above 2 Storage hosts: Calculate OSDs based upon pg_calc:
            [(Target PGs per OSD) * (# OSD) * (% Data) ]/ Size

        Select Target PGs per OSD = 200; to forecast it can double

        Determine number of OSD (in multiples of storage replication factor) on
        the first host-unlock of storage pair.
        """
        # Get configured ceph replication
        replication, min_replication = \
            StorageBackendConfig.get_ceph_pool_replication(self._db_api, tiers_obj)

        if tiers_obj.uuid == self.primary_tier_uuid:
            is_primary_tier = True
            pools = CEPH_POOLS
        else:
            is_primary_tier = False
            pools = constants.SB_TIER_CEPH_POOLS

        target_pg_num = None

        osds = 0
        stors = None
        last_storage = storage_hosts[0]
        for i in storage_hosts:
            if i.hostname > last_storage.hostname:
                last_storage = i

            # either cinder or ceph
            stors = self._db_api.istor_get_by_ihost(i.uuid)
            osds += len([s for s in stors if s.tier_name == tiers_obj.name])

        osds_raw = osds
        stors = self._db_api.istor_get_by_ihost(last_storage.uuid)
        storage_gap = len(storage_hosts) % replication
        stors_number = len([s for s in stors if s.tier_name == tiers_obj.name])
        if storage_gap != 0 and stors_number != 0:
            osds_adjust = (replication - storage_gap) * stors_number
            osds += osds_adjust
            LOG.debug("OSD - number of storage hosts is not a multiple of replication factor, "
                     "adjusting osds by %d to osds=%d" % (osds_adjust, osds))

        data_pt = None

        for pool in pools:
            if is_primary_tier:
                # Either pool name would be fine here
                if pool_name in constants.CEPH_POOL_OBJECT_GATEWAY_NAME:
                    if pool['pool_name'] in constants.CEPH_POOL_OBJECT_GATEWAY_NAME:
                        data_pt = int(pool['data_pt'])
                        break

            if pool['pool_name'] in pool_name:
                data_pt = int(pool['data_pt'])
                break

        target_pg_num_raw = None
        if data_pt and osds:
            # [(Target PGs per OSD) * (# OSD) * (% Data) ]/ Size
            target_pg_num_raw = ((osds * constants.CEPH_TARGET_PGS_PER_OSD *
                data_pt // 100) // replication)
            # find next highest power of 2 via shift bit length
            target_pg_num = 1 << (int(target_pg_num_raw) - 1).bit_length()

        LOG.info("OSD pool %s target_pg_num_raw=%s target_pg_num=%s "
                 "osds_raw=%s osds=%s" %
                 (pool_name, target_pg_num_raw, target_pg_num, osds_raw, osds))

        return target_pg_num, osds_raw

    # TODO(CephPoolsDecouple): remove
    def audit_osd_pool_on_tier(self, tier_obj, storage_hosts, pool_name):
        """ Audit an osd pool and update pg_num, pgp_num accordingly.
            storage_hosts; list of known storage host objects
            :param storage_hosts: list of storage host objects
            :param pool_name:
        """

        tier_pool_name = pool_name

        # Check if the pool exists
        response, body = self._ceph_api.osd_pool_get(
            tier_pool_name, "pg_num", body='json')
        if not response.ok:
            # Pool does not exist, log error
            LOG.error("OSD pool %(name)s get failed: %(reason)s, "
                      "details %(details)s" %
                      {"name": tier_pool_name, "reason": response.reason,
                       "details": body})
            return
        cur_pg_num = body['output']['pg_num']

        response, body = self._ceph_api.osd_pool_get(
            tier_pool_name, "pgp_num", body='json')
        if not response.ok:
            # Pool does not exist, log error
            LOG.error("OSD pool %(name)s get "
                      "failed: %(reason)s, details: %(details)s" %
                      {"name": tier_pool_name, "reason": response.reason,
                       "details": body})
            return
        cur_pgp_num = body['output']['pgp_num']

        LOG.info("OSD pool name %s, cur_pg_num=%s, cur_pgp_num=%s" %
                 (tier_pool_name, cur_pg_num, cur_pgp_num))
        # First ensure our pg_num and pgp_num match
        if cur_pgp_num < cur_pg_num:
            # The pgp_num needs to match the pg_num. Ceph has no limits on
            # how much the pgp_num can be stepped.
            target_pgp_num = cur_pg_num
            LOG.info("Increasing pgps from %d to %d" % (cur_pgp_num,
                                                        target_pgp_num))
            response, body = self._ceph_api.osd_set_pool_param(
                tier_pool_name, 'pgp_num', target_pgp_num, force=None, body='text')
            if not response.ok:
                # Do not fail the operation - just log it
                LOG.error("OSD pool %(name)s set pgp_num "
                          "failed: %(reason)s, details: %(details)s",
                          {"name": tier_pool_name, "reason": response.reason,
                           "details": body})
                return

        # Only perform pg_num audit if ceph cluster is healthy
        if not self.ceph_status_ok():
            if not os.path.exists(constants.SYSINV_RUNNING_IN_LAB):
                LOG.info("Ceph Status not healthy, skipping OSD pg_num audit")
                return

        target_pg_num, osds = self._calculate_target_pg_num_for_tier_pool(
            tier_obj, tier_pool_name, storage_hosts)

        # Check whether the number of pgs needs to be increased
        if cur_pg_num < target_pg_num:
            # This is tricky, because ceph only allows the number of pgs
            # on an OSD to be increased by 32 in one step. (Check? force)
            max_pg_num = cur_pg_num + (osds * 32)
            if target_pg_num > max_pg_num:
                LOG.warn("Stepping pg_num - current: %d, target: %d, "
                         "step: %d " % (cur_pg_num, target_pg_num,
                                        max_pg_num))
                target_pg_num = max_pg_num

            LOG.info("Increasing pg_num from %d to %d" % (cur_pg_num,
                                                          target_pg_num))
            response, body = self._ceph_api.osd_set_pool_param(
                tier_pool_name, 'pg_num', target_pg_num, body='text')
            # Add: force='--yes-i-really-mean-it' for cached pools
            # once changing PGs is considered stable
            if not response.ok:
                # Do not fail the operation - just log it
                LOG.error("OSD pool %(name)s set pg_num "
                          "failed: %(reason)s, details: %(details)s",
                          {"name": tier_pool_name, "reason": response.reason,
                           "details": body})
                return

                # Ceph needs time to increase the number of pgs before
                # we attempt to increase the pgp number. We will wait for the
                # audit to call us and increase the pgp number at that point.

    # TODO(CephPoolsDecouple): remove
    def audit_osd_quotas_for_tier(self, tier_obj):

        # TODO(rchurch): Make this smarter.Just look at the OSD for the tier to
        # determine if we can continue. For now making sure all are up/in is ok
        try:
            osd_stats = self.get_osd_stats()
            if not ((int(osd_stats['num_osds']) > 0) and
                    (int(osd_stats['num_osds']) ==
                     int(osd_stats['num_up_osds'])) and
                    (int(osd_stats['num_osds']) ==
                     int(osd_stats['num_in_osds']))):
                LOG.info("Not all OSDs are up. "
                         "Not configuring default quotas.")
                return
        except Exception as e:
            LOG.error("Error contacting cluster for getting "
                      "osd information. Exception:  %s", e)
            return

        try:
            primary_tier_gib = int(self.get_ceph_primary_tier_size())
            # In case have only two controllers up, the cluster is considered
            # up, but the total cluster is reported as zero. For such a case we
            # don't yet dynamically update the ceph quotas
            if primary_tier_gib == 0:
                LOG.info("Ceph cluster is up, but no storage nodes detected.")
                return
        except Exception as e:
            LOG.error("Error contacting cluster for getting "
                      "cluster information. Exception:  %s", e)
            return

        if tier_obj.forbackendid is None:
            LOG.error("Tier %s does not have a backend attached. Quotas "
                      "enforcement is skipped until a backend is attached."
                      % tier_obj.name)
            return

        # Get the storage backend
        storage_ceph = self._db_api.storage_ceph_get(tier_obj.forbackendid)

        # TODO(rchurch) optimize this if/then
        if tier_obj.uuid == self.primary_tier_uuid:

            # Get upgrade status
            upgrade = None
            try:
                upgrade = self._db_api.software_upgrade_get_one()
            except exception.NotFound:
                LOG.info("No upgrade in progress. Skipping quota "
                         "upgrade checks.")

            # Grab the current values
            cinder_pool_gib = storage_ceph.cinder_pool_gib or 0
            kube_pool_gib = storage_ceph.kube_pool_gib or 0
            glance_pool_gib = storage_ceph.glance_pool_gib or 0
            ephemeral_pool_gib = storage_ceph.ephemeral_pool_gib or 0
            object_pool_gib = storage_ceph.object_pool_gib or 0

            # Initial cluster provisioning after cluster is up
            # glance_pool_gib = 20 GiB
            # kube_pool_gib = 20 Gib
            # cinder_pool_gib = total_cluster_size - glance_pool_gib
            #                                      - kube_pool_gib
            # ephemeral_pool_gib = 0
            if (upgrade is None and
                    cinder_pool_gib == constants.CEPH_POOL_VOLUMES_QUOTA_GIB and
                    kube_pool_gib == constants.CEPH_POOL_KUBE_QUOTA_GIB and
                    glance_pool_gib == constants.CEPH_POOL_IMAGES_QUOTA_GIB and
                    ephemeral_pool_gib == constants.CEPH_POOL_EPHEMERAL_QUOTA_GIB and
                    object_pool_gib == constants.CEPH_POOL_OBJECT_GATEWAY_QUOTA_GIB):
                # The minimum development setup requires two storage
                # nodes each with one 10GB OSD. This results in a cluster
                # size which is under the default glance pool size of 20GB.
                # Setting the glance pool to a value lower than 20GB
                # is a development safeguard only and should not really
                # happen in real-life scenarios.
                if (primary_tier_gib >
                        constants.CEPH_POOL_IMAGES_QUOTA_GIB +
                        constants.CEPH_POOL_KUBE_QUOTA_GIB):
                    cinder_pool_gib = (primary_tier_gib -
                                       constants.CEPH_POOL_IMAGES_QUOTA_GIB -
                                       constants.CEPH_POOL_KUBE_QUOTA_GIB)

                    self._db_api.storage_ceph_update(storage_ceph.uuid,
                                                     {'cinder_pool_gib':
                                                      cinder_pool_gib})
                else:
                    glance_pool_gib = primary_tier_gib // 2
                    kube_pool_gib = primary_tier_gib - glance_pool_gib

                    # Set the quota for the glance pool.
                    self._db_api.storage_ceph_update(storage_ceph.uuid,
                                                     {'glance_pool_gib':
                                                      glance_pool_gib})

                    # Set the quota for the k8s pool.
                    self._db_api.storage_ceph_update(storage_ceph.uuid,
                                                     {'kube_pool_gib':
                                                      kube_pool_gib})

                self.executed_default_quota_check_by_tier[tier_obj.name] = True
            elif (upgrade is not None and
                  self.check_storage_upgrade_finished(upgrade)):
                LOG.info("Upgrade in progress. Setting quotas based on "
                         "previously found values.")
                if primary_tier_gib > glance_pool_gib:
                    cinder_pool_gib = (primary_tier_gib -
                                       glance_pool_gib -
                                       ephemeral_pool_gib -
                                       object_pool_gib)
                    self._db_api.storage_ceph_update(storage_ceph.uuid,
                                                     {'cinder_pool_gib':
                                                      cinder_pool_gib})
                else:
                    glance_pool_gib = primary_tier_gib
                    self._db_api.storage_ceph_update(storage_ceph.uuid,
                                                     {'glance_pool_gib':
                                                      glance_pool_gib})

                self.executed_default_quota_check_by_tier[tier_obj.name] = True
            elif (primary_tier_gib > 0 and
                  primary_tier_gib == (cinder_pool_gib +
                                       kube_pool_gib +
                                       glance_pool_gib +
                                       ephemeral_pool_gib +
                                       object_pool_gib)):
                # in case sysinv is restarted mark the local
                # variable as true to prevent further checking
                self.executed_default_quota_check_by_tier[tier_obj.name] = True

        else:
            # Grab the current values
            cinder_pool_gib = storage_ceph.cinder_pool_gib or 0
            kube_pool_gib = storage_ceph.kube_pool_gib or 0

            # Secondary tiers: only cinder and kube pool supported.
            tiers_size = self.get_ceph_tiers_size()
            tier_root = "{0}{1}".format(tier_obj.name,
                                        constants.CEPH_CRUSH_TIER_SUFFIX)
            tier_size_gib = tiers_size.get(tier_root, 0)

            if (cinder_pool_gib == constants.CEPH_POOL_VOLUMES_QUOTA_GIB and
                    kube_pool_gib == constants.CEPH_POOL_KUBE_QUOTA_GIB):
                if (tier_size_gib >
                        constants.CEPH_POOL_VOLUMES_QUOTA_GIB +
                        constants.CEPH_POOL_KUBE_QUOTA_GIB):
                    cinder_pool_gib = primary_tier_gib -\
                                      constants.CEPH_POOL_KUBE_QUOTA_GIB
                    kube_pool_gib = constants.CEPH_POOL_KUBE_QUOTA_GIB
                else:
                    kube_pool_gib = tier_size_gib // 2
                    cinder_pool_gib = tier_size_gib - kube_pool_gib

            tier_pools_sum = kube_pool_gib + cinder_pool_gib

            # Set the quota for the cinder-volumes pool.
            self._db_api.storage_ceph_update(
                storage_ceph.uuid, {'cinder_pool_gib': cinder_pool_gib})

            # Set the quota for the k8s pool.
            self._db_api.storage_ceph_update(
                storage_ceph.uuid, {'kube_pool_gib': kube_pool_gib})

            # Adjust pool quotas based on pool relationships.
            if tier_size_gib == tier_pools_sum:
                # Need the sum of the quotas to equal the tier size
                self.executed_default_quota_check_by_tier[tier_obj.name] = True
            elif tier_pools_sum == 0:
                # Special case: For now with one pool allow no quota
                self.executed_default_quota_check_by_tier[tier_obj.name] = True

    # TODO(CephPoolsDecouple): remove
    def audit_osd_pools_by_tier(self):
        """ Check osd pool pg_num vs calculated target pg_num.
            Set pool quotas default values dynamically depending
            on cluster size.
        """

        tiers = self._db_api.storage_tier_get_by_cluster(self.cluster_db_uuid)
        ceph_tiers = [t for t in tiers if t.type == constants.SB_TIER_TYPE_CEPH]
        for t in ceph_tiers:

            # Only provision default quotas once
            if (t.name not in self.executed_default_quota_check_by_tier or
                    not self.executed_default_quota_check_by_tier[t.name]):

                self.executed_default_quota_check_by_tier[t.name] = False
                self.audit_osd_quotas_for_tier(t)

            audit = []
            storage_hosts = self._db_api.ihost_get_by_personality(constants.STORAGE)
            # osd audit is not required for <= 2 hosts
            if storage_hosts and len(storage_hosts) > 2:
                if t.uuid == self.primary_tier_uuid:

                    # Query ceph to get rgw object pool name.
                    # a local copy of CEPH_POOLS here is wasteful.
                    # Nothing changes it anymore.
                    pools_snapshot = copy.deepcopy(CEPH_POOLS)
                    for pool in pools_snapshot:
                        if pool['pool_name'] == constants.CEPH_POOL_OBJECT_GATEWAY_NAME_JEWEL:
                            try:
                                pool_name = self.get_ceph_object_pool_name()
                                if pool_name is None:
                                    LOG.error("Rados gateway object data pool does not exist.")
                                else:
                                    pool['pool_name'] = pool_name
                            except RequestException as e:
                                LOG.warn(_('Failed to retrieve rados gateway object data pool. '
                                           'Reason: %(reason)s') % {'reason':
                                               six.text_type(e)})
                                break

                    audit = [(pools_snapshot, storage_hosts)]

                else:
                    # Adjust the pool name based on the current tier
                    pools_snapshot = copy.deepcopy(constants.SB_TIER_CEPH_POOLS)
                    for p in pools_snapshot:
                        p['pool_name'] += "-%s" % t.name
                    audit = [(pools_snapshot, storage_hosts)]

                if audit is not None:
                    for pools, storage_hosts in audit:
                        for pool in pools:
                            try:
                                self.audit_osd_pool_on_tier(t,
                                                            storage_hosts,
                                                            pool['pool_name'])
                            except RequestException as e:
                                LOG.warn(_('OSD pool %(pool_name)s audit failed. '
                                           'Reason: %(reason)s') % {
                                               'pool_name': pool['pool_name'],
                                               'reason': six.text_type(e)})

    def remove_ceph_monitor(self, hostname, timeout=None):
        try:
            response, body = self._ceph_api.mon_remove(hostname, body='json',
                timeout=timeout)
            if not response.ok:
                LOG.error("Remove monitor error reponse: {} {}"
                    .format(response, body))
        except Exception as e:
            LOG.error("Exception in removing monitor: {}".format(e))
