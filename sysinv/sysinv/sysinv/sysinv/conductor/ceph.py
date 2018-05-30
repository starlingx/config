# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright (c) 2016-2018 Wind River Systems, Inc.
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
import wsme
from requests.exceptions import RequestException, ReadTimeout

from cephclient import wrapper as ceph
from fm_api import constants as fm_constants
from fm_api import fm_api
from sysinv.common import ceph as ceph_utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.openstack.common import log as logging
from sysinv.openstack.common import uuidutils
from sysinv.common.storage_backend_conf import StorageBackendConfig

from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import excutils
from sysinv.openstack.common import rpc
from sysinv.openstack.common.rpc.common import CommonRpcContext
from sysinv.openstack.common.rpc.common import RemoteError as RpcRemoteError

from sysinv.conductor.cache_tiering_service_config import ServiceConfig

LOG = logging.getLogger(__name__)
BACKING_POOLS = copy.deepcopy(constants.BACKING_POOLS)
CACHE_POOLS = copy.deepcopy(constants.CACHE_POOLS)

SERVICE_TYPE_CEPH = constants.SERVICE_TYPE_CEPH
CACHE_TIER = constants.SERVICE_PARAM_SECTION_CEPH_CACHE_TIER
CACHE_TIER_DESIRED = constants.SERVICE_PARAM_SECTION_CEPH_CACHE_TIER_DESIRED
CACHE_TIER_APPLIED = constants.SERVICE_PARAM_SECTION_CEPH_CACHE_TIER_APPLIED
CACHE_TIER_SECTIONS = [CACHE_TIER, CACHE_TIER_DESIRED, CACHE_TIER_APPLIED]
CACHE_TIER_CACHE_ENABLED = constants.SERVICE_PARAM_CEPH_CACHE_TIER_CACHE_ENABLED

CACHE_TIER_RESTORE_TASK_DISABLE = "cache_tier_restore_task_disable"
CACHE_TIER_RESTORE_TASK_ENABLE = "cache_tier_restore_task_enable"


class CacheTiering(object):
    def __init__(self, operator):
        self.operator = operator
        # Cache UUIDs of service_parameters for later use to
        # reduce DB access
        self.config_uuids = {}
        self.desired_config_uuids = {}
        self.applied_config_uuids = {}
        self.restore_task = None

    def get_config(self):
        ret = {}
        if StorageBackendConfig.is_ceph_backend_restore_in_progress(self.operator._db_api):
            LOG.info("Restore in progress. Return stub (disabled) Ceph cache tiering configuration")
            return ret
        for section in CACHE_TIER_SECTIONS:
            config = self.operator.service_parameter_get_all(section=section)
            if config:
                ret[section] = ServiceConfig(config).to_dict()
        LOG.info("Ceph cache tiering configuration: %s" % str(ret))
        return ret

    def is_cache_tiering_enabled(self):
        p = self.operator.service_parameter_get_one(SERVICE_TYPE_CEPH,
                                                    CACHE_TIER,
                                                    CACHE_TIER_CACHE_ENABLED)
        return (p.value.lower() == 'true')

    def apply_service_config(self, new_config, desired_config, applied_config):
        LOG.debug("Applying Ceph service config "
                  "new_config: %(new)s desired_config: %(desired)s "
                  "applied_config: %(applied)s" %
                  {'new': new_config.to_dict(),
                   'desired': desired_config.to_dict(),
                   'applied': applied_config.to_dict()})
        # See description in ceph.update_service_config for design detail

        if new_config.feature_enabled != applied_config.feature_enabled:
            if new_config.feature_enabled:
                self.enable_feature(new_config, applied_config)
            else:
                self.disable_feature(new_config, applied_config)
        elif new_config.cache_enabled != desired_config.cache_enabled:
            if not new_config.feature_enabled:
                raise exception.CephCacheEnableFailure(
                    reason='Cache tiering feature is not enabled')
            else:
                if not self.operator.ceph_status_ok() and \
                        not self.restore_task:
                    raise exception.CephCacheConfigFailure(
                        reason=_('Ceph Status is not healthy.'))

                if new_config.cache_enabled:
                    # Enable cache only if caching tier nodes are available
                    caching_hosts = self.operator.get_caching_hosts()
                    if len(caching_hosts) < 2:
                        raise exception.CephCacheConfigFailure(
                            reason=_('At least two caching hosts must be '
                                     'configured and enabled before '
                                     'enabling cache tiering.'))
                    if len(caching_hosts) % 2:
                        raise exception.CephCacheConfigFailure(
                            reason=_('Caching hosts are configured in pairs, '
                                     'both hosts of each pair must be '
                                     'configured and enabled before '
                                     'enabling cache tiering.'))
                    for h in caching_hosts:
                        if (h.availability != constants.AVAILABILITY_AVAILABLE and
                                h.operational != constants.OPERATIONAL_ENABLED):
                            raise exception.CephCacheConfigFailure(
                                reason=_('All caching hosts must be '
                                         'available before enabling '
                                         'cache tiering.'))
                    self.enable_cache(new_config, desired_config)
                else:
                    self.disable_cache(new_config, desired_config)
        else:
            if new_config.feature_enabled and new_config.cache_enabled:
                # To be safe let configure_osd_pools() be the only place that can
                # update the object pool name in BACKING_POOLS.
                backing_pools_snapshot = copy.deepcopy(BACKING_POOLS)
                for pool in backing_pools_snapshot:
                    # Need to query which Rados object data pool exists
                    if pool['pool_name'] == constants.CEPH_POOL_OBJECT_GATEWAY_NAME_JEWEL:
                        pool_name = self.operator.get_ceph_object_pool_name()
                        if pool_name is None:
                            raise wsme.exc.ClientSideError("Ceph object data pool does not exist.")
                        else:
                            pool['pool_name'] = pool_name

                    self.cache_pool_set_config(pool, new_config, desired_config)
            self.db_param_apply(new_config, desired_config, CACHE_TIER_DESIRED)
            self.db_param_apply(new_config, desired_config, CACHE_TIER_APPLIED)

    def db_param_apply(self, new_config, old_config, section):
        """ Update database section with delta between configs

        We are comparing 'new_config' with old_config and any difference is
        stored in 'section'. If a parameter is missing from new_config then
        it is also removed from 'section' otherwise, any difference will be
        updated or created in section.

        Note that 'section' will not necessarily have the same content as in
        'new_config' only the difference between new_config and old_config is
        updated in 'section'

        """
        # Use cached uuids for current section
        if section == CACHE_TIER:
            uuids = self.config_uuids
        elif section == CACHE_TIER_DESIRED:
            uuids = self.desired_config_uuids
        elif section == CACHE_TIER_APPLIED:
            uuids = self.applied_config_uuids
        else:
            uuids = old_config.uuid

        # Delete service parameters that have been removed
        for name in (set(old_config.params) - set(new_config.params)):
            try:
                self.operator.service_parameter_destroy(name, section)
            except exception.NotFound:
                pass

        # Update feature_enable of old_config with new value
        name = constants.SERVICE_PARAM_CEPH_CACHE_TIER_FEATURE_ENABLED
        _uuid = uuids.get(name)
        value = 'true' if new_config.feature_enabled else 'false'
        self.operator.service_parameter_create_or_update(name, value,
                                                         section, _uuid)

        # Update cache_enable of old_config with new value
        name = constants.SERVICE_PARAM_CEPH_CACHE_TIER_CACHE_ENABLED
        _uuid = uuids.get(name)
        value = 'true' if new_config.cache_enabled else 'false'
        self.operator.service_parameter_create_or_update(name, value,
                                                         section, _uuid)
        # Update all of the other service parameters
        for name, value in new_config.params.iteritems():
            _uuid = uuids.get(name)
            self.operator.service_parameter_create_or_update(name, value,
                                                             section, _uuid)
        if section == CACHE_TIER_APPLIED:
            self.operator.cache_tier_config_out_of_date_alarm_clear()

    def cache_pool_set_config(self, pool, new_config, applied_config):
        for name in (set(applied_config.params) - set(new_config.params)):
            if name in constants.CACHE_TIERING_DEFAULTS:
                LOG.debug("Setting default for parameter: %s" % name)
                self.operator.cache_pool_set_param(pool, name,
                                                   constants.CACHE_TIERING_DEFAULTS[name])
            else:
                LOG.warn(_("Unable to reset cache pool parameter {} to default value").format(name))
        for name, value in new_config.params.iteritems():
            if value != applied_config.params.get(name):
                LOG.debug("Setting value of parameter: %(name)s"
                          " to: %(value)s" % {'name': name,
                                              'value': value})
                self.operator.cache_pool_set_param(pool, name, value)

    def enable_feature(self, new_config, applied_config):
        if new_config.cache_enabled:
            raise exception.CephCacheFeatureEnableFailure(
                reason=_("Cannot enable feature and cache at the same time, "
                         "please enable feature first then cache"))
        else:
            ceph_helper = ceph_utils.CephApiOperator()
            num_monitors, required_monitors, quorum_names = \
                ceph_helper.get_monitors_status(self.operator._db_api)

            if num_monitors < required_monitors:
                raise exception.CephCacheFeatureEnableFailure(
                    reason=_("Only %d storage monitor available. At least %s "
                             "unlocked and enabled hosts with monitors are "
                             "required. Please ensure hosts with monitors are "
                             "unlocked and enabled - candidates: controller-0, "
                             "controller-1, storage-0") % (num_monitors,
                                                           required_monitors))
        # This is only a flag so we set it to both desired and applied at the
        # same time
        self.db_param_apply(new_config, applied_config, CACHE_TIER_DESIRED)
        self.db_param_apply(new_config, applied_config, CACHE_TIER_APPLIED)
        LOG.info(_("Cache tiering feature enabled"))

    def disable_feature(self, new_config, desired_config):
        if desired_config.cache_enabled:
            raise exception.CephCacheFeatureDisableFailure(
                reason=_("Please disable cache before disabling feature."))
        else:
            ceph_caching_hosts = self.operator.get_caching_hosts()
            if len(ceph_caching_hosts):
                raise exception.CephCacheFeatureDisableFailure(
                    reason=_("{} hosts present: {}").format(
                        constants.PERSONALITY_SUBTYPE_CEPH_CACHING,
                        [h['hostname'] for h in ceph_caching_hosts]))
        # This is only a flag so we set it to both desired and applied at the
        # same time
        self.db_param_apply(new_config, desired_config, CACHE_TIER_DESIRED)
        self.db_param_apply(new_config, desired_config, CACHE_TIER_APPLIED)
        LOG.info(_("Cache tiering feature disabled"))

    def enable_cache(self, new_config, desired_config):
        if not new_config.feature_enabled:
            raise exception.CephCacheEnableFailure(
                reason='Cache tiering feature is not enabled')
        if not self.operator.check_all_group_cache_valid():
            raise exception.CephCacheEnableFailure(
                reason=_("Each cache group should have at least"
                         " one storage host available"))
        self.db_param_apply(new_config, desired_config, CACHE_TIER_DESIRED)
        # 'cache_tiering_enable_cache' is called with a 'desired_config'
        # before it was stored in the database! self.db_param_apply only
        # updates the database.
        rpc.call(CommonRpcContext(),
                 constants.CEPH_MANAGER_RPC_TOPIC,
                 {'method': 'cache_tiering_enable_cache',
                  'args': {'new_config': new_config.to_dict(),
                           'applied_config': desired_config.to_dict()}})

    def enable_cache_complete(self, success, _exception, new_config, applied_config):
        new_config = ServiceConfig.from_dict(new_config)
        applied_config = ServiceConfig.from_dict(applied_config)
        if success:
            self.db_param_apply(new_config, applied_config, CACHE_TIER_APPLIED)
            LOG.info(_("Cache tiering: enable cache complete"))
            if self.restore_task == CACHE_TIER_RESTORE_TASK_ENABLE:
                self.operator.reset_storage_backend_task()
                self.restore_task = None
        else:
            # Operation failed, so desired config need to be returned
            # to the initial value before user executed
            #   system service-parameter-apply ceph
            self.db_param_apply(applied_config, new_config, CACHE_TIER_DESIRED)
            LOG.warn(_exception)

    def disable_cache(self, new_config, desired_config):
        self.db_param_apply(new_config, desired_config, CACHE_TIER_DESIRED)
        rpc.call(CommonRpcContext(),
                 constants.CEPH_MANAGER_RPC_TOPIC,
                 {'method': 'cache_tiering_disable_cache',
                  'args': {'new_config': new_config.to_dict(),
                           'applied_config': desired_config.to_dict()}})

    def disable_cache_complete(self, success, _exception,
                               new_config, applied_config):
        new_config = ServiceConfig.from_dict(new_config)
        applied_config = ServiceConfig.from_dict(applied_config)
        if success:
            self.db_param_apply(new_config, applied_config, CACHE_TIER_APPLIED)
            LOG.info(_("Cache tiering: disable cache complete"))
            if self.restore_task == CACHE_TIER_RESTORE_TASK_DISABLE:
                self.restore_task = CACHE_TIER_RESTORE_TASK_ENABLE
                self.operator.restore_cache_tiering()
        else:
            self.db_param_apply(applied_config, new_config, CACHE_TIER_DESIRED)
            LOG.warn(_exception)

    def operation_in_progress(self):
        return rpc.call(CommonRpcContext(),
                        constants.CEPH_MANAGER_RPC_TOPIC,
                        {'method': 'cache_tiering_operation_in_progress',
                         'args': {}})

    def restore_ceph_config_after_storage_enabled(self):
        LOG.info(_("Restore Ceph config after storage enabled"))

        # get cache tiering config.sections
        #
        current_config = ServiceConfig(
            self.operator.service_parameter_get_all(section=CACHE_TIER))
        LOG.info(_("Cache tiering: current configuration %s") % str(current_config))
        applied_config = ServiceConfig(
            self.operator.service_parameter_get_all(section=CACHE_TIER_APPLIED))
        LOG.info(_("Cache tiering: applied configuration %s") % str(applied_config))
        desired_config = ServiceConfig(
            self.operator.service_parameter_get_all(section=CACHE_TIER_DESIRED))
        LOG.info(_("Cache tiering: desired configuration %s") % str(desired_config))

        # desired config is the union of applied and desired config. prior
        # to backup. This should handle the case when backup is executed
        # while cache tiering operation is in progress
        #
        config = current_config.to_dict()
        config.update(applied_config.to_dict())
        config.update(desired_config.to_dict())
        config = ServiceConfig.from_dict(config)
        if (len(self.operator.service_parameter_get_all(
                section=CACHE_TIER_DESIRED,
                name=constants.SERVICE_PARAM_CEPH_CACHE_TIER_FEATURE_ENABLED)) == 0):
            # use applied config in case there's no desired config in
            # the database - otherwise ServiceConfig() uses the default
            # value (False) which may incorrectly override applied config
            #
            config.feature_enabled = applied_config.feature_enabled
        if (len(self.operator.service_parameter_get_all(
                section=CACHE_TIER_DESIRED,
                name=constants.SERVICE_PARAM_CEPH_CACHE_TIER_CACHE_ENABLED)) == 0):
            # use applied config in case there's no desired config in
            # the database - otherwise ServiceConfig() uses the default
            # value (False) which may incorrectly override applied config
            #
            config.cache_enabled = applied_config.cache_enabled
        LOG.info(_("Cache tiering: set database desired config %s") % str(config))
        self.db_param_apply(config, desired_config, CACHE_TIER_DESIRED)
        desired_config = config

        # cache tier applied section stores system state prior to backup;
        # clear it on restore before triggering a ceph-manager apply action
        #
        config = ServiceConfig()
        LOG.info(_("Cache tiering: clear database applied configuration"))
        self.db_param_apply(config, applied_config, CACHE_TIER_APPLIED)
        applied_config = config

        # apply desired configuration in 2 steps: enable feature
        # then enable cache
        #
        if desired_config.feature_enabled:
            cache_enabled = desired_config.cache_enabled
            if cache_enabled:
                LOG.info(_("Cache tiering: disable cache_enabled while enabling feature"))
                desired_config.cache_enabled = False
            LOG.info(_("Cache tiering: enable feature after restore"))
            try:
                self.apply_service_config(desired_config, applied_config, applied_config)
                applied_config.feature_enabled = True
                if cache_enabled:
                    desired_config.cache_enabled = True
                    LOG.info(_("Cache tiering: enable cache after restore"))
                    try:
                        self.apply_service_config(desired_config, applied_config, applied_config)
                    except exception.CephFailure as e:
                        LOG.warn(_("Cache tiering: failed to enable cache after restore. Reason: %s") % str(e))
            except exception.CephFailure as e:
                LOG.warn(_("Cache tiering: failed to enable feature after restore. Reason: %s") % str(e))


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
            endpoint='http://localhost:5001/api/v0.1/')
        self._db_cluster = None
        self._db_primary_tier = None
        self._cluster_name = 'ceph_cluster'
        self._cache_tiering_pools = {
            constants.CEPH_POOL_VOLUMES_NAME + '-cache': constants.CEPH_POOL_VOLUMES_NAME,
            constants.CEPH_POOL_EPHEMERAL_NAME + '-cache': constants.CEPH_POOL_EPHEMERAL_NAME,
            constants.CEPH_POOL_IMAGES_NAME + '-cache': constants.CEPH_POOL_IMAGES_NAME
        }
        self._cache_tiering = CacheTiering(self)
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
            if (body['output']['health']['overall_status'] !=
                    constants.CEPH_HEALTH_OK):
                rc = False
        except Exception as e:
            rc = False
            LOG.warn("ceph status exception: %s " % e)

        return rc

    def _get_fsid(self):
        try:
            response, fsid = self._ceph_api.fsid(body='text', timeout=10)
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
        LOG.debug("_init_db_cluster_and_tier: Reteiving cluster record")
        try:
            self._db_cluster = self._db_api.clusters_get_all(
                type=constants.CINDER_BACKEND_CEPH)[0]
            if not self.cluster_ceph_uuid:
                # Retrieve ceph cluster fsid and update database
                fsid = self._get_fsid()
                if uuidutils.is_uuid_like(fsid):
                    LOG.debug("Update cluster record: fsid=%s." % fsid)
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
        LOG.info("Create new cluster record: fsid=%s." % fsid)
        # Create the default primary cluster
        self._db_cluster = self._db_api.cluster_create(
            {'uuid': fsid if uuidutils.is_uuid_like(fsid) else str(uuid.uuid4()),
             'cluster_uuid': fsid,
             'type': constants.CINDER_BACKEND_CEPH,
             'name': self._cluster_name,
             'system_id': isystem.id})

        # Create the default primary ceph storage tier
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
        group_stats = {
            constants.PERSONALITY_SUBTYPE_CEPH_BACKING: CephOperator.GroupStats(),
            constants.PERSONALITY_SUBTYPE_CEPH_CACHING: CephOperator.GroupStats()}

        peers = self._db_api.peers_get_all_by_cluster(self.cluster_id)
        for peer in peers:
            for host in peer.hosts:
                # Update host mapping
                host_to_peer[host] = peer
            if "cache" in peer.name:
                stats = group_stats[constants.PERSONALITY_SUBTYPE_CEPH_CACHING]
            else:
                stats = group_stats[constants.PERSONALITY_SUBTYPE_CEPH_BACKING]
            stats.peer_count += 1
            if len(peer.hosts) < replication:
                stats.incomplete_peers.append(peer)
        return host_to_peer, group_stats

    def assign_host_to_peer_group(self, host_obj):
        # Prevent re-running the peer assignment logic if the host already has a
        # peer
        if host_obj.peer_id:
            LOG.debug('Host:%s is already assigned to a peer group. Keeping '
                      'current group assignemnt.' % host_obj.hostname)
            return

        hostname = host_obj.hostname
        subtype = host_obj.capabilities['pers_subtype']

        # Get configured ceph replication
        replication, min_replication = StorageBackendConfig.get_ceph_pool_replication(self._db_api)

        # Sanity check #1: storage-0 and storage-1 subtype is ceph-backing
        # TODO: keep this check only for default replication until
        # TODO: cache tiering is deprecated
        if replication == constants.CEPH_REPLICATION_FACTOR_DEFAULT:
            if hostname in [constants.STORAGE_0_HOSTNAME,
                            constants.STORAGE_1_HOSTNAME] and \
                    subtype != constants.PERSONALITY_SUBTYPE_CEPH_BACKING:
                raise exception.StorageSubTypeUnexpected(host=hostname, subtype=subtype)

        host_to_peer, stats = self._get_db_peer_groups(replication)

        # Sanity Check #2: Is this host already assigned?
        peer = host_to_peer.get(hostname)
        if peer:
            raise exception.PeerAlreadyContainsThisHost(
                host=hostname,
                peer_name=peer.name)

        try:
            peer_obj = stats[subtype].incomplete_peers[0]
            peer_name = peer_obj.name
        except IndexError:
            peer_obj = None
            if subtype == constants.PERSONALITY_SUBTYPE_CEPH_CACHING:
                peer_name = '%s%s' % (constants.PEER_PREFIX_CACHING,
                                      str(stats[subtype].peer_count))
            else:
                peer_name = '%s%s' % (constants.PEER_PREFIX_BACKING,
                                      str(stats[subtype].peer_count))

        # TODO: keep these checks only for default repication until
        # TODO: cache tiering is deprecated
        if replication == constants.CEPH_REPLICATION_FACTOR_DEFAULT:
            # Sanity check #3: storage-0 and storage-1 are always in group-0
            if hostname in [constants.STORAGE_0_HOSTNAME,
                            constants.STORAGE_1_HOSTNAME] and \
                    peer_name != constants.PEER_BACKING_RSVD_GROUP:
                raise exception.StoragePeerGroupUnexpected(
                    host=hostname, subtype=subtype, peer_name=peer_name)

            # Sanity check #4: group-0 is reserved for storage-0 and storage-1
            if peer_name == constants.PEER_BACKING_RSVD_GROUP \
                    and hostname not in [constants.STORAGE_0_HOSTNAME,
                                         constants.STORAGE_1_HOSTNAME]:
                raise exception.StoragePeerGroupUnexpected(
                    host=hostname, subtype=subtype, peer_name=peer_name)

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

    def _calculate_target_pg_num(self, storage_hosts, pool_name):
        """
        Calculate target pg_num based upon storage hosts and OSD

        storage_hosts: storage host objects
        returns target_pg_num  calculated target policy group number
                osds_raw       actual osds

        Minimum: <= 2 storage applies minimum. (512, 512, 256, 256)
            Assume max 8 OSD for first pair to set baseline.
            cinder_volumes:  512 * 2
            ephemeral_vms:   512 * 2
            glance_images:   256 * 2
            .rgw.buckets:    256 * 2
            rbd:             64 (this is created by Ceph)
            --------------------
            Total:          3136
        Note: for a single OSD the value has to be less than 2048, formula:
        [Total] / [total number of OSD] = [PGs/OSD]
        3136    / 2 = 1568 < 2048
        See constants.BACKING_POOLS for up to date values

        Above 2 Storage hosts: Calculate OSDs based upon pg_calc:
            [(Target PGs per OSD) * (# OSD) * (% Data) ]/ Size

        Select Target PGs per OSD = 200; to forecast it can double

        Determine number of OSD (in muliples of storage-pairs) on the
        first host-unlock of storage pair.
        """
        target_pg_num = None

        osds = 0
        stors = None
        for i in storage_hosts:
            # either cinder or ceph
            stors = self._db_api.istor_get_by_ihost(i.uuid)
            osds += len(stors)

        osds_raw = osds
        if len(storage_hosts) % 2 != 0:
            osds += len(stors)
            LOG.debug("OSD odd number of storage hosts, adjusting osds by %d "
                      "to osds=%d" % (len(stors), osds))

        data_pt = None

        for pool in (BACKING_POOLS + CACHE_POOLS):
            # Either pool name would be fine here
            if pool_name in constants.CEPH_POOL_OBJECT_GATEWAY_NAME:
                if pool['pool_name'] in constants.CEPH_POOL_OBJECT_GATEWAY_NAME:
                    data_pt = int(pool['data_pt'])
                    break

            if pool['pool_name'] == pool_name:
                data_pt = int(pool['data_pt'])
                break

        target_pg_num_raw = None
        if data_pt and osds:
            # Get configured ceph replication
            replication, min_replication = StorageBackendConfig.get_ceph_pool_replication(self._db_api)

            # [(Target PGs per OSD) * (# OSD) * (% Data) ]/ Size
            target_pg_num_raw = ((osds * constants.CEPH_TARGET_PGS_PER_OSD * data_pt / 100) /
                                 replication)
            # find next highest power of 2 via shift bit length
            target_pg_num = 1 << (int(target_pg_num_raw) - 1).bit_length()

        LOG.info("OSD pool %s target_pg_num_raw=%s target_pg_num=%s "
                 "osds_raw=%s osds=%s" %
                 (pool_name, target_pg_num_raw, target_pg_num, osds_raw, osds))

        return target_pg_num, osds_raw

    def osd_pool_get(self, pool_name, param):
        response, body = self._ceph_api.osd_pool_get(
            pool_name, param, body='json')
        if not response.ok:
            raise exception.CephPoolGetParamFailure(
                pool_name=pool_name,
                param=param,
                reason=response.reason)
        return response, body

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

    def osd_get_pool_quota(self, pool_name):
        """Get the quota for an OSD pool
        :param pool_name:
        """

        resp, quota = self._ceph_api.osd_get_pool_quota(pool_name, body='json')
        if resp.ok:
            return {"max_objects": quota["output"]["quota_max_objects"],
                    "max_bytes": quota["output"]["quota_max_bytes"]}
        else:
            LOG.error("Getting the quota for %(name)s pool failed:%(reason)s)"
                      % {"name": pool_name, "reason": resp.reason})
            raise exception.CephPoolGetFailure(pool=pool_name,
                                               reason=resp.reason)

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

    def reset_cache_tiering(self):
        """Restore Cache Tiering service by toggling the cache_enabled field.
           The first step here is to disable cache_tiering.
        """

        # return if restore is already ongoing
        if self._cache_tiering.restore_task:
            LOG.info("Cache Tiering restore task %s inprogress"
                     % self._cache_tiering.restore_task)
            return

        # No need to restore if Cache Tiering is not enabled
        if not self._cache_tiering.is_cache_tiering_enabled():
            LOG.info("Cache Tiering service is not enabled. No need to restore")
            return True
        else:
            self._cache_tiering.restore_task = CACHE_TIER_RESTORE_TASK_DISABLE

        cache_enabled = self._db_api.service_parameter_get_one(
            service=SERVICE_TYPE_CEPH,
            section=CACHE_TIER,
            name=CACHE_TIER_CACHE_ENABLED)

        self.service_parameter_update(
            cache_enabled.uuid, CACHE_TIER_CACHE_ENABLED, 'false', CACHE_TIER)
        try:
            self.update_service_config(do_apply=True)
        except RpcRemoteError as e:
            raise wsme.exc.ClientSideError(str(e.value))
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(e)
        return True

    def restore_cache_tiering(self):
        """Restore Cache Tiering service by toggling the cache_enabled field.
           The second step here is to re-enable cache_tiering.
        """
        cache_enabled = self._db_api.service_parameter_get_one(
            service=SERVICE_TYPE_CEPH,
            section=CACHE_TIER,
            name=CACHE_TIER_CACHE_ENABLED)

        self.service_parameter_update(
            cache_enabled.uuid, CACHE_TIER_CACHE_ENABLED, 'true', CACHE_TIER)
        try:
            self.update_service_config(do_apply=True)
        except RpcRemoteError as e:
            raise wsme.exc.ClientSideError(str(e.value))
        except Exception as e:
            with excutils.save_and_reraise_exception():
                LOG.exception(e)

    def restore_ceph_config(self, after_storage_enabled=False):
        """Restore Ceph configuration during Backup and Restore process.

        :returns: return True if restore is successful or no need to restore
        """
        # Check to make sure that the ceph manager has seen a valid Ceph REST
        # API response. If not, then we don't have a quorum and attempting to
        # restore the crushmap is a useless act. On a restore we may have
        # powered off yet to be installed storage hosts that have an operational
        # enabled state (i.e. a false positive) which gets us to this restore
        # function.

        if not self.ceph_manager_sees_cluster_up():
            LOG.info('Aborting crushmap restore.The cluster has yet to be '
                     'recognized as operational.')
            return False

        try:
            backup = os.path.join(constants.SYSINV_CONFIG_PATH,
                                  constants.CEPH_CRUSH_MAP_BACKUP)
            if os.path.exists(backup):
                out, err = cutils.trycmd(
                    'ceph', 'osd', 'setcrushmap',
                    '-i', backup,
                    discard_warnings=True)
                if err != '':
                    LOG.warn(_('Failed to restore Ceph crush map. '
                               'Reason: stdout={}, stderr={}').format(out, err))
                    return False
                else:
                    os.unlink(backup)
                    crushmap_flag_file = os.path.join(constants.SYSINV_CONFIG_PATH,
                                                      constants.CEPH_CRUSH_MAP_APPLIED)
                    try:
                        open(crushmap_flag_file, "w").close()
                    except IOError as e:
                        LOG.warn(_('Failed to create flag file: {}. '
                                   'Reason: {}').format(crushmap_flag_file, e))
        except OSError as e:
            LOG.warn(_('Failed to restore Ceph crush map. '
                       'Reason: {}').format(e))
            return False

        if after_storage_enabled:
            StorageBackendConfig.update_backend_states(
                self._db_api,
                constants.CINDER_BACKEND_CEPH,
                task=constants.SB_TASK_NONE
            )
            self._cache_tiering.restore_ceph_config_after_storage_enabled()
            return True

        # check if osdmap is emtpy as an indication for Backup and Restore
        # case where ceph config needs to be restored.
        osd_stats = self.get_osd_stats()
        if int(osd_stats['num_osds']) > 0:
            return True

        LOG.info("osdmap is empty, restoring Ceph config...")
        return self.rebuild_osdmap()

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
                msg = _("Failed to to complete parameter assignment on OSD pool"
                        ": {0}. reason: {1}").format(name, response.reason)
                e = exception.CephFailure(reason=msg)
                LOG.error(e)
                self.delete_osd_pool(pool_name)
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
                msg = _("Failed to to complete parameter assignment on existing"
                        "OSD pool: {0}. reason: {1}").format(name,
                                                             response.reason)
                e = exception.CephFailure(reason=msg)
                LOG.error(e)
                raise e

    def create_or_resize_osd_pool(self, pool_name, pg_num, pgp_num,
                                  size, min_size):
        """Create or resize an osd pool as needed
        :param pool_name:  pool name
        :param pg_num:   number of placement groups
        :param pgp_num:  number of placement groups for placement
        :param size:     number of replicas for objects in the pool
        :param min_size:  minimum number of replicas required for I/O
        """

        # Determine the ruleset to use
        if pool_name.endswith("-cache"):
            # ruleset 1: is the ruleset for the cache tier
            # Name: cache_tier_ruleset
            ruleset = 1
        else:
            # ruleset 0: is the default ruleset if no crushmap is loaded or
            # the ruleset for the backing tier if loaded:
            # Name: storage_tier_ruleset
            ruleset = 0

        # Create the pool if not present
        self._pool_create(pool_name, pg_num, pgp_num, ruleset, size, min_size)

    def cache_pool_create(self, pool):
        backing_pool = pool['pool_name']
        cache_pool = backing_pool + '-cache'

        # Due to http://tracker.ceph.com/issues/8043 we only audit
        # caching pool PGs when the pools are created, for now.
        pg_num, _ = self._calculate_target_pg_num(self.get_caching_hosts(), cache_pool)
        self.create_or_resize_osd_pool(cache_pool, pg_num, pg_num)

    def cache_pool_delete(self, pool):
        cache_pool = pool['pool_name'] + '-cache'
        self.delete_osd_pool(cache_pool)

    def cache_tier_add(self, pool):
        backing_pool = pool['pool_name']
        cache_pool = backing_pool + '-cache'
        response, body = self._ceph_api.osd_tier_add(
            backing_pool, cache_pool,
            force_nonempty="--force-nonempty",
            body='json')
        if response.ok:
            LOG.info(_("Added OSD tier: "
                       "backing_pool={}, cache_pool={}").format(backing_pool, cache_pool))
        else:
            e = exception.CephPoolAddTierFailure(
                backing_pool=backing_pool,
                cache_pool=cache_pool,
                response_status_code=response.status_code,
                response_reason=response.reason,
                status=body.get('status'),
                output=body.get('output'))
            LOG.warn(e)
            raise e

    def cache_tier_remove(self, pool):
        backing_pool = pool['pool_name']
        cache_pool = backing_pool + '-cache'
        response, body = self._ceph_api.osd_tier_remove(
            backing_pool, cache_pool, body='json')
        if response.ok:
            LOG.info(_("Removed OSD tier: "
                       "backing_pool={}, cache_pool={}").format(backing_pool, cache_pool))
        else:
            e = exception.CephPoolRemoveTierFailure(
                backing_pool=backing_pool,
                cache_pool=cache_pool,
                response_status_code=response.status_code,
                response_reason=response.reason,
                status=body.get('status'),
                output=body.get('output'))
            LOG.warn(e)
            raise e

    def cache_mode_set(self, pool, mode):
        backing_pool = pool['pool_name']
        cache_pool = backing_pool + '-cache'
        response, body = self._ceph_api.osd_tier_cachemode(
            cache_pool, mode, body='json')
        if response.ok:
            LOG.info(_("Set OSD tier cache mode: "
                       "cache_pool={}, mode={}").format(cache_pool, mode))
        else:
            e = exception.CephCacheSetModeFailure(
                cache_pool=cache_pool,
                response_status_code=response.status_code,
                response_reason=response.reason,
                status=body.get('status'),
                output=body.get('output'))
            LOG.warn(e)
            raise e

    def cache_pool_set_param(self, pool, name, value):
        backing_pool = pool['pool_name']
        cache_pool = backing_pool + '-cache'
        self.osd_set_pool_param(cache_pool, name, value)

    def service_parameter_get_all(self, section, name=None):
        return self._db_api.service_parameter_get_all(
            service=constants.SERVICE_TYPE_CEPH,
            section=section, name=name)

    def service_parameter_get_one(self, service, section, name):
        return self._db_api.service_parameter_get_one(service,
                                                      section,
                                                      name)

    def service_parameter_create_or_update(self, name, value,
                                           section, uuid=None):
        if uuid:
            self.service_parameter_update(uuid, name, value, section)
        else:
            try:
                self.service_parameter_create(name, value, section)
            except exception.ServiceParameterAlreadyExists:
                service = constants.SERVICE_TYPE_CEPH
                param = self._db_api.service_parameter_get_one(service,
                                                               section,
                                                               name)
                uuid = param.uuid
                self.service_parameter_update(uuid, name, value, section)

    def service_parameter_create(self, name, value, section):
        self._db_api.service_parameter_create({
            'service': constants.SERVICE_TYPE_CEPH,
            'section': section,
            'name': name,
            'value': value})

    def service_parameter_destroy_uuid(self, _uuid):
        self._db_api.service_parameter_destroy_uuid(_uuid)

    def service_parameter_destroy(self, name, section):
        self._db_api.service_parameter_destroy(name,
                                               constants.SERVICE_TYPE_CEPH,
                                               section)

    def service_parameter_update(self, _uuid, name, value, section):
        self._db_api.service_parameter_update(
            _uuid,
            {'service': constants.SERVICE_TYPE_CEPH,
             'section': section,
             'name': name,
             'value': value})

    def get_caching_hosts(self):
        storage_nodes = self._db_api.ihost_get_by_personality(constants.STORAGE)
        ceph_caching_hosts = []
        for node in storage_nodes:
            if node.capabilities.get('pers_subtype') == constants.PERSONALITY_SUBTYPE_CEPH_CACHING:
                ceph_caching_hosts.append(node)
        return ceph_caching_hosts

    def get_backing_hosts(self):
        storage_nodes = self._db_api.ihost_get_by_personality(constants.STORAGE)
        ceph_backing_hosts = []
        for node in storage_nodes:
            if ('pers_subtype' not in node.capabilities or
                    node.capabilities.get('pers_subtype') == constants.PERSONALITY_SUBTYPE_CEPH_BACKING):
                ceph_backing_hosts.append(node)
        return ceph_backing_hosts

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

    def get_osd_pool_quota(self, pool_name):
        """Get the quota for an OSD pool
        :param pool_name:
        """

        resp, quota = self._ceph_api.osd_get_pool_quota(pool_name, body='json')
        if not resp.ok:
            e = exception.CephPoolGetQuotaFailure(
                pool=pool_name, reason=resp.reason)
            LOG.error(e)
            raise e
        else:
            return {"max_objects": quota["output"]["quota_max_objects"],
                    "max_bytes": quota["output"]["quota_max_bytes"]}

    def set_osd_pool_quota(self, pool, max_bytes=0, max_objects=0):
        """Set the quota for an OSD pool
        Setting max_bytes or max_objects to 0 will disable that quota param
        :param pool:         OSD pool
        :param max_bytes:    maximum bytes for OSD pool
        :param max_objects:  maximum objects for OSD pool
        """

        # Update quota if needed
        prev_quota = self.get_osd_pool_quota(pool)
        if prev_quota["max_bytes"] != max_bytes:
            resp, b = self._ceph_api.osd_set_pool_quota(pool, 'max_bytes',
                                                        max_bytes, body='json')
            if resp.ok:
                LOG.info(_("Set OSD pool quota: "
                           "pool={}, max_bytes={}").format(pool, max_bytes))
            else:
                e = exception.CephPoolSetQuotaFailure(
                    pool=pool, name='max_bytes', value=max_bytes, reason=resp.reason)
                LOG.error(e)
                raise e
        if prev_quota["max_objects"] != max_objects:
            resp, b = self._ceph_api.osd_set_pool_quota(pool, 'max_objects',
                                                        max_objects,
                                                        body='json')
            if resp.ok:
                LOG.info(_("Set OSD pool quota: "
                           "pool={}, max_objects={}").format(pool, max_objects))
            else:
                e = exception.CephPoolSetQuotaFailure(
                    pool=pool, name='max_objects', value=max_objects, reason=resp.reason)
                LOG.error(e)
                raise e

    def get_pools_values(self):
        """Create or resize all of the osd pools as needed
        """

        default_quota_map = {'cinder': constants.CEPH_POOL_VOLUMES_QUOTA_GIB,
                             'glance': constants.CEPH_POOL_IMAGES_QUOTA_GIB,
                             'ephemeral': constants.CEPH_POOL_EPHEMERAL_QUOTA_GIB,
                             'object': constants.CEPH_POOL_OBJECT_GATEWAY_QUOTA_GIB}

        storage_ceph = StorageBackendConfig.get_configured_backend_conf(
            self._db_api,
            constants.CINDER_BACKEND_CEPH
        )

        quotas = []
        for p in ['cinder', 'glance', 'ephemeral', 'object']:
            quota_attr = p + '_pool_gib'
            quota_val = getattr(storage_ceph, quota_attr)

            if quota_val is None:
                quota_val = default_quota_map[p]
                self._db_api.storage_ceph_update(storage_ceph.uuid,
                                                 {quota_attr: quota_val})

            quotas.append(quota_val)

        LOG.debug("Pool Quotas: %s" % quotas)
        return tuple(quotas)

    def set_quota_gib(self, pool_name):
        quota_gib_value = None
        cinder_pool_gib, glance_pool_gib, ephemeral_pool_gib, \
            object_pool_gib = self.get_pools_values()

        if pool_name.find(constants.CEPH_POOL_VOLUMES_NAME) != -1:
            quota_gib_value = cinder_pool_gib
        elif pool_name.find(constants.CEPH_POOL_IMAGES_NAME) != -1:
            quota_gib_value = glance_pool_gib
        elif pool_name.find(constants.CEPH_POOL_EPHEMERAL_NAME) != -1:
            quota_gib_value = ephemeral_pool_gib
        elif pool_name.find(constants.CEPH_POOL_OBJECT_GATEWAY_NAME_JEWEL) != -1 or \
                 pool_name.find(constants.CEPH_POOL_OBJECT_GATEWAY_NAME_HAMMER) != -1:
            quota_gib_value = object_pool_gib
        else:
            quota_gib_value = 0

        return quota_gib_value

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

    def _configure_primary_tier_pool(self, pool, size, min_size):
        """Configure the default Ceph tier pools."""

        pool['quota_gib'] = self.set_quota_gib(pool['pool_name'])
        try:
            self.create_or_resize_osd_pool(pool['pool_name'],
                                           pool['pg_num'],
                                           pool['pgp_num'],
                                           size,
                                           min_size)
            self.set_osd_pool_quota(pool['pool_name'],
                                    pool['quota_gib'] * 1024 ** 3)
        except exception.CephFailure:
            pass

    def _configure_secondary_tier_pools(self, tier_obj, size, min_size):
        """Configure the service pools that are allowed for additional ceph tiers.
        """
        # Get the backend object if there is one attached.

        backend = None
        if tier_obj.forbackendid:
            backend = self._db_api.storage_ceph_get(tier_obj.forbackendid)

        # Make sure OSD exist for this tier before creating ceph pools
        LOG.info("calling _configure_secondary_tier_pools to create ceph pools")
        if not tier_obj.stors:
            LOG.info("No need to create ceph pools as no OSD exists in tier %s"
                     % tier_obj.name)
            return

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

                # create the pool
                self._pool_create(pool_name, p['pg_num'], p['pgp_num'],
                                  ruleset, size, min_size)

                # apply the quota to the tier
                if backend:
                    self.set_osd_pool_quota(pool_name,
                                            quota_gib_value * 1024 ** 3)

            else:
                e = exception.CephPoolRulesetFailure(
                    name=rule_name, reason=body['status'])
                raise e

    def configure_osd_pools(self):
        """Create or resize all of the osd pools as needed
           ceph backend could be 2nd backend which is in configuring state
        """

        # Get pool replication parameters
        pool_size, pool_min_size = StorageBackendConfig.get_ceph_pool_replication(self._db_api)

        # Handle pools for multiple tiers
        tiers = self._db_api.storage_tier_get_by_cluster(self.cluster_db_uuid)
        ceph_tiers = filter(lambda t: t.type == constants.SB_TIER_TYPE_CEPH, tiers)
        for t in ceph_tiers:
            if t.uuid == self.primary_tier_uuid:

                # In case we're updating pool_size to a different value than
                # default. Just update pool size for ceph's default pool 'rbd'
                # as well
                try:
                    self._configure_primary_tier_pool(
                        {'pool_name': constants.CEPH_POOL_RBD_NAME,
                         'pg_num': constants.CEPH_POOL_RBD_PG_NUM,
                         'pgp_num': constants.CEPH_POOL_RBD_PGP_NUM},
                        pool_size,
                        pool_min_size)
                except exception.CephFailure:
                    pass

                # Handle primary tier pools (cinder/glance/swift/ephemeral)
                for pool in BACKING_POOLS:
                    # TODO(rchurch): The following is added for R3->R4 upgrades. Can we
                    # remove this for R5? Or is there some R3->R4->R5 need to keep this
                    # around.
                    try:
                        self.update_ceph_object_pool_name(pool)
                    except exception.CephFailure:
                        pass

                    self._configure_primary_tier_pool(pool, pool_size,
                                                      pool_min_size)
            else:
                try:
                    self._configure_secondary_tier_pools(t, pool_size,
                                                         pool_min_size)
                except exception.CephPoolRulesetFailure as e:
                    LOG.info("Cannot add pools: %s" % e)
                except exception.CephFailure as e:
                    LOG.info("Cannot add pools: %s" % e)

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

    def get_osd_stats(self, timeout=30):
        try:
            resp, body = self._ceph_api.osd_stat(body='json',
                                                 timeout=timeout)
        except ReadTimeout as e:
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

    def get_ceph_cluster_info_availability(self):
        # Check if the ceph cluster is ready to return statistics
        storage_hosts = self._db_api.ihost_get_by_personality(
            constants.STORAGE)
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

    def check_all_group_cache_valid(self):
        peers = self._db_api.peers_get_all_by_cluster(self.cluster_id)
        if not len(peers):
            return False
        for peer in peers:
            group_name = peer.name
            if group_name.find("cache") != -1:
                available_cnt = 0
                host_cnt = 0
                for host in self._db_api.ihost_get_by_personality(constants.STORAGE):
                    if peer.id == host['peer_id']:
                        host_cnt += 1
                        host_action_locking = False
                        host_action = host['ihost_action'] or ""
                        if (host_action.startswith(constants.FORCE_LOCK_ACTION) or
                                host_action.startswith(constants.LOCK_ACTION)):
                            host_action_locking = True
                        if (host['administrative'] == constants.ADMIN_UNLOCKED and
                                host['operational'] == constants.OPERATIONAL_ENABLED and
                                not host_action_locking):
                            available_cnt += 1
                if (host_cnt > 0) and (available_cnt == 0):
                    return False
        return True

    def cache_tier_config_out_of_date_alarm_set(self):
        entity_instance_id = "%s=%s" % (
            fm_constants.FM_ENTITY_TYPE_CLUSTER,
            self.cluster_ceph_uuid)
        LOG.warn(_("Raise Ceph cache tier configuration out of date alarm: %s") % entity_instance_id)
        self._fm_api.set_fault(
            fm_api.Fault(
                alarm_id=fm_constants.FM_ALARM_ID_CEPH_CACHE_TIER_CONFIG_OUT_OF_DATE,
                alarm_state=fm_constants.FM_ALARM_STATE_SET,
                entity_type_id=fm_constants.FM_ENTITY_TYPE_CLUSTER,
                entity_instance_id=entity_instance_id,
                severity=fm_constants.FM_ALARM_SEVERITY_MAJOR,
                reason_text=_("Ceph Cache Tier: Configuration is out-of-date."),
                alarm_type=fm_constants.FM_ALARM_TYPE_7,
                probable_cause=fm_constants.ALARM_PROBABLE_CAUSE_75,
                proposed_repair_action=_("Run 'system service-parameter-apply ceph' "
                                         "to apply Ceph service configuration"),
                service_affecting=True))

    def cache_tier_config_out_of_date_alarm_clear(self):
        entity_instance_id = "%s=%s" % (
            fm_constants.FM_ENTITY_TYPE_CLUSTER,
            self.cluster_ceph_uuid)
        LOG.warn(_("Clear Ceph cache tier configuration out of date alarm: %s") % entity_instance_id)
        self._fm_api.clear_fault(
            fm_constants.FM_ALARM_ID_CEPH_CACHE_TIER_CONFIG_OUT_OF_DATE,
            entity_instance_id)

    def cache_tiering_get_config(self):
        return self._cache_tiering.get_config()

    def get_pool_pg_num(self, pool_name):
        pg_num, _ = self._calculate_target_pg_num(self.get_caching_hosts(),
                                                  pool_name)

        # Make sure we return the max between the minimum configured value
        # and computed target pg_num
        for pool in (BACKING_POOLS + CACHE_POOLS):
            # either object pool name is fine here
            if pool_name in constants.CEPH_POOL_OBJECT_GATEWAY_NAME:
                if pool['pool_name'] in constants.CEPH_POOL_OBJECT_GATEWAY_NAME:
                    break
            if pool['pool_name'] == pool_name:
                break

        return max(pg_num, pool['pg_num'])

    def update_service_config(self, do_apply=False):
        if StorageBackendConfig.is_ceph_backend_restore_in_progress(self._db_api):
            raise exception.CephPoolApplyRestoreInProgress()
        if self._cache_tiering.operation_in_progress():
            raise exception.CephPoolApplySetParamFailure()

        # Each service parameter has three states:
        #   1. First, the one that the client sees, stored in section:
        #      SERVICE_PARAM_SECTION_CEPH_CACHE_TIER
        #   2. Second, the one that is stored when the client runs:
        #      'system service-parameter-apply ceph' stored in:
        #      SERVICE_PARAM_SECTION_CEPH_CACHE_TIER_DESIRED
        #   3. Third, the one after the config is correctly applied:
        #      SERVICE_PARAM_SECTION_CEPH_CACHE_TIER_APPLIED
        # When a service (e.g. ceph-manager) is restarted and finds that
        # DESIRED != APPLIED then it takes corrective action.

        # Get service parameters from DB, this should only be needed once
        new_config = ServiceConfig(
            self.service_parameter_get_all(
                section=constants.SERVICE_PARAM_SECTION_CEPH_CACHE_TIER))
        desired_config = ServiceConfig(
            self.service_parameter_get_all(
                section=constants.SERVICE_PARAM_SECTION_CEPH_CACHE_TIER_DESIRED))
        applied_config = ServiceConfig(
            self.service_parameter_get_all(
                section=constants.SERVICE_PARAM_SECTION_CEPH_CACHE_TIER_APPLIED))

        # Cache UUIDs for configs
        if new_config:
            self.config_uuids = new_config.uuid
        if desired_config:
            self.desired_config_uuids = desired_config.uuid
        if applied_config:
            self.applied_config_uuids = applied_config.uuid

        if not do_apply:
            if new_config != applied_config:
                self.cache_tier_config_out_of_date_alarm_set()
            else:
                self.cache_tier_config_out_of_date_alarm_clear()
        else:
            self._cache_tiering.apply_service_config(new_config,
                                                     desired_config,
                                                     applied_config)

    def cache_tiering_enable_cache_complete(self, *args):
        self._cache_tiering.enable_cache_complete(*args)

    def cache_tiering_disable_cache_complete(self, *args):
        self._cache_tiering.disable_cache_complete(*args)

    def get_pools_config(self):
        for pool in BACKING_POOLS:
            # Here it is okay for object pool name is either
            # constants.CEPH_POOL_OBJECT_GATEWAY_NAME_JEWEL or
            # constants.CEPH_POOL_OBJECT_GATEWAY_NAME_HAMMER
            pool['quota_gib'] = self.set_quota_gib(pool['pool_name'])
        return BACKING_POOLS

    def get_ceph_primary_tier_size(self):
        return rpc.call(CommonRpcContext(),
                        constants.CEPH_MANAGER_RPC_TOPIC,
                        {'method': 'get_primary_tier_size',
                         'args': {}})

    def get_ceph_tiers_size(self):
        return rpc.call(CommonRpcContext(),
                        constants.CEPH_MANAGER_RPC_TOPIC,
                        {'method': 'get_tiers_size',
                         'args': {}})

    def ceph_manager_sees_cluster_up(self):
        """Determine if the ceph manager sees an active cluster.

           :returns True if ceph manager audit of ceph api was successful
        """
        return rpc.call(CommonRpcContext(),
                        constants.CEPH_MANAGER_RPC_TOPIC,
                        {'method': 'is_cluster_up',
                         'args': {}})

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
            Minimum: <= 2 storage applies minimum. (512, 512, 256, 256)
                Assume max 8 OSD for first pair to set baseline.

                cinder_volumes:  512 * 2
                ephemeral_vms:   512 * 2
                glance_images:   256 * 2
                .rgw.buckets:    256 * 2
                rbd:             64 (this is created by Ceph)
                --------------------
                Total:          3136

            Note: for a single OSD the value has to be less than 2048, formula:
            [Total] / [total number of OSD] = [PGs/OSD]
            3136    / 2 = 1568 < 2048
            See constants.BACKING_POOLS for up to date values

        Secondary Tiers:
            Minimum: <= 2 storage applies minimum. (512)
                Assume max 4 OSD (i.e. 4 for primary and 4 for secondary) for
                    first pair to set baseline.

                cinder_volumes:  512 * 2
                rbd:             64 (this is created by Ceph)
                --------------------
                Total:          1088

            Note: for a single OSD the value has to be less than 2048, formula:
            [Total] / [total number of OSD] = [PGs/OSD]
            1088    / 2 = 544 < 2048
            See constants.SB_TIER_CEPH_POOLS for up to date values

        Above 2 Storage hosts: Calculate OSDs based upon pg_calc:
            [(Target PGs per OSD) * (# OSD) * (% Data) ]/ Size

        Select Target PGs per OSD = 200; to forecast it can double

        Determine number of OSD (in multiples of storage replication factor) on the
        first host-unlock of storage pair.
        """
        # Get configured ceph replication
        replication, min_replication = StorageBackendConfig.get_ceph_pool_replication(self._db_api)

        if tiers_obj.uuid == self.primary_tier_uuid:
            is_primary_tier = True
            pools = (BACKING_POOLS + CACHE_POOLS)
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
            osds += len(filter(lambda s: s.tier_name == tiers_obj.name, stors))

        osds_raw = osds
        stors = self._db_api.istor_get_by_ihost(last_storage.uuid)
        storage_gap = len(storage_hosts) % replication
        stors_number = len(filter(lambda s: s.tier_name == tiers_obj.name, stors))
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

            if pool['pool_name'] == pool_name:
                data_pt = int(pool['data_pt'])
                break

        target_pg_num_raw = None
        if data_pt and osds:
            # [(Target PGs per OSD) * (# OSD) * (% Data) ]/ Size
            target_pg_num_raw = ((osds * constants.CEPH_TARGET_PGS_PER_OSD * data_pt / 100) /
                                 replication)
            # find next highest power of 2 via shift bit length
            target_pg_num = 1 << (int(target_pg_num_raw) - 1).bit_length()

        LOG.info("OSD pool %s target_pg_num_raw=%s target_pg_num=%s "
                 "osds_raw=%s osds=%s" %
                 (pool_name, target_pg_num_raw, target_pg_num, osds_raw, osds))

        return target_pg_num, osds_raw

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
            # In case have only two controllers up, the cluster is considered up,
            # but the total cluster is reported as zero. For such a case we don't
            # yet dynamically update the ceph quotas
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
            cinder_pool_gib = storage_ceph.cinder_pool_gib
            glance_pool_gib = storage_ceph.glance_pool_gib
            ephemeral_pool_gib = storage_ceph.ephemeral_pool_gib
            object_pool_gib = storage_ceph.object_pool_gib

            # Initial cluster provisioning after cluster is up
            # glance_pool_gib = 20 GiB
            # cinder_pool_gib = total_cluster_size - glance_pool_gib
            # ephemeral_pool_gib = 0
            if (upgrade is None and
                    cinder_pool_gib == constants.CEPH_POOL_VOLUMES_QUOTA_GIB and
                    glance_pool_gib == constants.CEPH_POOL_IMAGES_QUOTA_GIB and
                    ephemeral_pool_gib == constants.CEPH_POOL_EPHEMERAL_QUOTA_GIB and
                    object_pool_gib == constants.CEPH_POOL_OBJECT_GATEWAY_QUOTA_GIB):
                # The minimum development setup requires two storage
                # nodes each with one 10GB OSD. This result in cluster
                # size which is under the default glance pool size of 20GB.
                # Setting the glance pool to a value lower than 20GB
                # is a developement safeguard only and should not really
                # happen in real-life scenarios.
                if primary_tier_gib > constants.CEPH_POOL_IMAGES_QUOTA_GIB:
                    cinder_pool_gib = (primary_tier_gib -
                                       constants.CEPH_POOL_IMAGES_QUOTA_GIB)

                    self._db_api.storage_ceph_update(storage_ceph.uuid,
                                                     {'cinder_pool_gib':
                                                      cinder_pool_gib})
                    self.set_osd_pool_quota(constants.CEPH_POOL_VOLUMES_NAME,
                                            cinder_pool_gib * 1024 ** 3)
                else:
                    glance_pool_gib = primary_tier_gib
                    self._db_api.storage_ceph_update(storage_ceph.uuid,
                                                     {'glance_pool_gib':
                                                      glance_pool_gib})
                    self.set_osd_pool_quota(constants.CEPH_POOL_IMAGES_NAME,
                                            glance_pool_gib * 1024 ** 3)

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
                    self.set_osd_pool_quota(constants.CEPH_POOL_VOLUMES_NAME,
                                            cinder_pool_gib * 1024 ** 3)
                else:
                    glance_pool_gib = primary_tier_gib
                    self._db_api.storage_ceph_update(storage_ceph.uuid,
                                                     {'glance_pool_gib':
                                                      glance_pool_gib})
                    self.set_osd_pool_quota(constants.CEPH_POOL_IMAGES_NAME,
                                            glance_pool_gib * 1024 ** 3)

                self.executed_default_quota_check_by_tier[tier_obj.name] = True
            elif (primary_tier_gib > 0 and
                  primary_tier_gib == (cinder_pool_gib +
                                       glance_pool_gib +
                                       ephemeral_pool_gib +
                                       object_pool_gib)):
                # in case sysinv is restarted mark the local
                # variable as true to prevent further checking
                self.executed_default_quota_check_by_tier[tier_obj.name] = True

        else:
            # Secondary tiers: only cinder pool supported.

            tiers_size = self.get_ceph_tiers_size()
            tier_root = "{0}{1}".format(tier_obj.name,
                                        constants.CEPH_CRUSH_TIER_SUFFIX)
            tier_size_gib = tiers_size.get(tier_root, 0)

            # Take action on individual pools not considering any relationships
            # between pools
            tier_pools_sum = 0
            for pool in constants.SB_TIER_CEPH_POOLS:

                # Grab the current values
                current_gib = storage_ceph.get(pool['be_quota_attr'])
                default_gib = pool['quota_default']

                if not current_gib:
                    self._db_api.storage_ceph_update(storage_ceph.uuid,
                                                     {pool['be_quota_attr']:
                                                      default_gib})
                    self._db_api.storage_ceph_update(storage_ceph.uuid,
                                                     {pool['be_quota_attr']:
                                                      default_gib * 1024 ** 3})
                    current_gib = default_gib
                tier_pools_sum += current_gib

            # Adjust pool quotas based on pool relationships.
            if tier_size_gib == tier_pools_sum:
                # Need the sum of the quotas to equal the tier size
                self.executed_default_quota_check_by_tier[tier_obj.name] = True
            elif tier_pools_sum == 0:
                # Special case: For now with one pool allow no quota
                self.executed_default_quota_check_by_tier[tier_obj.name] = True

    def audit_osd_pools_by_tier(self):
        """ Check osd pool pg_num vs calculated target pg_num.
            Set pool quotas default values dynamically depending
            on cluster size.
        """

        tiers = self._db_api.storage_tier_get_by_cluster(self.cluster_db_uuid)
        ceph_tiers = filter(lambda t: t.type == constants.SB_TIER_TYPE_CEPH, tiers)
        for t in ceph_tiers:

            # Only provision default quotas once
            if (t.name not in self.executed_default_quota_check_by_tier or
                    not self.executed_default_quota_check_by_tier[t.name]):

                self.executed_default_quota_check_by_tier[t.name] = False
                self.audit_osd_quotas_for_tier(t)

            audit = []
            backing_hosts = self.get_backing_hosts()
            # osd audit is not required for <= 2 hosts
            if backing_hosts and len(backing_hosts) > 2:
                if t.uuid == self.primary_tier_uuid:

                    # Query ceph to get rgw object pool name.
                    # To be safe let configure_osd_pools() be the only place that can
                    # update the object pool name in BACKING_POOLS, so we make a local
                    # copy of BACKING_POOLS here.
                    backing_pools_snapshot = copy.deepcopy(BACKING_POOLS)
                    for pool in backing_pools_snapshot:
                        if pool['pool_name'] == constants.CEPH_POOL_OBJECT_GATEWAY_NAME_JEWEL:
                            try:
                                pool_name = self.get_ceph_object_pool_name()
                                if pool_name is None:
                                    LOG.error("Rados gateway object data pool does not exist.")
                                else:
                                    pool['pool_name'] = pool_name
                            except RequestException as e:
                                LOG.warn(_('Failed to retrieve rados gateway object data pool. '
                                           'Reason: %(reason)s') % {'reason': str(e.message)})
                                break

                    audit = [(backing_pools_snapshot, backing_hosts)]

                else:
                    # Adjust the pool name based on the current tier
                    pools_snapshot = copy.deepcopy(constants.SB_TIER_CEPH_POOLS)
                    for p in pools_snapshot:
                        p['pool_name'] += "-%s" % t.name
                    audit = [(pools_snapshot, backing_hosts)]

                # Due to http://tracker.ceph.com/issues/8043 we only audit
                # caching pool PGs when the pools are created, for now.
                # Uncomment bellow to enable automatic configuration
                # Audit backing and caching pools
                # if self._cache_tiering.is_cache_tiering_enabled():
                #     caching_hosts = self.get_caching_hosts()
                #     if caching_hosts and len(caching_hosts) > 2:
                #         audit = audit.extend([(CACHE_POOLS, caching_hosts)])

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
                                               'reason': str(e.message)})
