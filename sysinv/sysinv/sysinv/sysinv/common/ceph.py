# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
# Copyright (c) 2016, 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" System Inventory Ceph Utilities and helper functions."""

from __future__ import absolute_import

from sysinv.api.controllers.v1 import utils

from cephclient import wrapper as ceph
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.openstack.common import log as logging
import subprocess
import pecan
import os
import requests

LOG = logging.getLogger(__name__)


class CephApiOperator(object):
    """Class to encapsulate Ceph operations for System Inventory API
       Methods on object-based storage devices (OSDs).
    """

    def __init__(self):
        self._ceph_api = ceph.CephWrapper(
            endpoint='http://localhost:5001/api/v0.1/')
        self._default_tier = constants.SB_TIER_DEFAULT_NAMES[
            constants.SB_TIER_TYPE_CEPH]

    def _format_root_name(self, name):
        """Generate normalized crushmap root name. """

        if name.endswith(constants.CEPH_CRUSH_TIER_SUFFIX):
            return name
        return name + constants.CEPH_CRUSH_TIER_SUFFIX

    def _crush_rule_status(self, tier_name):
        present = False

        LOG.info("ceph osd crush rule ls")
        response, body = self._ceph_api.osd_crush_rule_ls(body='json')
        LOG.info("CRUSH: %d :%s" % (response.status_code, body['status']))

        name = (tier_name + "-ruleset").replace('-', '_')

        if name in body['output']:
            present = True

        return (present, name, len(body['output']))

    def _crush_bucket_add(self, bucket_name, bucket_type):
        LOG.info("ceph osd crush add-bucket %s %s" % (bucket_name,
                                                      bucket_type))
        response, body = self._ceph_api.osd_crush_add_bucket(bucket_name,
                                                             bucket_type,
                                                             body='json')
        LOG.info("CRUSH: %d :%s" % (response.status_code, body['status']))

    def _crush_bucket_remove(self, bucket_name):
        LOG.info("ceph osd crush remove %s" % bucket_name)
        response, body = self._ceph_api.osd_crush_remove(bucket_name,
                                                         body='json')
        LOG.info("CRUSH: %d :%s" % (response.status_code, body['status']))

    def _crush_bucket_move(self, bucket_name, ancestor_type, ancestor_name):
        LOG.info("ceph osd crush move %s %s=%s" % (bucket_name, ancestor_type,
                                                   ancestor_name))
        response, body = self._ceph_api.osd_crush_move(
            bucket_name, "%s=%s" % (ancestor_type, ancestor_name),
            body='json')
        LOG.info("CRUSH: %d :%s" % (response.status_code, body['status']))

    def _crushmap_item_create(self, items, name, ancestor_name=None,
                              ancestor_type=None, depth=0):
        """Create crush map entry. """

        # This is a recursive method. Add a safeguard to prevent infinite
        # recursion.
        if depth > constants.CEPH_CRUSH_MAP_DEPTH:
            raise exception.CephCrushMaxRecursion(depth=depth)

        root_name = self._format_root_name(name)

        for i in items:
            bucket_name = (root_name
                           if i['type'] == 'root'
                           else '%s-%s' % (i['name'], name))
            if i['type'] != 'osd':
                LOG.error("bucket_name = %s, depth = %d" % (bucket_name, depth))
                self._crush_bucket_add(bucket_name, i['type'])

                if 'items' in i:
                    self._crushmap_item_create(i['items'], name,
                                               ancestor_name=bucket_name,
                                               ancestor_type=i['type'],
                                               depth=depth + 1)

            if ancestor_type:
                if i['type'] != 'osd':
                    self._crush_bucket_move(bucket_name, ancestor_type,
                                            ancestor_name)

    def _crushmap_item_delete(self, items, name, ancestor_name=None,
                              ancestor_type=None, depth=0, rollback=False):
        """Delete a crush map entry. """

        # This is a recursive method. Add a safeguard to to prevent infinite
        # recursion.
        if depth > constants.CEPH_CRUSH_MAP_DEPTH:
            return depth

        root_name = self._format_root_name(name)
        ret_code = 0

        for i in items:
            if rollback:
                bucket_name = (root_name
                               if i['type'] == 'root'
                               else '%s-%s' % (i['name'], name))
            else:
                bucket_name = root_name if i['type'] == 'root' else i['name']

            if 'items' in i:
                ret_code = self._crushmap_item_delete(i['items'], name,
                                                      ancestor_name=bucket_name,
                                                      ancestor_type=i['type'],
                                                      depth=depth + 1,
                                                      rollback=rollback)

            LOG.error("bucket_name = %s, depth = %d, ret_code = %s" % (bucket_name, depth, ret_code))
            self._crush_bucket_remove(bucket_name)

        if ret_code != 0 and depth == 0:
            raise exception.CephCrushMaxRecursion(depth=ret_code)

        return (ret_code if ret_code else 0)

    def _crushmap_root_mirror(self, src_name, dest_name):
        """Create a new root hierarchy that matches an existing root hierarchy.
        """

        # Nomenclature for mirrored tiers:
        # root XXX-tier
        #     chassis group-0-XXX
        #         host storage-0-XXX
        #         host storage-1-XXX
        src_root_name = self._format_root_name(src_name)
        dest_root_name = self._format_root_name(dest_name)

        # currently prevent mirroring of anything other than the source tier
        default_root_name = self._format_root_name(self._default_tier)
        if src_root_name != default_root_name:
            reason = "Can only mirror '%s'." % default_root_name
            raise exception.CephCrushInvalidTierUse(tier=src_name,
                                                    reason=reason)

        response, body = self._ceph_api.osd_crush_tree(body='json')
        if response.status_code == requests.codes.ok:
            # Scan for the destination root, should not be present
            dest_root = filter(lambda r: r['name'] == dest_root_name,
                               body['output'])
            if dest_root:
                reason = "Tier '%s' already exists." % dest_root_name
                raise exception.CephCrushInvalidTierUse(tier=dest_root_name,
                                                        reason=reason)

            src_root = filter(lambda r: r['name'] == src_root_name,
                              body['output'])
            if not src_root:
                reason = ("The required source root '%s' does not exist." %
                          src_root_name)
                raise exception.CephCrushInvalidTierUse(tier=src_root_name,
                                                        reason=reason)

            # Mirror the root hierarchy
            LOG.info("Mirroring crush root for new tier: src = %s, dest = %s" %
                     (src_root_name, dest_root_name))
            try:
                self._crushmap_item_create(src_root, dest_name)
            except exception.CephCrushMaxRecursion:
                LOG.error("Unexpected recursion level seen while mirroring "
                          "crushmap hierarchy. Rolling back crushmap changes")
                self._crushmap_item_delete(src_root, dest_name, rollback=True)

    def _crushmap_root_delete(self, name):
        """Remove the crushmap root entry. """

        default_root_name = self._format_root_name(self._default_tier)
        root_name = self._format_root_name(name)
        if root_name == default_root_name:
            reason = "Cannot remove tier '%s'." % default_root_name
            raise exception.CephCrushInvalidTierUse(tier=name, reason=reason)

        response, body = self._ceph_api.osd_crush_tree(body='json')
        if response.status_code == requests.codes.ok:
            # Scan for the destinaion root, should not be present
            root = filter(lambda r: r['name'] == root_name, body['output'])

            if not root:
                reason = "The crushmap root '%s' does not exist." % root_name
                raise exception.CephCrushInvalidTierUse(tier=name,
                                                        reason=reason)

            # Delete the root hierarchy
            try:
                self._crushmap_item_delete(root, name)
            except exception.CephCrushMaxRecursion:
                LOG.debug("Unexpected recursion level seen while deleting "
                          "crushmap hierarchy")

    def _insert_crush_rule(self, file_contents, root_name, rule_name, rule_count,
                           replicate_by='host'):
        """ Insert a new crush rule for a new storage tier.
        Valid replicate_by options are 'host' or 'osd'.
        """

        # generate rule
        rule = [
            "rule %s {\n" % rule_name,
            "    ruleset %d\n" % int(rule_count + 1),
            "    type replicated\n",
            "    min_size 1\n",
            "    max_size 10\n",
            "    step take %s\n" % root_name,
            "    step choose firstn 1 type chassis\n",
            "    step chooseleaf firstn 0 type %s\n" % replicate_by,
            "    step emit\n",
            "}\n"
        ]

        # insert rule: maintain comment at the end of the crushmap
        insertion_index = len(file_contents) - 1
        for l in reversed(rule):
            file_contents.insert(insertion_index, l)

    def _crushmap_rule_add(self, name, replicate_by):
        """Add a tier crushmap rule."""

        crushmap_flag_file = os.path.join(constants.SYSINV_CONFIG_PATH,
                                          constants.CEPH_CRUSH_MAP_APPLIED)
        if not os.path.isfile(crushmap_flag_file):
            reason = "Cannot add any additional rules."
            raise exception.CephCrushMapNotApplied(reason=reason)

        default_root_name = self._format_root_name(self._default_tier)
        root_name = self._format_root_name(name)
        if root_name == default_root_name:
            reason = ("Rule for the default storage tier '%s' already exists." %
                      default_root_name)
            raise exception.CephCrushInvalidTierUse(tier=name, reason=reason)

        # get the current rule count
        rule_is_present, rule_name, rule_count = self._crush_rule_status(root_name)

        if rule_is_present:
            reason = (("Rule '%s' is already present in the crushmap. No action "
                       "taken.") % rule_name)
            raise exception.CephCrushInvalidRuleOperation(rule=rule_name,
                                                          reason=reason)

        # NOTE: The Ceph API only supports simple single step rule creation.
        # Because of this we need to update the crushmap the hard way.

        tmp_crushmap_bin_file = os.path.join(constants.SYSINV_CONFIG_PATH,
                                             "crushmap_rule_update.bin")
        tmp_crushmap_txt_file = os.path.join(constants.SYSINV_CONFIG_PATH,
                                             "crushmap_rule_update.txt")

        # Extract the crushmap
        cmd = ["ceph", "osd", "getcrushmap", "-o", tmp_crushmap_bin_file]
        stdout, __ = cutils.execute(*cmd, run_as_root=False)

        if os.path.exists(tmp_crushmap_bin_file):
            # Decompile the crushmap
            cmd = ["crushtool",
                   "-d", tmp_crushmap_bin_file,
                   "-o", tmp_crushmap_txt_file]
            stdout, __ = cutils.execute(*cmd, run_as_root=False)

            if os.path.exists(tmp_crushmap_txt_file):
                # Add the custom rule
                with open(tmp_crushmap_txt_file, 'r') as fp:
                    contents = fp.readlines()

                self._insert_crush_rule(contents, root_name,
                                        rule_name, rule_count, replicate_by)

                with open(tmp_crushmap_txt_file, 'w') as fp:
                    contents = "".join(contents)
                    fp.write(contents)

                # Compile the crush map
                cmd = ["crushtool",
                       "-c", tmp_crushmap_txt_file,
                       "-o", tmp_crushmap_bin_file]
                stdout, __ = cutils.execute(*cmd, run_as_root=False)

                # Load the new crushmap
                LOG.info("Loading updated crushmap with elements for "
                         "crushmap root: %s" % root_name)
                cmd = ["ceph", "osd", "setcrushmap",
                       "-i", tmp_crushmap_bin_file]
                stdout, __ = cutils.execute(*cmd, run_as_root=False)

        # cleanup
        if os.path.exists(tmp_crushmap_txt_file):
            os.remove(tmp_crushmap_txt_file)
        if os.path.exists(tmp_crushmap_bin_file):
            os.remove(tmp_crushmap_bin_file)

    def _crushmap_rule_delete(self, name):
        """Delete existing tier crushmap rule. """

        crushmap_flag_file = os.path.join(constants.SYSINV_CONFIG_PATH,
                                          constants.CEPH_CRUSH_MAP_APPLIED)
        if not os.path.isfile(crushmap_flag_file):
            reason = "Cannot remove any additional rules."
            raise exception.CephCrushMapNotApplied(reason=reason)

        default_root_name = self._format_root_name(self._default_tier)
        root_name = self._format_root_name(name)
        if root_name == default_root_name:
            reason = (("Cannot remove the rule for tier '%s'.") %
                      default_root_name)
            raise exception.CephCrushInvalidTierUse(tier=name,
                                                    reason=reason)

        # get the current rule count
        rule_is_present, rule_name, rule_count = self._crush_rule_status(root_name)

        if not rule_is_present:
            reason = (("Rule '%s' is not present in the crushmap. No action "
                       "taken.") % rule_name)
            raise exception.CephCrushInvalidRuleOperation(rule=rule_name,
                                                          reason=reason)

        LOG.info("ceph osd crush rule rm %s" % rule_name)
        response, body = self._ceph_api.osd_crush_rule_rm(rule_name,
                                                          body='json')
        LOG.info("CRUSH: %d :%s" % (response.status_code, body['status']))

    def crushmap_tier_delete(self, name):
        """Delete a custom storage tier to the crushmap. """

        try:
            # First: Delete the custom ruleset
            self._crushmap_rule_delete(name)
        except exception.CephCrushInvalidRuleOperation as e:
            if 'not present' not in str(e):
                raise e

        try:
            # Second: Delete the custom tier
            self._crushmap_root_delete(name)
        except exception.CephCrushInvalidTierUse as e:
            if 'does not exist' not in str(e):
                raise e
        except exception.CephCrushMaxRecursion as e:
            raise e

    def crushmap_tiers_add(self):
        """Add all custom storage tiers to the crushmap. """

        cluster = pecan.request.dbapi.clusters_get_all(name='ceph_cluster')

        # get the list of tiers
        tiers = pecan.request.dbapi.storage_tier_get_by_cluster(
            cluster[0].uuid)
        for t in tiers:
            if (t.type == constants.SB_TIER_TYPE_CEPH and
                    t.name != self._default_tier and
                    t.status == constants.SB_TIER_STATUS_DEFINED):

                try:
                    # First: Mirror the default hierarchy
                    self._crushmap_root_mirror(self._default_tier, t.name)

                    # Second: Add ruleset
                    # PG replication can be done per OSD or per host, hence replicate_by
                    # is set to either 'osd' or 'host'.
                    if utils.is_aio_simplex_system(pecan.request.dbapi):
                        # Since we have a single host replication is done on OSDs
                        # to ensure disk based redundancy.
                        self._crushmap_rule_add(t.name, replicate_by='osd')
                    else:
                        # Replication is done on different nodes of the same peer
                        # group ensuring host based redundancy.
                        self._crushmap_rule_add(t.name, replicate_by='host')
                except exception.CephCrushInvalidTierUse as e:
                    if 'already exists' in e:
                        continue
                except exception.CephCrushMaxRecursion as e:
                    raise e

    def _crushmap_tiers_bucket_add(self, bucket_name, bucket_type):
        """Add a new bucket to all the tiers in the crushmap. """

        cluster = pecan.request.dbapi.clusters_get_all(name='ceph_cluster')
        tiers = pecan.request.dbapi.storage_tier_get_by_cluster(
            cluster[0].uuid)
        for t in tiers:
            if t.type == constants.SB_TIER_TYPE_CEPH:
                if t.name == self._default_tier:
                    self._crush_bucket_add(bucket_name, bucket_type)
                else:
                    self._crush_bucket_add("%s-%s" % (bucket_name, t.name),
                                           bucket_type)

    def _crushmap_tiers_bucket_remove(self, bucket_name):
        """Remove an existing bucket from all the tiers in the crushmap. """

        cluster = pecan.request.dbapi.clusters_get_all(name='ceph_cluster')
        tiers = pecan.request.dbapi.storage_tier_get_by_cluster(
            cluster[0].uuid)
        for t in tiers:
            if t.type == constants.SB_TIER_TYPE_CEPH:
                if t.name == self._default_tier:
                    self._crush_bucket_remove(bucket_name)
                else:
                    self._crush_bucket_remove(
                        "%s-%s" % (bucket_name, t.name))

    def _crushmap_tiers_bucket_move(self, bucket_name, ancestor_type,
                                    ancestor_name):
        """Move common bucket in all the tiers in the crushmap. """

        cluster = pecan.request.dbapi.clusters_get_all(name='ceph_cluster')
        tiers = pecan.request.dbapi.storage_tier_get_by_cluster(
            cluster[0].uuid)
        for t in tiers:
            if t.type == constants.SB_TIER_TYPE_CEPH:

                if t.name == self._default_tier:
                    ancestor_name = (self._format_root_name(ancestor_name)
                                     if ancestor_type == 'root'
                                     else ancestor_name)

                    self._crush_bucket_move(bucket_name, ancestor_type,
                                            ancestor_name)
                else:

                    ancestor_name = (self._format_root_name(t.name)
                                     if ancestor_type == 'root'
                                     else "%s-%s" % (ancestor_name, t.name))

                    self._crush_bucket_move(
                        "%s-%s" % (bucket_name, t.name),
                        ancestor_type,
                        ancestor_name)

    def ceph_status_ok(self, timeout=10):
        """
            returns rc bool. True if ceph ok, False otherwise
            :param timeout: ceph api timeout
        """
        rc = True

        try:
            response, body = self._ceph_api.status(body='json',
                                                   timeout=timeout)
            ceph_status = body['output']['health']['overall_status']
            if ceph_status != constants.CEPH_HEALTH_OK:
                LOG.warn("ceph status=%s " % ceph_status)
                rc = False
        except Exception as e:
            rc = False
            LOG.warn("ceph status exception: %s " % e)

        return rc

    def _osd_quorum_names(self, timeout=10):
        quorum_names = []
        try:
            response, body = self._ceph_api.quorum_status(body='json',
                                                          timeout=timeout)
            quorum_names = body['output']['quorum_names']
        except Exception as ex:
            LOG.exception(ex)
            return quorum_names

        return quorum_names

    def remove_osd_key(self, osdid):
        osdid_str = "osd." + str(osdid)
        # Remove the OSD authentication key
        response, body = self._ceph_api.auth_del(
            osdid_str, body='json')
        if not response.ok:
            LOG.error("Auth delete failed for OSD %s: %s",
                      osdid_str, response.reason)

    def osd_host_lookup(self, osd_id):
        response, body = self._ceph_api.osd_crush_tree(body='json')
        for i in range(0, len(body)):
            # there are 2 chassis lists - cache-tier and root-tier
            # that can be seen in the output of 'ceph osd crush tree':
            # [{"id": -2,"name": "cache-tier", "type": "root",
            # "type_id": 10, "items": [...]},
            # {"id": -1,"name": "storage-tier","type": "root",
            # "type_id": 10, "items": [...]}]
            chassis_list = body['output'][i]['items']
            for chassis in chassis_list:
                # extract storage list/per chassis
                storage_list = chassis['items']
                for storage in storage_list:
                    # extract osd list/per storage
                    storage_osd_list = storage['items']
                    for osd in storage_osd_list:
                        if osd['id'] == osd_id:
                            # return storage name where osd is located
                            return storage['name']
        return None

    def check_osds_down_up(self, hostname, upgrade):
        # check if osds from a storage are down/up
        response, body = self._ceph_api.osd_tree(body='json')
        osd_tree = body['output']['nodes']
        size = len(osd_tree)
        for i in range(1, size):
            if osd_tree[i]['type'] != "host":
                continue
            children_list = osd_tree[i]['children']
            children_num = len(children_list)
            # when we do a storage upgrade, storage node must be locked
            # and all the osds of that storage node must be down
            if (osd_tree[i]['name'] == hostname):
                for j in range(1, children_num + 1):
                    if (osd_tree[i + j]['type'] == constants.STOR_FUNCTION_OSD and
                       osd_tree[i + j]['status'] == "up"):
                        # at least one osd is not down
                        return False
                # all osds are up
                return True

    def host_crush_remove(self, hostname):
        # remove host from crushmap when system host-delete is executed
        response, body = self._ceph_api.osd_crush_remove(
            hostname, body='json')

    def set_crushmap(self):
        if fix_crushmap():
            self.crushmap_tiers_add()

    def update_crushmap(self, hostupdate):
        self.set_crushmap()
        storage_num = int(hostupdate.ihost_orig['hostname'][8:])
        if (storage_num >= 2 and
                hostupdate.ihost_orig['invprovision'] !=
                constants.PROVISIONED):

            # update crushmap.bin accordingly with the host and it's peer group
            node_bucket = hostupdate.ihost_orig['hostname']
            ipeer = pecan.request.dbapi.peer_get(
                hostupdate.ihost_orig['peer_id'])

            self._crushmap_tiers_bucket_add(node_bucket, "host")
            self._crushmap_tiers_bucket_add(ipeer.name, "chassis")
            self._crushmap_tiers_bucket_move(ipeer.name, "root", self._default_tier)
            self._crushmap_tiers_bucket_move(node_bucket, "chassis", ipeer.name)

    def host_osd_status(self, hostname):
        # should prevent locking of a host if HEALTH_BLOCK
        host_health = None
        try:
            response, body = self._ceph_api.pg_dump_stuck(body='json')
            pg_detail = len(body['output'])
        except Exception as e:
            LOG.exception(e)
            return host_health

        # osd_list is a list where I add
        # each osd from pg_detail whose hostname
        # is not equal with hostnamge given as parameter
        osd_list = []
        for x in range(pg_detail):
            # extract the osd and return the storage node
            osd = body['output'][x]['acting']
            # osd is a list with osd where a stuck/degraded PG
            # was replicated. If osd is empty, it means
            # PG is not replicated to any osd
            if not osd:
                continue
            osd_id = int(osd[0])
            if osd_id in osd_list:
                continue
            # potential future optimization to cache all the
            # osd to host lookups for the single call to host_osd_status().
            host_name = self.osd_host_lookup(osd_id)
            if (host_name is not None and
               host_name == hostname):
                # mark the selected storage node with HEALTH_BLOCK
                # we can't lock any storage node marked with HEALTH_BLOCK
                return constants.CEPH_HEALTH_BLOCK
            osd_list.append(osd_id)
        return constants.CEPH_HEALTH_OK

    def get_monitors_status(self, db_api):
        # first check that the monitors are available in sysinv
        num_active_monitors = 0
        num_inv_monitors = 0
        required_monitors = constants.MIN_STOR_MONITORS
        quorum_names = []
        inventory_monitor_names = []
        ihosts = db_api.ihost_get_list()
        for ihost in ihosts:
            if ihost['personality'] == constants.COMPUTE:
                continue
            capabilities = ihost['capabilities']
            if 'stor_function' in capabilities:
                host_action = ihost['ihost_action'] or ""
                locking = (host_action.startswith(constants.LOCK_ACTION) or
                           host_action.startswith(constants.FORCE_LOCK_ACTION))
                if (capabilities['stor_function'] == constants.STOR_FUNCTION_MONITOR and
                   ihost['administrative'] == constants.ADMIN_UNLOCKED and
                   ihost['operational'] == constants.OPERATIONAL_ENABLED and
                   not locking):
                    num_inv_monitors += 1
                    inventory_monitor_names.append(ihost['hostname'])

        LOG.info("Active ceph monitors in inventory = %s" % str(inventory_monitor_names))

        # check that the cluster is actually operational.
        # if we can get the monitor quorum from ceph, then
        # the cluster is truly operational
        if num_inv_monitors >= required_monitors:
            try:
                quorum_names = self._osd_quorum_names()
            except Exception:
                # if the cluster is not responding to requests
                # we set the quorum_names to an empty list , indicating a problem
                quorum_names = []
                LOG.error("Ceph cluster not responding to requests.")

        LOG.info("Active ceph monitors in ceph cluster = %s" % str(quorum_names))

        # There may be cases where a host is in an unlocked-available state,
        # but the monitor is down due to crashes or manual removal.
        # For such cases, we determine the list of active ceph monitors to be
        # the intersection of the sysinv reported unlocked-available monitor
        # hosts and the monitors reported in the quorum via the ceph API.
        active_monitors = list(set(inventory_monitor_names) & set(quorum_names))
        LOG.info("Active ceph monitors = %s" % str(active_monitors))

        num_active_monitors = len(active_monitors)

        return num_active_monitors, required_monitors, active_monitors

    def list_osd_pools(self):
        """List all osd pools."""
        resp, pools = self._ceph_api.osd_pool_ls(body='json')
        if not resp.ok:
            e = exception.CephPoolListFailure(
                reason=resp.reason)
            LOG.error(e)
            raise e
        else:
            return pools['output']


def fix_crushmap(dbapi=None):
    # Crush Map: Replication of PGs across storage node pairs
    if not dbapi:
        dbapi = pecan.request.dbapi
    crushmap_flag_file = os.path.join(constants.SYSINV_CONFIG_PATH,
                                      constants.CEPH_CRUSH_MAP_APPLIED)
    if not os.path.isfile(crushmap_flag_file):
        if utils.is_aio_simplex_system(dbapi):
            crushmap_file = "/etc/sysinv/crushmap-aio-sx.bin"
        else:
            crushmap_file = "/etc/sysinv/crushmap.bin"
        LOG.info("Updating crushmap with: %s" % crushmap_file)
        try:
            subprocess.check_output("ceph osd setcrushmap -i %s" % crushmap_file,
                                    stderr=subprocess.STDOUT, shell=True)
        except subprocess.CalledProcessError as e:
            # May not be critical, depends on where this is called.
            reason = "Error: %s Output: %s" % (str(e), e.output)
            raise exception.CephCrushMapNotApplied(reason=reason)
        try:
            open(crushmap_flag_file, "w").close()
        except IOError as e:
            LOG.warn(_('Failed to create flag file: {}. '
                       'Reason: {}').format(crushmap_flag_file, e))

        return True
