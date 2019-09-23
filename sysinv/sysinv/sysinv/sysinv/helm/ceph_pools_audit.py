#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.common import exception

from sysinv.helm import base
from sysinv.helm import common


class CephPoolsAuditHelm(base.BaseHelm):
    """Class to encapsulate helm operations for the ceph-pools-audit chart"""

    CHART = common.HELM_CHART_CEPH_POOLS_AUDIT
    SUPPORTED_NAMESPACES = base.BaseHelm.SUPPORTED_NAMESPACES + \
        [common.HELM_NS_STORAGE_PROVISIONER]
    SUPPORTED_APP_NAMESPACES = {
        constants.HELM_APP_PLATFORM:
            base.BaseHelm.SUPPORTED_NAMESPACES + [common.HELM_NS_STORAGE_PROVISIONER],
    }

    SERVICE_NAME = 'ceph-pools'

    def execute_manifest_updates(self, operator):
        # On application load this chart is enabled. Only disable if specified
        # by the user
        if not self._is_enabled(operator.APP, self.CHART,
                                common.HELM_NS_STORAGE_PROVISIONER):
            operator.chart_group_chart_delete(
                operator.CHART_GROUPS_LUT[self.CHART],
                operator.CHARTS_LUT[self.CHART])

    def get_namespaces(self):
        return self.SUPPORTED_NAMESPACES

    def get_overrides(self, namespace=None):

        backends = self.dbapi.storage_backend_get_list()
        ceph_bks = [bk for bk in backends if bk.backend == constants.SB_TYPE_CEPH]

        if not ceph_bks:
            return {}  # ceph is not configured

        monitors = self._get_formatted_ceph_monitor_ips()

        # Get tier info.
        tiers = self.dbapi.storage_tier_get_list()

        tiers_cfg = []
        for bk in ceph_bks:
            # Get the tier associated to the Ceph backend.
            tier = next((t for t in tiers if t.forbackendid == bk.id), None)
            if not tier:
                raise Exception("No tier present for backend %s" % bk.name)

            # Get the tier rule name.
            rule_name = "{0}{1}{2}".format(
                tier.name,
                constants.CEPH_CRUSH_TIER_SUFFIX,
                "-ruleset").replace('-', '_')

            # Tier config needed for the overrides.
            tier_cfg = {
                "name": bk.name.encode('utf8', 'strict'),
                "replication": int(bk.capabilities.get("replication")),
                "min_replication": int(bk.capabilities.get("min_replication")),
                "crush_rule_name": rule_name.encode('utf8', 'strict'),
            }
            tiers_cfg.append(tier_cfg)

        overrides = {
            common.HELM_NS_STORAGE_PROVISIONER: {
                'conf': {
                    'ceph': {
                        'monitors': monitors,
                        'storage_tiers': tiers_cfg
                    }
                }
            }
        }

        if namespace in self.SUPPORTED_NAMESPACES:
            return overrides[namespace]
        elif namespace:
            raise exception.InvalidHelmNamespace(chart=self.CHART,
                                                 namespace=namespace)
        else:
            return overrides
