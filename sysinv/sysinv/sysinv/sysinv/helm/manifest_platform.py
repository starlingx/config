# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" System inventory Armada manifest operator."""

from sysinv.common import constants
from sysinv.helm import manifest_base as base
from sysinv.helm.ceph_pools_audit import CephPoolsAuditHelm
from sysinv.helm.rbd_provisioner import RbdProvisionerHelm


class PlatformArmadaManifestOperator(base.ArmadaManifestOperator):

    APP = constants.HELM_APP_PLATFORM
    ARMADA_MANIFEST = 'platform-integration-manifest'

    CHART_GROUP_CEPH = 'starlingx-ceph-charts'
    CHART_GROUPS_LUT = {
        CephPoolsAuditHelm.CHART: CHART_GROUP_CEPH,
        RbdProvisionerHelm.CHART: CHART_GROUP_CEPH
    }

    CHARTS_LUT = {
        CephPoolsAuditHelm.CHART: 'kube-system-ceph-pools-audit',
        RbdProvisionerHelm.CHART: 'kube-system-rbd-provisioner'
    }

    def platform_mode_manifest_updates(self, dbapi, mode):
        """ Update the application manifest based on the platform

        :param dbapi: DB api object
        :param mode: mode to control how to apply the application manifest
        """
        pass
