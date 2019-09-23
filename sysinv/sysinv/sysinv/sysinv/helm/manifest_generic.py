# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" System inventory Armada manifest operator."""

from sysinv.helm import manifest_base as base


class GenericArmadaManifestOperator(base.ArmadaManifestOperator):

    APP = None
    ARMADA_MANIFEST = None

    CHART_GROUPS_LUT = {}
    CHARTS_LUT = {}

    def platform_mode_manifest_updates(self, dbapi, mode):
        """ Update the application manifest based on the platform

        :param dbapi: DB api object
        :param mode: mode to control how to apply the application manifest
        """
        pass
