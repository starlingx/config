#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" System inventory Generic FluxCD Kustomize operator."""

from sysinv.helm import kustomize_base as base


class GenericFluxCDKustomizeOperator(base.FluxCDKustomizeOperator):

    APP = None

    def platform_mode_kustomize_updates(self, dbapi, mode):
        """ Update the application kustomization manifests based on the platform

        :param dbapi: DB api object
        :param mode: mode to control how to apply the application manifest
        """
        pass
