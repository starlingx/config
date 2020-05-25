# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from sysinv.db import api as dbapi
from sysinv.helm import common

from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils
from sysinv.tests.helm import base
from sysinv.tests.helm import test_helm


class CertManagerTestCase(test_helm.StxPlatformAppMixin,
                  base.HelmTestCaseMixin):

    def setUp(self):
        super(CertManagerTestCase, self).setUp()
        self.app = dbutils.create_test_app(name='cert-manager')
        self.dbapi = dbapi.get_instance()


class CertManagerIPv4ControllerHostTestCase(CertManagerTestCase,
                                             dbbase.ProvisionedControllerHostTestCase):

    def test_replicas(self):
        overrides = self.operator.get_helm_chart_overrides(
            common.HELM_CHART_CERT_MANAGER,
            cnamespace=common.HELM_NS_CERT_MANAGER)

        self.assertOverridesParameters(overrides, {
            # 1 replica for 1 controller
            'replicaCount': 1
        })


class CertManagerIPv6AIODuplexSystemTestCase(CertManagerTestCase,
                                              dbbase.BaseIPv6Mixin,
                                              dbbase.ProvisionedAIODuplexSystemTestCase):

    def test_replicas(self):
        overrides = self.operator.get_helm_chart_overrides(
            common.HELM_CHART_CERT_MANAGER,
            cnamespace=common.HELM_NS_CERT_MANAGER)

        self.assertOverridesParameters(overrides, {
            # 2 replicas for 2 controllers
            'replicaCount': 2
        })
