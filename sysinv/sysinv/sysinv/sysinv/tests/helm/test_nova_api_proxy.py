# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.helm import common

from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils
from sysinv.tests.helm import base
from sysinv.tests.helm import test_helm


class NovaApiProxyTestCase(test_helm.StxOpenstackAppMixin,
                           base.HelmTestCaseMixin):

    def setUp(self):
        super(NovaApiProxyTestCase, self).setUp()
        self.app = dbutils.create_test_app(name=self.app_name)


class NovaApiProxyIPv4ControllerHostTestCase(NovaApiProxyTestCase,
                                             dbbase.ControllerHostTestCase):

    def test_replicas(self):
        overrides = self.operator.get_helm_chart_overrides(
            common.HELM_CHART_NOVA_API_PROXY,
            cnamespace=common.HELM_NS_OPENSTACK)

        self.assertOverridesParameters(overrides, {
            # Only one replica for a single controller
            'pod': {'replicas': {'proxy': 1}}
        })


class NovaApiProxyIPv4AIODuplexSystemTestCase(NovaApiProxyTestCase,
                                              dbbase.AIODuplexSystemTestCase):

    def test_replicas(self):
        overrides = self.operator.get_helm_chart_overrides(
            common.HELM_CHART_NOVA_API_PROXY,
            cnamespace=common.HELM_NS_OPENSTACK)

        self.assertOverridesParameters(overrides, {
            # Expect two replicas because there are two controllers
            'pod': {'replicas': {'proxy': 2}}
        })
