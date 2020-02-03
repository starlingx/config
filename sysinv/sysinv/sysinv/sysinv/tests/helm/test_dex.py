# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from sysinv.common import constants
from sysinv.common import utils
from sysinv.db import api as dbapi
from sysinv.helm import common

from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils
from sysinv.tests.helm import base
from sysinv.tests.helm import test_helm


class DexTestCase(test_helm.StxPlatformAppMixin,
                  base.HelmTestCaseMixin):

    def setUp(self):
        super(DexTestCase, self).setUp()
        self.app = dbutils.create_test_app(name='oidc-auth-apps')
        self.dbapi = dbapi.get_instance()

    def test_issuer(self):
        overrides = self.operator.get_helm_chart_overrides(
            common.HELM_CHART_DEX,
            cnamespace=common.HELM_NS_KUBE_SYSTEM)

        oam_addr_name = utils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                                  constants.NETWORK_TYPE_OAM)
        oam_address = self.dbapi.address_get_by_name(oam_addr_name)
        config_issuer = "https://%s:30556/dex" % (utils.format_url_address(oam_address.address))
        self.assertOverridesParameters(overrides, {
            # issuer is set properly
            'config': {'issuer': config_issuer}
        })


class DexIPv4ControllerHostTestCase(DexTestCase,
                                             dbbase.ProvisionedControllerHostTestCase):

    def test_replicas(self):
        overrides = self.operator.get_helm_chart_overrides(
            common.HELM_CHART_DEX,
            cnamespace=common.HELM_NS_KUBE_SYSTEM)

        self.assertOverridesParameters(overrides, {
            # 1 replica for 1 controller
            'replicas': 1
        })


class DexIPv6AIODuplexSystemTestCase(DexTestCase,
                                              dbbase.BaseIPv6Mixin,
                                              dbbase.ProvisionedAIODuplexSystemTestCase):

    def test_replicas(self):
        overrides = self.operator.get_helm_chart_overrides(
            common.HELM_CHART_DEX,
            cnamespace=common.HELM_NS_KUBE_SYSTEM)

        self.assertOverridesParameters(overrides, {
            # 2 replicas for 2 controllers
            'replicas': 2
        })
