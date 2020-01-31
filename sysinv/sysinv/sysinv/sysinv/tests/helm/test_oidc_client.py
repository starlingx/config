# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.helm import common

from sysinv.common import constants
from sysinv.common import utils
from sysinv.db import api as dbapi
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils
from sysinv.tests.helm import base
from sysinv.tests.helm import test_helm


class OidcClientTestCase(test_helm.StxPlatformAppMixin,
                         base.HelmTestCaseMixin):

    def setUp(self):
        super(OidcClientTestCase, self).setUp()
        self.app = dbutils.create_test_app(name=self.app_name)
        self.dbapi = dbapi.get_instance()

    def test_addresses(self):
        overrides = self.operator.get_helm_chart_overrides(
            common.HELM_CHART_OIDC_CLIENT,
            cnamespace=common.HELM_NS_KUBE_SYSTEM)
        oam_addr_name = utils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                                  constants.NETWORK_TYPE_OAM)
        address = self.dbapi.address_get_by_name(oam_addr_name)
        oam_url = utils.format_url_address(address.address)
        parameters = {
            'config': {
                'issuer': 'https://%s:30556/dex' % oam_url,
                'redirect_uri': "http://%s:30555/callback" % oam_url,
            }
        }
        self.assertOverridesParameters(overrides, parameters)


class OidcClientIPv4ControllerHostTestCase(OidcClientTestCase,
                                           dbbase.ProvisionedControllerHostTestCase):
    def test_replicas(self):
        overrides = self.operator.get_helm_chart_overrides(
            common.HELM_CHART_DEX,
            cnamespace=common.HELM_NS_KUBE_SYSTEM)

        self.assertOverridesParameters(overrides, {
            # Only one replica for a single controller
            'replicas': 1
        })


class OidcClientIPv6ControllerHostTestCase(OidcClientTestCase,
                                           dbbase.BaseIPv6Mixin,
                                           dbbase.ProvisionedControllerHostTestCase):
    pass


class OidcClientIPv4AIODuplexSystemTestCase(OidcClientTestCase,
                                            dbbase.ProvisionedAIODuplexSystemTestCase):
    def test_replicas(self):
        overrides = self.operator.get_helm_chart_overrides(
            common.HELM_CHART_DEX,
            cnamespace=common.HELM_NS_KUBE_SYSTEM)

        self.assertOverridesParameters(overrides, {
            # Expect two replicas because there are two controllers
            'replicas': 2
        })
