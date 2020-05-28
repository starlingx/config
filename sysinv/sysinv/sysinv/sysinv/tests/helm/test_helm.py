# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import keyring
import mock

from sysinv.helm.helm import HelmOperator
from sysinv.helm.manifest_base import ArmadaManifestOperator

from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils
from sysinv.tests.helm import base as helm_base


class StxPlatformAppMixin(object):
    path_name = 'stx-platform.tgz'
    app_name = 'oidc-auth-apps'

    def setUp(self):
        super(StxPlatformAppMixin, self).setUp()


class HelmOperatorTestSuiteMixin(helm_base.HelmTestCaseMixin):
    """When HelmOperatorTestSuiteMixin is added as a Mixin
       alongside a subclass of BaseHostTestCase
       these testcases are added to it
       This also requires an AppMixin to provide app_name
    """
    def setUp(self):
        super(HelmOperatorTestSuiteMixin, self).setUp()
        self.app = dbutils.create_test_app(name=self.app_name)
        # If a ceph keyring entry is missing, a subprocess will be invoked
        # so a fake keyring password is being supplied here.
        keyring.set_password('glance', 'admin_keyring', 'FakePassword1*')

        # Armada routines that write to disk can be mocked away
        save_overrides = mock.patch.object(ArmadaManifestOperator,
                                           'save_overrides')
        self.mock_save_overrides = save_overrides.start()
        self.addCleanup(save_overrides.stop)

        save_delete_manifest = mock.patch.object(ArmadaManifestOperator,
                                                 'save_delete_manifest')
        save_delete_manifest.start()
        self.addCleanup(save_delete_manifest.stop)

        save_summary = mock.patch.object(ArmadaManifestOperator,
                                         'save_summary')
        save_summary.start()
        self.addCleanup(save_summary.stop)

        # _write_file is called per helm chart
        write_file = mock.patch.object(ArmadaManifestOperator,
                                       '_write_file')
        write_file.start()
        self.addCleanup(write_file.stop)

    def tearDown(self):
        super(HelmOperatorTestSuiteMixin, self).tearDown()

    @mock.patch.object(HelmOperator, '_write_chart_overrides')
    def test_generate_helm_chart_overrides(self, mock_write_chart):
        self.operator.generate_helm_application_overrides(self.path_name,
                                                          self.app_name)
        assert self.mock_save_overrides.called


# ============ Tests ======

# Test Configuration:
# - Controller
# - IPv6
# - Ceph Storage
# - stx-platform app
class HelmSTXPlatformControllerTestCase(StxPlatformAppMixin,
                                         dbbase.BaseIPv6Mixin,
                                         dbbase.BaseCephStorageBackendMixin,
                                         HelmOperatorTestSuiteMixin,
                                         dbbase.ControllerHostTestCase):
    pass
