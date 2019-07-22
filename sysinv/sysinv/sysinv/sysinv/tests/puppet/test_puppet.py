# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants

from sysinv.tests.db import base as dbbase
from sysinv.tests.puppet import base


class PuppetOperatorTestCase(base.PuppetTestCaseMixin,
                             dbbase.BaseHostTestCase):

    def setUp(self):
        super(PuppetOperatorTestCase, self).setUp()
        self._create_test_common()

    def test_create_static_config(self):
        self.operator.create_static_config()
        assert self.mock_write_config.called

    def test_create_secure_config(self):
        self.operator.create_secure_config()
        assert self.mock_write_config.called

    def test_update_system_config(self):
        self.operator.update_system_config()
        assert self.mock_write_config.called

    def test_update_secure_system_config(self):
        self.operator.update_secure_system_config()
        assert self.mock_write_config.called

    def test_update_host_config(self):
        host = self._create_test_host(constants.CONTROLLER)
        self.operator.update_host_config(host)
        assert self.mock_write_config.called


class PlatformIPv4ControllerHostTestCase(base.PuppetTestCaseMixin,
                                         dbbase.ControllerHostTestCase):
    pass


class PlatformIPv4WorkerHostTestCase(base.PuppetTestCaseMixin,
                                     dbbase.WorkerHostTestCase):
    pass


class PlatformIPv4StorageHostTestCase(base.PuppetTestCaseMixin,
                                      dbbase.StorageHostTestCase):
    pass


class PlatformIPv4AIOHostTestCase(base.PuppetTestCaseMixin,
                                  dbbase.AIOHostTestCase):
    pass


class PlatformIPv6ControllerHostTestCase(base.PuppetTestCaseMixin,
                                         dbbase.BaseIPv6Mixin,
                                         dbbase.ControllerHostTestCase):
    pass


class PlatformIPv6WorkerHostTestCase(base.PuppetTestCaseMixin,
                                     dbbase.BaseIPv6Mixin,
                                     dbbase.WorkerHostTestCase):
    pass


class PlatformIPv6StorageHostTestCase(base.PuppetTestCaseMixin,
                                      dbbase.BaseIPv6Mixin,
                                      dbbase.StorageHostTestCase):
    pass


class PlatformIPv6AIOHostTestCase(base.PuppetTestCaseMixin,
                                  dbbase.BaseIPv6Mixin,
                                  dbbase.AIOHostTestCase):
    pass
