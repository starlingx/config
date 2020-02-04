# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.tests.db import base as dbbase
from sysinv.tests.puppet import base


class PuppetOperatorTestSuiteMixin(base.PuppetTestCaseMixin):
    """When PuppetOperatorTestSuiteMixin is added as a Mixin
       to a testcase which is a subclass of BaseHostTestCase
       these testcases are added to it
    """

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

    # self.host is defined in BaseHostTestCase
    def test_update_host_config(self):
        self.operator.update_host_config(self.host)  # pylint: disable=no-member
        assert self.mock_write_config.called


#  ============= IPv4 environment tests ==============
# Tests all puppet operations for a Controller (defaults to IPv4)
class PlatformIPv4ControllerHostTestCase(PuppetOperatorTestSuiteMixin,
                                         dbbase.ControllerHostTestCase):
    pass


# Tests all puppet operations for a Worker (defaults to IPv4)
class PlatformIPv4WorkerHostTestCase(PuppetOperatorTestSuiteMixin,
                                     dbbase.WorkerHostTestCase):
    pass


# Tests all puppet operations for a Storage Host (defaults to IPv4)
class PlatformIPv4StorageHostTestCase(PuppetOperatorTestSuiteMixin,
                                      dbbase.StorageHostTestCase):
    pass


# Tests all puppet operations for an AIO Host (defaults to IPv4)
class PlatformIPv4AIOHostTestCase(PuppetOperatorTestSuiteMixin,
                                  dbbase.AIOHostTestCase):
    pass


#  ============= IPv6 environment tests ==============
# Tests all puppet operations for a Controller using IPv6
class PlatformIPv6ControllerHostTestCase(PuppetOperatorTestSuiteMixin,
                                         dbbase.BaseIPv6Mixin,
                                         dbbase.ControllerHostTestCase):
    pass


# Tests all puppet operations for a Worker using IPv6
class PlatformIPv6WorkerHostTestCase(PuppetOperatorTestSuiteMixin,
                                     dbbase.BaseIPv6Mixin,
                                     dbbase.WorkerHostTestCase):
    pass


# Tests all puppet operations for a Storage Host using IPv6
class PlatformIPv6StorageHostTestCase(PuppetOperatorTestSuiteMixin,
                                      dbbase.BaseIPv6Mixin,
                                      dbbase.StorageHostTestCase):
    pass


# Tests all puppet operations for an AIO Host using IPv6
class PlatformIPv6AIOHostTestCase(PuppetOperatorTestSuiteMixin,
                                  dbbase.BaseIPv6Mixin,
                                  dbbase.AIOHostTestCase):
    pass


#  ============= Ceph Backend environment tests ==============
# Tests all puppet operations for an AIO Host using IPv4 and Ceph Backend
class PlatformCephBackendAIOHostTestCase(PuppetOperatorTestSuiteMixin,
                                         dbbase.BaseCephStorageBackendMixin,
                                         dbbase.AIOHostTestCase):
    pass
