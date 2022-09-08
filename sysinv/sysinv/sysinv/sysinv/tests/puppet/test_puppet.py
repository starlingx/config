# Copyright (c) 2019-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from sysinv.common import constants

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
    def test_centos_update_host_config(self):
        self.mocked_get_os_type = mock.patch(
            'sysinv.common.utils.get_os_type',
            return_value=constants.OS_CENTOS)
        self.mocked_get_os_type.start()

        self.operator.update_host_config(self.host)  # pylint: disable=no-member
        assert self.mock_write_config.called

        self.addCleanup(self.mocked_get_os_type.stop)

    # self.host is defined in BaseHostTestCase
    def test_debian_update_host_config(self):
        self.mocked_get_os_type = mock.patch(
            'sysinv.common.utils.get_os_type',
            return_value=constants.OS_DEBIAN)
        self.mocked_get_os_type.start()

        self.operator.update_host_config(self.host)  # pylint: disable=no-member
        assert self.mock_write_config.called

        self.addCleanup(self.mocked_get_os_type.stop)


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


class PlatformIPv6AIODuplexHostTestCase(PuppetOperatorTestSuiteMixin,
                                        dbbase.BaseIPv6Mixin,
                                        dbbase.AIODuplexHostTestCase):
    pass


#  ============= Ceph Backend environment tests ==============
# Tests all puppet operations for an AIO Host using IPv4 and Ceph Backend
class PlatformCephBackendAIOHostTestCase(PuppetOperatorTestSuiteMixin,
                                         dbbase.BaseCephStorageBackendMixin,
                                         dbbase.AIOHostTestCase):
    pass


# Tests all puppet operations for an AIO-DX Host using IPv4 and Ceph Backend
class PlatformCephBackendAIODuplexHostTestCase(PuppetOperatorTestSuiteMixin,
                                               dbbase.BaseCephStorageBackendMixin,
                                               dbbase.AIODuplexHostTestCase):
    pass


#  ============= Openstack environment tests ==============
class PlatformUpgradeOpenstackAIODuplexHostTestCase(PuppetOperatorTestSuiteMixin,
                                                    dbbase.BaseCephStorageBackendMixin,
                                                    dbbase.PlatformUpgradeTestCase):

    def test_update_system_config(self):
        mock_open = mock.mock_open(read_data=self.fake_hieradata)
        with mock.patch('six.moves.builtins.open', mock_open):
            super(PlatformUpgradeOpenstackAIODuplexHostTestCase, self).test_update_system_config()
            mock_open.assert_has_calls(
                [
                    mock.call("/opt/platform/puppet/0.0/hieradata/system.yaml", "r"),  # ceph
                    mock.call("/opt/platform/puppet/0.0/hieradata/system.yaml", "r"),  # dcdbsync
                    mock.call("/opt/platform/puppet/0.0/hieradata/system.yaml", "r"),  # dcorch
                    mock.call("/opt/platform/puppet/0.0/hieradata/system.yaml", "r"),  # nfv
                ],
                any_order=True
            )

    def test_update_secure_system_config(self):
        mock_open = mock.mock_open(read_data=self.fake_hieradata)
        with mock.patch('six.moves.builtins.open', mock_open):
            super(PlatformUpgradeOpenstackAIODuplexHostTestCase, self).test_update_secure_system_config()
            mock_open.assert_has_calls(
                [
                    mock.call("/opt/platform/puppet/0.0/hieradata/secure_system.yaml", "r"),  # dcdbsync
                    mock.call("/opt/platform/puppet/0.0/hieradata/secure_system.yaml", "r"),  # dcorch
                ],
                any_order=True
            )
