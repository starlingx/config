#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the generic utils.
"""

import mock
import fcntl
import errno

from sysinv.common import utils
from sysinv.tests import base


class TestCommonUtils(base.TestCase):
    def setUp(self):
        super(TestCommonUtils, self).setUp()

        self.lockfd = "fd"
        self.io_excp = IOError("test io error exception")
        self.io_excp.errno = errno.EAGAIN

    def test_parse_range_set(self):
        # Empty string
        self.assertEqual(utils.parse_range_set(""), [])
        # Single item
        self.assertEqual(utils.parse_range_set("11"), [11])
        # Multi non-consecutive items
        self.assertEqual(set(utils.parse_range_set("1,3,5")), set([1, 3, 5]))
        # Multi consecutive items
        self.assertEqual(set(utils.parse_range_set("1,2,3")), set([1, 2, 3]))
        # Out of order
        self.assertEqual(set(utils.parse_range_set("1,3,2")), set([1, 2, 3]))
        # Single range
        self.assertEqual(set(utils.parse_range_set("7-10")),
                         set([7, 8, 9, 10]))
        # Mix of single items and range
        self.assertEqual(set(utils.parse_range_set("1,3-7,11,2")),
                         set([1, 2, 3, 4, 5, 6, 7, 11]))
        # Duplicates
        self.assertEqual(set(utils.parse_range_set("1,2,3,2,1")),
                         set([1, 2, 3]))
        # Single items overlapping with range
        self.assertEqual(set(utils.parse_range_set("1-3,2,1")),
                         set([1, 2, 3]))

    @mock.patch("fcntl.flock")
    def test_exclusive_lock(self, flock_mock):
        utils.acquire_exclusive_nb_flock(self.lockfd)

        flock_mock.assert_called_with(self.lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    @mock.patch("fcntl.flock")
    def test_shared_lock(self, flock_mock):
        utils.acquire_shared_nb_flock(self.lockfd)

        flock_mock.assert_called_with(self.lockfd, fcntl.LOCK_SH | fcntl.LOCK_NB)

    @mock.patch("fcntl.flock")
    def test_exclusive_lock_with_retries(self, flock_mock):
        flock_mock.side_effect = [self.io_excp, self.io_excp, self.lockfd]

        utils.acquire_exclusive_nb_flock(self.lockfd, wait_interval=1)

        self.assertEqual(flock_mock.call_count, 3)

    @mock.patch("fcntl.flock")
    def test_shared_lock_with_retries(self, flock_mock):
        flock_mock.side_effect = [self.io_excp, self.io_excp, self.io_excp, self.lockfd]

        utils.acquire_shared_nb_flock(self.lockfd, wait_interval=1)

        self.assertEqual(flock_mock.call_count, 4)

    @mock.patch("fcntl.flock")
    def test_acquire_lock_returns_max_retries(self, flock_mock):
        flock_mock.side_effect = [self.io_excp, self.io_excp, self.io_excp, self.lockfd]

        result = utils.acquire_shared_nb_flock(self.lockfd, max_retry=3, wait_interval=1)

        self.assertEqual(flock_mock.call_count, 3)
        self.assertEqual(result, 0)

    @mock.patch("fcntl.flock")
    def test_release_lock(self, flock_mock):
        utils.release_flock(self.lockfd)

        flock_mock.assert_called_with(self.lockfd, fcntl.LOCK_UN)

    @mock.patch("fcntl.flock")
    def test_raise_if_unexpected_exception(self, flock_mock):
        self.io_excp.errno = errno.EBADF
        flock_mock.side_effect = self.io_excp

        self.assertRaises(IOError, utils.acquire_shared_nb_flock, self.lockfd)

    def test_skip_udev_acquires_shared_lock(self):
        mock_decorated_func = mock.MagicMock()
        utils.acquire_shared_nb_flock = mock.MagicMock()
        utils.release_flock = mock.MagicMock()

        f = utils.skip_udev_partition_probe(mock_decorated_func)

        mock_open = mock.mock_open()
        with mock.patch('six.moves.builtins.open', mock_open):
            f(device_node=self.lockfd)

        utils.acquire_shared_nb_flock.assert_called_once()
        mock_decorated_func.assert_called_once()
        utils.release_flock.assert_called_once()

    def test_skip_udev_skip_function_if_lock_fails(self):
        mock_decorated_func = mock.MagicMock()
        utils.acquire_shared_nb_flock = mock.MagicMock(return_value=0)
        utils.release_flock = mock.MagicMock()

        f = utils.skip_udev_partition_probe(mock_decorated_func)

        mock_open = mock.mock_open()
        with mock.patch('six.moves.builtins.open', mock_open):
            f(device_node=self.lockfd)

        utils.acquire_shared_nb_flock.assert_called_once()
        self.assertEqual(mock_decorated_func.call_count, 0)
        self.assertEqual(utils.release_flock.call_count, 0)

    @mock.patch('sysinv.common.utils.get_vswitch_type')
    def test_has_vswitch_enabled_vswitch_type_none_label_enabled(self, mock_get_vswitch_type):
        mock_get_vswitch_type.return_value = None
        mock_host_label = mock.Mock()
        mock_host_label.label_key = 'openvswitch'
        mock_host_label.label_value = 'enabled'
        self.assertFalse(utils.has_vswitch_enabled([mock_host_label], mock.Mock()))
        mock_get_vswitch_type.assert_called_once()

    @mock.patch('sysinv.common.utils.get_vswitch_type')
    def test_has_vswitch_enabled_vswitch_type_none_label_disabled(self, mock_get_vswitch_type):
        mock_get_vswitch_type.return_value = None
        mock_host_label = mock.Mock()
        mock_host_label.label_key = 'openvswitch'
        mock_host_label.label_value = 'disabled'
        self.assertFalse(utils.has_vswitch_enabled([mock_host_label], mock.Mock()))
        mock_get_vswitch_type.assert_called_once()

    @mock.patch('sysinv.common.utils.get_vswitch_type')
    def test_has_vswitch_enabled_vswitch_type_none_label_empty(self, mock_get_vswitch_type):
        mock_get_vswitch_type.return_value = None
        mock_host_label = mock.Mock()
        mock_host_label.label_key = ''
        mock_host_label.label_value = ''
        self.assertFalse(utils.has_vswitch_enabled([mock_host_label], mock.Mock()))
        mock_get_vswitch_type.assert_called_once()

    @mock.patch('sysinv.common.utils.get_vswitch_type')
    def test_has_vswitch_enabled_vswitch_type_none_label_none(self, mock_get_vswitch_type):
        mock_get_vswitch_type.return_value = None
        mock_host_label = mock.Mock()
        mock_host_label.label_key = None
        mock_host_label.label_value = None
        self.assertFalse(utils.has_vswitch_enabled([mock_host_label], mock.Mock()))
        mock_get_vswitch_type.assert_called_once()

    @mock.patch('sysinv.common.utils.get_vswitch_type')
    def test_has_vswitch_enabled_vswitch_type_ovs_dpdk_label_enabled(self, mock_get_vswitch_type):
        mock_get_vswitch_type.return_value = 'ovs-dpdk'
        mock_host_label = mock.Mock()
        mock_host_label.label_key = 'openvswitch'
        mock_host_label.label_value = 'enabled'
        self.assertTrue(utils.has_vswitch_enabled([mock_host_label], mock.Mock()))
        mock_get_vswitch_type.assert_called_once()

    @mock.patch('sysinv.common.utils.get_vswitch_type')
    def test_has_vswitch_enabled_vswitch_type_ovs_dpdk_label_disabled(self, mock_get_vswitch_type):
        mock_get_vswitch_type.return_value = 'ovs-dpdk'
        mock_host_label = mock.Mock()
        mock_host_label.label_key = 'openvswitch'
        mock_host_label.label_value = 'disabled'
        self.assertFalse(utils.has_vswitch_enabled([mock_host_label], mock.Mock()))
        mock_get_vswitch_type.assert_called_once()

    @mock.patch('sysinv.common.utils.get_vswitch_type')
    def test_has_vswitch_enabled_vswitch_type_ovs_dpdk_label_random(self, mock_get_vswitch_type):
        mock_get_vswitch_type.return_value = 'ovs-dpdk'
        mock_host_label = mock.Mock()
        mock_host_label.label_key = '123123'
        mock_host_label.label_value = '123123'
        self.assertFalse(utils.has_vswitch_enabled([mock_host_label], mock.Mock()))
        mock_get_vswitch_type.assert_called_once()

    @mock.patch('sysinv.common.utils.get_vswitch_type')
    def test_has_vswitch_enabled_vswitch_type_random_label_enabled(self, mock_get_vswitch_type):
        mock_get_vswitch_type.return_value = '123123'
        mock_host_label = mock.Mock()
        mock_host_label.label_key = 'openvswitch'
        mock_host_label.label_value = 'enabled'
        self.assertFalse(utils.has_vswitch_enabled([mock_host_label], mock.Mock()))
        mock_get_vswitch_type.assert_called_once()

    @mock.patch('sysinv.common.utils.get_vswitch_type')
    def test_has_vswitch_enabled_vswitch_type_random_label_disabled(self, mock_get_vswitch_type):
        mock_get_vswitch_type.return_value = '123123'
        mock_host_label = mock.Mock()
        mock_host_label.label_key = 'openvswitch'
        mock_host_label.label_value = 'disabled'
        self.assertFalse(utils.has_vswitch_enabled([mock_host_label], mock.Mock()))
        mock_get_vswitch_type.assert_called_once()

    @mock.patch('sysinv.common.utils.get_vswitch_type')
    def test_has_vswitch_enabled_vswitch_type_random_label_random(self, mock_get_vswitch_type):
        mock_get_vswitch_type.return_value = '123123'
        mock_host_label = mock.Mock()
        mock_host_label.label_key = '123123'
        mock_host_label.label_value = '123123'
        self.assertFalse(utils.has_vswitch_enabled([mock_host_label], mock.Mock()))
        mock_get_vswitch_type.assert_called_once()

    @mock.patch('sysinv.common.utils.get_vswitch_type')
    def test_has_vswitch_enabled_vswitch_type_downstream_label_enabled(self, mock_get_vswitch_type):
        mock_get_vswitch_type.return_value = 'downstream_vswitch'
        mock_host_label = mock.Mock()
        mock_host_label.label_key = 'downstream_vswitch'
        mock_host_label.label_value = 'enabled'
        self.assertTrue(utils.has_vswitch_enabled([mock_host_label], mock.Mock()))
        mock_get_vswitch_type.assert_called_once()

    @mock.patch('sysinv.common.utils.get_vswitch_type')
    def test_has_vswitch_enabled_vswitch_type_downstream_label_disabled(self, mock_get_vswitch_type):
        mock_get_vswitch_type.return_value = 'downstream_vswitch'
        mock_host_label = mock.Mock()
        mock_host_label.label_key = 'downstream_vswitch'
        mock_host_label.label_value = 'disabled'
        self.assertFalse(utils.has_vswitch_enabled([mock_host_label], mock.Mock()))
        mock_get_vswitch_type.assert_called_once()

    @mock.patch('sysinv.common.utils.get_vswitch_type')
    def test_has_vswitch_enabled_vswitch_type_downstream_label_none(self, mock_get_vswitch_type):
        mock_get_vswitch_type.return_value = 'downstream_vswitch'
        mock_host_label = mock.Mock()
        mock_host_label.label_key = 'downstream_vswitch'
        mock_host_label.label_value = None
        self.assertFalse(utils.has_vswitch_enabled([mock_host_label], mock.Mock()))
        mock_get_vswitch_type.assert_called_once()
