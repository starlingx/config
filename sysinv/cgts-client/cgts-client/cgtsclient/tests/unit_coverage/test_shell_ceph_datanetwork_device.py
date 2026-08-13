#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Batch 11: ceph_mon, datanetwork, device_image, address_pool_shell,
device_image_shell, device_label_shell,
drbdconfig_shell, app_shell, cluster_shell."""
import unittest
from unittest import mock

from cgtsclient import exc
from cgtsclient.tests.unit_coverage._helpers import _make_resource
from cgtsclient.tests.unit_coverage._helpers import _make_shell_args
from cgtsclient.tests.unit_coverage._helpers import _patch_print
from cgtsclient.v1 import ceph_mon
from cgtsclient.v1 import datanetwork
from cgtsclient.v1 import device_image


# --- ceph_mon.py ceph_mon_add ---
class TestCephMonAdd(unittest.TestCase):

    def test_ceph_mon_add_not_confirmed(self):
        args = _make_shell_args(confirmed=None, ceph_mon_gib=None)
        r = ceph_mon.ceph_mon_add(None, args, 'h1')
        self.assertIsNone(r)


# --- datanetwork.py _find_datanetwork ---
class TestDatanetworkFind(unittest.TestCase):
    def test_find_by_id(self):
        cc = mock.MagicMock()
        cc.datanetwork.list.return_value = (
            [_make_resource(id=1, name='dn1', uuid='u1')]
        )
        r = datanetwork._find_datanetwork(cc, '1')
        self.assertEqual(r.name, 'dn1')

    def test_find_by_uuid(self):
        cc = mock.MagicMock()
        cc.datanetwork.get.return_value = (
            _make_resource(uuid='a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11')
        )
        r = datanetwork._find_datanetwork(
            cc,
            'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'
        )
        self.assertIsNotNone(r)

    def test_find_by_name(self):
        cc = mock.MagicMock()
        cc.datanetwork.list.return_value = (
            [_make_resource(id=1, name='dn1')]
        )
        r = datanetwork._find_datanetwork(cc, 'dn1')
        self.assertEqual(r.name, 'dn1')

    def test_find_not_found_id(self):
        cc = mock.MagicMock()
        cc.datanetwork.list.return_value = []
        self.assertRaises(exc.CommandError,
                          datanetwork._find_datanetwork,
                          cc,
                          '99')

    def test_find_not_found_name(self):
        cc = mock.MagicMock()
        cc.datanetwork.list.return_value = []
        self.assertRaises(exc.CommandError,
                          datanetwork._find_datanetwork,
                          cc,
                          'missing')

    def test_find_not_found_uuid(self):
        cc = mock.MagicMock()
        cc.datanetwork.get.side_effect = exc.HTTPNotFound()
        self.assertRaises(exc.CommandError, datanetwork._find_datanetwork, cc,
                          'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11')


# --- device_image.py ---
class TestDeviceImageManager(unittest.TestCase):

    def test_upload_invalid_attr(self):
        api = mock.MagicMock()
        mgr = device_image.DeviceImageManager(api)
        self.assertRaises(exc.InvalidAttribute,
                          mgr.upload,
                          '/tmp/img',
                          bad='x')


class TestDeviceImageFind(unittest.TestCase):
    def test_find_by_id(self):
        cc = mock.MagicMock()
        cc.device_image.list.return_value = (
            [_make_resource(id=1, name='img1', uuid='u1')]
        )
        r = device_image._find_device_image(cc, '1')
        self.assertEqual(r.name, 'img1')

    def test_find_by_uuid(self):
        cc = mock.MagicMock()
        cc.device_image.get.return_value = (
            _make_resource(uuid='a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11')
        )
        r = device_image._find_device_image(
            cc,
            'a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11'
        )
        self.assertIsNotNone(r)

    def test_find_by_name(self):
        cc = mock.MagicMock()
        cc.device_image.list.return_value = (
            [_make_resource(id=1, name='img1')]
        )
        r = device_image._find_device_image(cc, 'img1')
        self.assertEqual(r.name, 'img1')

    def test_find_not_found(self):
        cc = mock.MagicMock()
        cc.device_image.list.return_value = []
        self.assertRaises(exc.CommandError,
                          device_image._find_device_image,
                          cc,
                          'missing')


# --- device_image_shell.py ---
@_patch_print
class TestDeviceImageShellDeep(unittest.TestCase):
    pass


# --- app_shell.py ---


# --- drbdconfig_shell.py ---


if __name__ == '__main__':
    unittest.main()
