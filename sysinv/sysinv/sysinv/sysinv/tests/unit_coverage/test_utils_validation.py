#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Comprehensive tests for sysinv.common.utils uncovered functions."""
import sys
import unittest
from unittest import mock

for _m in ['fm_core', 'rpm']:
    sys.modules.setdefault(_m, mock.MagicMock())

from sysinv.common import utils
from sysinv.common import exception
import io


class TestIPValidation(unittest.TestCase):
    def test_is_valid_ipv6_cidr(self):
        self.assertTrue(utils.is_valid_ipv6_cidr('::1/128'))
        self.assertFalse(utils.is_valid_ipv6_cidr('10.0.0.0/24'))

    def test_is_valid_cidr(self):
        self.assertTrue(utils.is_valid_cidr('10.0.0.0/24'))
        self.assertTrue(utils.is_valid_cidr('::1/128'))
        self.assertFalse(utils.is_valid_cidr('invalid'))

    def test_get_shortened_ipv6(self):
        r = utils.get_shortened_ipv6(
            '0000:0000:0000:0000:0000:0000:0000:0001'
        )
        self.assertEqual(r, '::1')

    def test_get_shortened_ipv6_cidr(self):
        r = utils.get_shortened_ipv6_cidr(
            '0000:0000:0000:0000:0000:0000:0000:0001/128'
        )
        self.assertIn('::1', r)

    def test_format_url_address(self):
        self.assertEqual(utils.format_url_address('10.0.0.1'),
                         '10.0.0.1')
        self.assertEqual(utils.format_url_address('::1'), '[::1]')

    def test_validate_and_normalize_mac(self):
        r = utils.validate_and_normalize_mac('AA:BB:CC:DD:EE:FF')
        self.assertEqual(r, 'aa:bb:cc:dd:ee:ff')

    def test_validate_and_normalize_mac_invalid(self):
        self.assertRaises(exception.InvalidMAC,
                          utils.validate_and_normalize_mac, 'invalid')


class TestPCIValidation(unittest.TestCase):
    def test_is_valid_hex(self):
        self.assertTrue(utils.is_valid_hex('0x1234'))
        self.assertFalse(utils.is_valid_hex('xyz'))

    def test_is_valid_pci_device_vendor_id(self):
        self.assertTrue(utils.is_valid_pci_device_vendor_id('0x1234'))
        self.assertFalse(
            utils.is_valid_pci_device_vendor_id('0x123456')
        )

    def test_is_valid_pci_class_id(self):
        self.assertTrue(utils.is_valid_pci_class_id('0x030000'))
        self.assertFalse(utils.is_valid_pci_class_id('xyz'))


class TestStringUtils(unittest.TestCase):
    def test_sanitize_hostname(self):
        r = utils.sanitize_hostname('My_Host.Name!')
        self.assertNotIn('!', r)

    def test_generate_uid(self):
        r = utils.generate_uid('test')
        self.assertIsNotNone(r)

    def test_random_alnum(self):
        r = utils.random_alnum(16)
        self.assertEqual(len(r), 16)

    def test_convert_to_list_dict(self):
        r = utils.convert_to_list_dict(['a', 'b'], 'item')
        self.assertEqual(len(r), 2)
        self.assertEqual(r[0]['item'], 'a')

    def test_is_int_like(self):
        self.assertTrue(utils.is_int_like('42'))
        self.assertFalse(utils.is_int_like('abc'))

    def test_is_float_like(self):
        self.assertTrue(utils.is_float_like('3.14'))
        self.assertFalse(utils.is_float_like('abc'))

    def test_is_empty_value(self):
        self.assertTrue(utils.is_empty_value(None))
        self.assertTrue(utils.is_empty_value(''))
        self.assertFalse(utils.is_empty_value('hello'))

    def test_truncate_message(self):
        r = utils.truncate_message('x' * 300, max_length=255)
        self.assertEqual(len(r), 255)

    def test_deep_get(self):
        d = {'a': {'b': {'c': 42}}}
        self.assertEqual(utils.deep_get(d, ['a', 'b', 'c']), 42)
        self.assertIsNone(utils.deep_get(d, ['a', 'x']))


class TestFileUtils(unittest.TestCase):

    def test_hash_file(self):
        f = io.BytesIO(b'hello world')
        r = utils.hash_file(f)
        self.assertIsNotNone(r)

    @mock.patch('builtins.open', mock.mock_open(read_data='content'))
    def test_get_file_content(self):
        r = utils.get_file_content('/tmp/test')
        self.assertEqual(r, 'content')

    def test_read_cached_file(self):
        cache = {'data': 'old', 'mtime': 0}
        with mock.patch('os.path.getmtime', return_value=1):
            with mock.patch('builtins.open',
                            mock.mock_open(read_data='new')
                            ):
                data = utils.read_cached_file('/tmp/test', cache)
                self.assertEqual(data, 'new')


class TestCertUtils(unittest.TestCase):

    def test_generate_random_password(self):
        r = utils.generate_random_password(16)
        self.assertEqual(len(r), 16)


class TestMiscFunctions(unittest.TestCase):
    def test_flatten_nested_lists(self):
        r = utils.flatten_nested_lists([[1, 2], [3, 4]])
        self.assertEqual(list(r), [1, 2, 3, 4])

    def test_filter_versions(self):
        versions = ['v1.20.1', 'v1.21.0', 'v1.22.0']
        r = utils.filter_versions(versions, 'v1.20.0', 'v1.22.0')
        self.assertIsInstance(r, list)

    def test_config_is_reboot_required(self):
        r = utils.config_is_reboot_required('config-uuid')
        self.assertIsInstance(r, bool)

    def test_compare_lists_of_dict(self):
        l1 = [{'a': 1}]
        l2 = [{'a': 2}]
        r = utils.compare_lists_of_dict(l1, l2)
        self.assertIsInstance(r, bool)


if __name__ == '__main__':
    unittest.main()
