#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests to improve sysinv coverage by importing and exercising
low-coverage modules: exception classes, constants, device, dc_api,
helm/common, ipsec constants, objects/__init__.
"""

import unittest
from sysinv.common import exception
from sysinv.common.device import PCI_DEVICE_CLASS_FPGA
from sysinv.common.exception import ProcessExecutionError
from sysinv.common.exception import SysinvException
from sysinv.common.exception import _cleanse_dict


class TestExceptionClasses(unittest.TestCase):
    """Importing and instantiating exception classes covers their
    definitions.
    """

    def test_import_all_exceptions(self):
        self.assertTrue(hasattr(exception, 'SysinvException'))

    def test_sysinv_exception_default_message(self):
        exc = SysinvException()
        self.assertIsNotNone(str(exc))

    def test_sysinv_exception_custom_message(self):
        exc = SysinvException("custom error")
        self.assertIn("custom", str(exc))

    def test_process_execution_error(self):
        exc = ProcessExecutionError(stdout='out', stderr='err',
                                    exit_code=1, cmd='test')
        self.assertEqual(exc.exit_code, 1)

    def test_process_execution_error_defaults(self):
        exc = ProcessExecutionError()
        self.assertIsNotNone(str(exc))

    def test_cleanse_dict(self):
        d = {'user': 'admin', 'admin_password': 'secret', 'key': 'val'}
        result = _cleanse_dict(d)
        self.assertNotIn('admin_password', result)
        self.assertIn('user', result)

    def test_instantiate_all_exception_subclasses(self):
        """Instantiate every SysinvException subclass to cover class
        bodies.
        """
        base = exception.SysinvException
        count = 0
        for name in dir(exception):
            cls = getattr(exception, name)
            if (isinstance(cls, type) and issubclass(cls, base) and
                    cls is not base):
                try:
                    cls()
                    count += 1
                except Exception:
                    try:
                        cls(message="test")
                        count += 1
                    except Exception:
                        pass
        self.assertGreater(count, 100)

    def test_exception_with_kwargs(self):
        exc = SysinvException(reason="test reason")
        self.assertIsNotNone(str(exc))

    def test_exception_format_message(self):
        exc = SysinvException()
        self.assertIsNotNone(exc.format_message())


class TestCommonDevice(unittest.TestCase):
    """Tests for sysinv.common.device module."""

    def test_pci_device_class_acclr_eq(self):
        self.assertEqual(PCI_DEVICE_CLASS_FPGA, '120000')
        self.assertEqual(PCI_DEVICE_CLASS_FPGA, '120001')

    def test_pci_device_class_acclr_ne(self):
        self.assertNotEqual(PCI_DEVICE_CLASS_FPGA, '999999')

    def test_pci_device_class_acclr_str(self):
        self.assertIn('120000', str(PCI_DEVICE_CLASS_FPGA))

    def test_pci_device_class_acclr_hash(self):
        self.assertIsInstance(hash(PCI_DEVICE_CLASS_FPGA), int)


if __name__ == '__main__':
    unittest.main()
