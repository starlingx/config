#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for scripts/ipsec-swap-certificates.py."""

import importlib.util
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.modules.setdefault('cryptography', mock.MagicMock())
sys.modules.setdefault('cryptography.x509', mock.MagicMock())
sys.modules.setdefault('cryptography.hazmat', mock.MagicMock())
sys.modules.setdefault('cryptography.hazmat.backends', mock.MagicMock())
sys.modules.setdefault(
    'cryptography.hazmat.primitives',
    mock.MagicMock()
)
sys.modules.setdefault(
    'cryptography.hazmat.primitives.serialization',
    mock.MagicMock()
)

_script = os.path.join(os.path.dirname(__file__), '..', 'scripts',
                       'ipsec-swap-certificates.py')
_spec = importlib.util.spec_from_file_location('ipsec_swap',
                                               os.path.abspath(_script))
ipsec_swap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ipsec_swap)


class TestRemoveCaCertificates(unittest.TestCase):
    """Tests for remove_ca_certificates."""

    def test_removes_matching_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            open(
                os.path.join(tmpdir, 'system-local-ca-0.crt'),
                'w').close(
            )
            open(
                os.path.join(tmpdir, 'system-local-ca-0_l1.crt'),
                'w').close(
            )
            open(os.path.join(tmpdir, 'other.crt'), 'w').close()
            with mock.patch.object(
                    ipsec_swap,
                    'IPSEC_CA_CERT_DIR',
                    tmpdir + '/'
            ):
                result = ipsec_swap.remove_ca_certificates(
                    'system-local-ca-0'
                )
            self.assertTrue(result)
            self.assertFalse(
                os.path.exists(
                    os.path.join(
                        tmpdir,
                        'system-local-ca-0.crt')))
            self.assertTrue(
                os.path.exists(os.path.join(tmpdir, 'other.crt'))
            )

    def test_returns_true_no_matches(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.object(
                    ipsec_swap,
                    'IPSEC_CA_CERT_DIR',
                    tmpdir + '/'
            ):
                self.assertTrue(
                    ipsec_swap.remove_ca_certificates('nonexistent')
                )

    def test_returns_false_on_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            open(
                os.path.join(tmpdir, 'system-local-ca-0.crt'),
                'w').close(
            )
            with mock.patch.object(
                    ipsec_swap,
                    'IPSEC_CA_CERT_DIR',
                    tmpdir + '/'
            ):
                with mock.patch('os.remove',
                                side_effect=Exception("perm")
                                ):
                    self.assertFalse(
                        ipsec_swap
                        .remove_ca_certificates(
                            'system-local-ca-0'))


class TestRenameCaCertificates(unittest.TestCase):
    """Tests for rename_ca_certificates."""

    def test_renames_matching_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            open(
                os.path.join(tmpdir, 'system-local-ca-1.crt'),
                'w').close(
            )
            with mock.patch.object(
                    ipsec_swap,
                    'IPSEC_CA_CERT_DIR',
                    tmpdir + '/'
            ):
                self.assertTrue(ipsec_swap.rename_ca_certificates(
                    'system-local-ca-1', 'system-local-ca-0'))
            self.assertTrue(
                os.path.exists(
                    os.path.join(
                        tmpdir,
                        'system-local-ca-0.crt')))

    def test_returns_false_on_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            open(
                os.path.join(tmpdir, 'system-local-ca-1.crt'),
                'w').close(
            )
            with mock.patch.object(
                    ipsec_swap,
                    'IPSEC_CA_CERT_DIR',
                    tmpdir + '/'
            ):
                with mock.patch('os.rename',
                                side_effect=Exception("fail")
                                ):
                    self.assertFalse(ipsec_swap.rename_ca_certificates(
                        'system-local-ca-1', 'system-local-ca-0'))


class TestGetCaCertificatePath(unittest.TestCase):
    """Tests for get_ca_certificate_path."""

    def test_index_zero(self):
        result = ipsec_swap.get_ca_certificate_path('prefix', 0)
        self.assertTrue(result.endswith('prefix.crt'))

    def test_index_nonzero(self):
        result = ipsec_swap.get_ca_certificate_path('prefix', 2)
        self.assertIn('_l2', result)


class TestExtractCertsFromPem(unittest.TestCase):
    """Tests for extract_certs_from_pem."""

    def test_no_certs(self):
        self.assertEqual(ipsec_swap.extract_certs_from_pem(b"no certs"),
                         [])

    @mock.patch.object(ipsec_swap, 'x509')
    def test_with_cert(self, mock_x509):
        mock_x509.load_pem_x509_certificate.return_value = (
            mock.MagicMock()
        )
        pem = (
            b"-----BEGIN CERTIFICATE-----\n"
            b"data\n"
            b"-----END CERTIFICATE-----\n"
        )
        result = ipsec_swap.extract_certs_from_pem(pem)
        self.assertEqual(len(result), 1)

    @mock.patch.object(ipsec_swap, 'x509')
    def test_bad_cert_returns_none(self, mock_x509):
        mock_x509.load_pem_x509_certificate.side_effect = (
            Exception("bad")
        )
        pem = (
            b"-----BEGIN CERTIFICATE-----\n"
            b"bad\n"
            b"-----END CERTIFICATE-----\n"
        )
        self.assertIsNone(ipsec_swap.extract_certs_from_pem(pem))


class TestSaveCertBundle(unittest.TestCase):
    """Tests for save_cert_bundle."""

    @mock.patch.object(ipsec_swap, 'extract_certs_from_pem')
    def test_saves_certs(self, mock_extract):
        mock_cert = mock.MagicMock()
        mock_cert.public_bytes.return_value = b"CERTDATA"
        mock_extract.return_value = [mock_cert]
        with tempfile.TemporaryDirectory() as tmpdir:
            with mock.patch.object(
                    ipsec_swap,
                    'IPSEC_CA_CERT_DIR',
                    tmpdir + '/'
            ):
                ipsec_swap.save_cert_bundle(b"pem", 'test-prefix')
            self.assertEqual(len(os.listdir(tmpdir)), 1)


if __name__ == '__main__':
    unittest.main()
