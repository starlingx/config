# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- encoding: utf-8 -*-
#
#
# Copyright (c) 2017-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /certificate_install/ methods.
"""

import os
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from sysinv.api.controllers.v1 import certificate as cert_api
from sysinv.tests.api import base


class CertificateTestCase(base.FunctionalTest):

    def setUp(self):
        super(CertificateTestCase, self).setUp()

    def test_check_cert_dns_name_valid_SAN(self):
        # This certificate contains
        # CN: *.vbox.local
        # DNS: *.vbox.local
        certfile = os.path.join(os.path.dirname(__file__), "data",
                                'cert-with-key-SAN.pem')
        with open(certfile, 'rb') as f:
            pem_contents = f.read()
        cert = x509.load_pem_x509_certificate(pem_contents,
                                              default_backend())

        result = cert_api._check_cert_dns_name(cert, 'vbox.local')
        self.assertTrue(result)

        result = cert_api._check_cert_dns_name(cert, 'domain.org')
        self.assertIn("doesn't match", str(result))

        result = cert_api._check_cert_dns_name(cert, 'lab.vbox.local')
        self.assertIn("doesn't match", str(result))

    def test_check_cert_dns_name_invalid_SAN(self):
        # This certificate contains
        # CN: *.vbox.local
        # DNS:*.*.vbox.local, DNS:bad.*.vbox.local
        certfile = os.path.join(os.path.dirname(__file__), "data",
                                'cert-with-key-invalidDNS.pem')
        with open(certfile, 'rb') as f:
            pem_contents = f.read()
        cert = x509.load_pem_x509_certificate(pem_contents,
                                              default_backend())

        result = cert_api._check_cert_dns_name(cert, 'vbox.local')
        self.assertIn("doesn't match", str(result))

        result = cert_api._check_cert_dns_name(cert, 'a.vbox.local')
        self.assertIn("doesn't match", str(result))

        result = cert_api._check_cert_dns_name(cert, 'a.b.vbox.local')
        self.assertIn("doesn't match", str(result))

        result = cert_api._check_cert_dns_name(cert, 'bad.b.vbox.local')
        self.assertIn("doesn't match", str(result))

    def test_check_cert_dns_name_CN_only(self):
        # This certificate contains CN:*.vbox.local
        certfile = os.path.join(os.path.dirname(__file__), "data",
                                'cert-with-key-CNnoSAN.pem')
        with open(certfile, 'rb') as f:
            pem_contents = f.read()
        cert = x509.load_pem_x509_certificate(pem_contents,
                                              default_backend())

        result = cert_api._check_cert_dns_name(cert, 'vbox.local')
        self.assertTrue(result)

        result = cert_api._check_cert_dns_name(cert, 'a.vbox.local')
        self.assertIn("doesn't match", str(result))

        result = cert_api._check_cert_dns_name(cert, 'a.b.vbox.local')
        self.assertIn("doesn't match", str(result))

        result = cert_api._check_cert_dns_name(cert, 'bad.b.vbox.local')
        self.assertIn("doesn't match", str(result))

    def test_check_cert_dns_name_multi_SAN(self):
        # This certificate contains
        # CN: *.vbox.local
        # DNS: *.vbox.local, bad.*.vbox.local, *.example.com

        certfile = os.path.join(os.path.dirname(__file__), "data",
                                'cert-with-key-multiSAN.pem')
        with open(certfile, 'rb') as f:
            pem_contents = f.read()
        cert = x509.load_pem_x509_certificate(pem_contents,
                                              default_backend())

        result = cert_api._check_cert_dns_name(cert, 'vbox.local')
        self.assertTrue(result)

        # domain matches one of the DNS names, but not the CN
        result = cert_api._check_cert_dns_name(cert, 'example.com')
        self.assertTrue(result)

        result = cert_api._check_cert_dns_name(cert, 'a.vbox.local')
        self.assertIn("doesn't match", str(result))

        result = cert_api._check_cert_dns_name(cert, 'x.example.com')
        self.assertIn("doesn't match", str(result))

    def test_check_cert_dns_name_CN_differ_SAN(self):
        # This certificate contains
        # CN: *.vbox.local
        # DNS: bad.*.vbox.local, *.example.com

        certfile = os.path.join(os.path.dirname(__file__), "data",
                                'cert-with-key-CNdifferSAN.pem')
        with open(certfile, 'rb') as f:
            pem_contents = f.read()
        cert = x509.load_pem_x509_certificate(pem_contents,
                                              default_backend())

        # domain matches CN, but does not match any of the DNS names
        result = cert_api._check_cert_dns_name(cert, 'vbox.local')
        self.assertIn("doesn't match", str(result))

        # domain matches one of the DNS names, but not the CN
        result = cert_api._check_cert_dns_name(cert, 'example.com')
        self.assertTrue(result)

        result = cert_api._check_cert_dns_name(cert, 'a.vbox.local')
        self.assertIn("doesn't match", str(result))

        result = cert_api._check_cert_dns_name(cert, 'x.example.com')
        self.assertIn("doesn't match", str(result))
