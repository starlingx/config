#
# Copyright (c) 2017-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /certificate_install/delete methods.
"""

import json
import mock
import os
import uuid as UUID
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from six.moves import http_client
from sysinv.api.controllers.v1 import certificate as cert_api
from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils


class FakeConductorAPI(object):

    def __init__(self):
        self.config_certificate = self.fake_config_certificate
        self.delete_certificate = mock.MagicMock()
        self.config_certificate_return = None
        self.platcert_k8s_secret_value = False

    def fake_config_certificate(self, context, pem, config_dict):
        return self.config_certificate_return

    def setup_config_certificate(self, data):
        self.config_certificate_return = data

    def update_admin_ep_certificate(self, context):
        return True


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


class ApiCertificateTestCaseMixin(object):

    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/certificate'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'certificates'

    # COMMON_FIELD is a field that is known to exist for inputs and outputs
    COMMON_FIELD = 'certificates'

    # expected_api_fields are attributes that should be populated by
    # an API query
    expected_api_fields = ['uuid']

    # hidden_api_fields are attributes that should not be populated by
    # an API query
    hidden_api_fields = []

    def setUp(self):
        super(ApiCertificateTestCaseMixin, self).setUp()
        self.fake_conductor_api = FakeConductorAPI()

        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)

    def get_single_url(self, uuid):
        return '%s/%s' % (self.API_PREFIX, uuid)

    def _create_db_object(self, obj_id=None):
        return dbutils.create_test_certificate(
            id=obj_id, certtype='ssl_ca', signature='ssl_ca_123456789')

    @staticmethod
    def extract_certs_from_pem_file(certfile):
        """ extract certificates from a X509 PEM file
        """
        marker = b'-----BEGIN CERTIFICATE-----'
        with open(certfile, 'rb') as f:
            pem_contents = f.read()
            start = 0
            certs = []
            while True:
                index = pem_contents.find(marker, start)
                if index == -1:
                    break
                cert = x509.load_pem_x509_certificate(pem_contents[index::],
                                                      default_backend())
                certs.append(cert)
                start = index + len(marker)
        return certs

    @staticmethod
    def get_cert_signature(mode, cert):
        signature = mode + '_' + str(cert.serial_number)
        if len(signature) > 255:
            signature = signature[:255]
        return signature


class ApiCertificatePostTestSuite(ApiCertificateTestCaseMixin,
                                  base.FunctionalTest):
    """ Certificate post operations
    """
    def setUp(self):
        super(ApiCertificatePostTestSuite, self).setUp()
        self.create_test_isystem()

        # Mock the KubeOperator
        self.kube_get_secret_result = None

        def mock_kube_get_secret(obj, name, namespace):
            return self.kube_get_secret_result
        self.mocked_kube_get_secret = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_secret',
            mock_kube_get_secret)
        self.mocked_kube_get_secret.start()
        self.addCleanup(self.mocked_kube_get_secret.stop)

    def create_test_isystem(self):
        return dbutils.create_test_isystem(capabilities={'https_enabled': True})

    # Test successful POST operation to install 1 CA certificate
    def test_install_one_CA_certificate(self):
        mode = 'ssl_ca'
        certfile = os.path.join(os.path.dirname(__file__), "data",
                                'ca-cert-one-cert.pem')

        in_certs = self.extract_certs_from_pem_file(certfile)
        fake_config_certificate_return = []
        for in_cert in in_certs:
            fake_config_certificate_return.append(
                        {'signature': self.get_cert_signature(mode, in_cert),
                         'not_valid_before': in_cert.not_valid_before,
                         'not_valid_after': in_cert.not_valid_after})
        self.fake_conductor_api.\
            setup_config_certificate(fake_config_certificate_return)

        data = {'mode': mode}
        files = [('file', certfile)]
        response = self.post_with_files('%s/%s' % (self.API_PREFIX, 'certificate_install'),
                                  data,
                                  upload_files=files,
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)
        resp = json.loads(response.body)
        self.assertIn('certificates', resp)
        ret_certs = resp.get('certificates')
        self.assertEqual(len(in_certs), len(ret_certs))
        for ret_cert in ret_certs:
            self.assertIn('certtype', ret_cert)
            self.assertEqual(ret_cert.get('certtype'), mode)
            self.assertIn('signature', ret_cert)
            self.assertIn('start_date', ret_cert)
            self.assertIn('expiry_date', ret_cert)
            found_match = False
            for in_cert in in_certs:
                ret_cert_start_date = str(ret_cert.get('start_date'))
                ret_cert_start_date = ret_cert_start_date.replace('+00:00', '')
                ret_cert_expiry_date = str(ret_cert.get('expiry_date'))
                ret_cert_expiry_date = \
                    ret_cert_expiry_date.replace('+00:00', '')
                if ret_cert.get('signature') == \
                        self.get_cert_signature(mode, in_cert) and \
                        ret_cert_start_date == \
                        str(in_cert.not_valid_before) and \
                        ret_cert_expiry_date == \
                        str(in_cert.not_valid_after):
                    found_match = True
            self.assertTrue(found_match)

    def test_renew_certificate(self):
        certtype = constants.CERTIFICATE_TYPE_ADMIN_ENDPOINT
        data = {'certtype': certtype}
        response = self.post_json('%s/%s' % (self.API_PREFIX, 'renew_certificate'),
                                        data,
                                        headers=self.API_HEADERS,
                                        expect_errors=True)

        self.assertTrue(response)

    # Test successful POST operation to install 2 CA certificate
    def test_install_two_CA_certificate(self):
        mode = 'ssl_ca'
        certfile = os.path.join(os.path.dirname(__file__), "data",
                                'ca-cert-two-certs.pem')

        in_certs = self.extract_certs_from_pem_file(certfile)
        fake_config_certificate_return = []
        for in_cert in in_certs:
            fake_config_certificate_return.append(
                        {'signature': self.get_cert_signature(mode, in_cert),
                         'not_valid_before': in_cert.not_valid_before,
                         'not_valid_after': in_cert.not_valid_after})
        self.fake_conductor_api.\
            setup_config_certificate(fake_config_certificate_return)

        data = {'mode': mode}
        files = [('file', certfile)]
        response = self.post_with_files('%s/%s' % (self.API_PREFIX,
                                                   'certificate_install'),
                                        data,
                                        upload_files=files,
                                        headers=self.API_HEADERS,
                                        expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)
        resp = json.loads(response.body)
        self.assertIn('certificates', resp)
        ret_certs = resp.get('certificates')
        self.assertEqual(len(in_certs), len(ret_certs))
        for ret_cert in ret_certs:
            self.assertIn('certtype', ret_cert)
            self.assertEqual(ret_cert.get('certtype'), mode)
            self.assertIn('signature', ret_cert)
            self.assertIn('start_date', ret_cert)
            self.assertIn('expiry_date', ret_cert)
            found_match = False
            for in_cert in in_certs:
                ret_cert_start_date = str(ret_cert.get('start_date'))
                ret_cert_start_date = ret_cert_start_date.replace('+00:00', '')
                ret_cert_expiry_date = str(ret_cert.get('expiry_date'))
                ret_cert_expiry_date = \
                    ret_cert_expiry_date.replace('+00:00', '')
                if ret_cert.get('signature') == \
                        self.get_cert_signature(mode, in_cert) and \
                        ret_cert_start_date == \
                        str(in_cert.not_valid_before) and \
                        ret_cert_expiry_date == \
                        str(in_cert.not_valid_after):
                    found_match = True
            self.assertTrue(found_match)

    # Test successful POST operation to install ssl certificate signed by
    # intermediate CA
    def test_install_2xcert_1xkey_ssl_certificate(self):
        mode = 'ssl'
        certfile = os.path.join(os.path.dirname(__file__), "data",
                                'ssl-cert-2xcert-1xkey-with-key.pem')

        in_certs = self.extract_certs_from_pem_file(certfile)
        fake_config_certificate_return = []
        for index, in_cert in enumerate(in_certs):
            is_ca = False if index == 0 else True
            fake_config_certificate_return.append(
                        {'signature': self.get_cert_signature(mode, in_cert),
                         'not_valid_before': in_cert.not_valid_before,
                         'not_valid_after': in_cert.not_valid_after,
                         'is_ca': is_ca})
        self.fake_conductor_api.\
            setup_config_certificate(fake_config_certificate_return)

        data = {'mode': mode}
        files = [('file', certfile)]
        response = self.post_with_files('%s/%s' % (self.API_PREFIX, 'certificate_install'),
                                  data,
                                  upload_files=files,
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)
        resp = json.loads(response.body)
        self.assertIn('certificates', resp)
        ret_certs = resp.get('certificates')

        # The installed cert contains the server cert and the intermediate
        # CA cert but the API returns only the server cert, which should match
        # the server cert in the cert file (the first one).
        self.assertEqual(len(ret_certs), 1)
        ret_cert = ret_certs[0]
        in_cert = in_certs[0]

        self.assertIn('certtype', ret_cert)
        self.assertEqual(ret_cert.get('certtype'), mode)
        self.assertIn('signature', ret_cert)
        self.assertIn('start_date', ret_cert)
        self.assertIn('expiry_date', ret_cert)

        ret_cert_start_date = str(ret_cert.get('start_date'))
        ret_cert_start_date = ret_cert_start_date.replace('+00:00', '')
        ret_cert_expiry_date = str(ret_cert.get('expiry_date'))
        ret_cert_expiry_date = ret_cert_expiry_date.replace('+00:00', '')
        found_match = False
        if ret_cert.get('signature') == \
                self.get_cert_signature(mode, in_cert) and \
                ret_cert_start_date == \
                str(in_cert.not_valid_before) and \
                ret_cert_expiry_date == \
                str(in_cert.not_valid_after):
            found_match = True
        self.assertTrue(found_match)

    # Test POST operation to install ssl certificate signed by intermediate CA,
    # but the server cert and intermediate cert in the file is in wrong order.
    def test_install_2xcert_1xkey_ssl_certificate_wrong_order(self):
        mode = 'ssl'
        certfile = os.path.join(os.path.dirname(__file__), "data",
                                'ssl-cert-2xcert-1xkey-with-key-wrong-order.pem')

        data = {'mode': mode}
        files = [('file', certfile)]
        response = self.post_with_files('%s/%s' % (self.API_PREFIX, 'certificate_install'),
                                  data,
                                  upload_files=files,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertTrue(response.body)
        resp = json.loads(response.body)
        self.assertTrue(resp.get('error'))
        fault_string_expected = 'The first cert in the file should not be a ' \
                                'CA cert'
        self.assertIn(fault_string_expected, str(resp.get('error')))

    # Test successful POST operation to install docker_registry certificate
    # signed by intermediate CA
    def test_install_2xcert_1xkey_docker_registry_certificate(self):
        mode = 'docker_registry'
        certfile = os.path.join(os.path.dirname(__file__), "data",
                                'docker_registry-cert-2xcert-1xkey-with-key.pem')

        in_certs = self.extract_certs_from_pem_file(certfile)
        fake_config_certificate_return = []
        for index, in_cert in enumerate(in_certs):
            is_ca = False if index == 0 else True
            fake_config_certificate_return.append(
                        {'signature': self.get_cert_signature(mode, in_cert),
                         'not_valid_before': in_cert.not_valid_before,
                         'not_valid_after': in_cert.not_valid_after,
                         'is_ca': is_ca})
        self.fake_conductor_api.\
            setup_config_certificate(fake_config_certificate_return)

        data = {'mode': mode}
        files = [('file', certfile)]
        response = self.post_with_files('%s/%s' % (self.API_PREFIX, 'certificate_install'),
                                  data,
                                  upload_files=files,
                                  headers=self.API_HEADERS,
                                  expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)
        resp = json.loads(response.body)
        self.assertIn('certificates', resp)
        ret_certs = resp.get('certificates')

        # The installed cert contains the server cert and the intermediate
        # CA cert but the API returns only the server cert, which should match
        # the server cert in the cert file (the first one).
        self.assertEqual(len(ret_certs), 1)
        ret_cert = ret_certs[0]
        in_cert = in_certs[0]

        self.assertIn('certtype', ret_cert)
        self.assertEqual(ret_cert.get('certtype'), mode)
        self.assertIn('signature', ret_cert)
        self.assertIn('start_date', ret_cert)
        self.assertIn('expiry_date', ret_cert)

        ret_cert_start_date = str(ret_cert.get('start_date'))
        ret_cert_start_date = ret_cert_start_date.replace('+00:00', '')
        ret_cert_expiry_date = str(ret_cert.get('expiry_date'))
        ret_cert_expiry_date = ret_cert_expiry_date.replace('+00:00', '')
        found_match = False
        if ret_cert.get('signature') == \
                self.get_cert_signature(mode, in_cert) and \
                ret_cert_start_date == \
                str(in_cert.not_valid_before) and \
                ret_cert_expiry_date == \
                str(in_cert.not_valid_after):
            found_match = True
        self.assertTrue(found_match)

    # Test POST operation to install docker_registry certificate signed by
    # intermediate CA, but the server cert and intermediate cert in the file
    # is in wrong order.
    def test_install_2xcert_1xkey_docker_registry_certificate_wrong_order(self):
        mode = 'docker_registry'
        certfile = os.path.join(os.path.dirname(__file__), "data",
                                'docker_registry-cert-2xcert-1xkey-with-key-wrong-order.pem')

        data = {'mode': mode}
        files = [('file', certfile)]
        response = self.post_with_files('%s/%s' % (self.API_PREFIX, 'certificate_install'),
                                  data,
                                  upload_files=files,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertTrue(response.body)
        resp = json.loads(response.body)
        self.assertTrue(resp.get('error'))
        fault_string_expected = 'The first cert in the file should not be a ' \
                                'CA cert'
        self.assertIn(fault_string_expected, str(resp.get('error')))

    # Test install ssl certificate signed by intermediate CA
    def test_force_failure_install_ssl_certificate(self):
        mode = 'ssl'
        certfile = os.path.join(os.path.dirname(__file__), "data",
                                'ssl-cert-2xcert-1xkey-with-key.pem')

        in_certs = self.extract_certs_from_pem_file(certfile)
        fake_config_certificate_return = []
        for index, in_cert in enumerate(in_certs):
            is_ca = False if index == 0 else True
            fake_config_certificate_return.append(
                        {'signature': self.get_cert_signature(mode, in_cert),
                         'not_valid_before': in_cert.not_valid_before,
                         'not_valid_after': in_cert.not_valid_after,
                         'is_ca': is_ca})
        self.fake_conductor_api.\
            setup_config_certificate(fake_config_certificate_return)

        # Set k8s_secret value to True (mark it as being managed by cert-manager)
        self.kube_get_secret_result = 'true'

        # Default behavior (force=false) should fail
        data = {'mode': mode}
        files = [('file', certfile)]
        response = self.post_with_files('%s/%s' % (self.API_PREFIX, 'certificate_install'),
                                  data,
                                  upload_files=files,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.status_code, http_client.OK)
        self.assertTrue(response.body)
        resp = json.loads(response.body)
        self.assertTrue(resp.get('error'))
        fault_err_msg = "Certificate is currently being managed by cert-manager"
        self.assertIn(fault_err_msg, str(resp.get('error')))

    # Test install ssl certificate signed by intermediate CA
    def test_force_success_install_ssl_certificate(self):
        mode = 'ssl'
        certfile = os.path.join(os.path.dirname(__file__), "data",
                                'ssl-cert-2xcert-1xkey-with-key.pem')

        in_certs = self.extract_certs_from_pem_file(certfile)
        fake_config_certificate_return = []
        for index, in_cert in enumerate(in_certs):
            is_ca = False if index == 0 else True
            fake_config_certificate_return.append(
                        {'signature': self.get_cert_signature(mode, in_cert),
                         'not_valid_before': in_cert.not_valid_before,
                         'not_valid_after': in_cert.not_valid_after,
                         'is_ca': is_ca})
        self.fake_conductor_api.\
            setup_config_certificate(fake_config_certificate_return)

        # Set k8s_secret value to True (mark it as being managed by cert-manager)
        self.kube_get_secret_result = 'true'

        data = {'mode': mode, 'force': 'true'}
        files = [('file', certfile)]
        response = self.post_with_files('%s/%s' % (self.API_PREFIX, 'certificate_install'),
                                  data,
                                  upload_files=files,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual(response.status_code, http_client.OK)
        resp = json.loads(response.body)
        self.assertIn('certificates', resp)


class ApiCertificateDeleteTestSuite(ApiCertificateTestCaseMixin,
                                    base.FunctionalTest):
    """ Certificate delete operations
    """
    def setUp(self):
        super(ApiCertificateDeleteTestSuite, self).setUp()
        self.delete_object = self._create_db_object()

    # Test successful CA certficate DELETE operation
    def test_delete_ca_certificate(self):
        uuid = self.delete_object.uuid
        certtype = self.delete_object.certtype
        signature = self.delete_object.signature
        response = self.delete(self.get_single_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=False)

        self.assertEqual(response.status_code, http_client.OK)
        self.assertTrue(response.body)
        resp = json.loads(response.body)
        self.assertIn('uuid', resp)
        self.assertEqual(uuid, resp.get('uuid'))
        self.assertIn('certtype', resp)
        self.assertEqual(certtype, resp.get('certtype'))
        self.assertIn('signature', resp)
        self.assertEqual(signature, resp.get('signature'))

    # Test CA certficate DELETE operation, no certificate found
    def test_delete_ca_certificate_not_found(self):
        uuid = UUID.uuid4()
        response = self.delete(self.get_single_url(uuid),
                               headers=self.API_HEADERS,
                               expect_errors=True)

        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertTrue(response.body)
        resp = json.loads(response.body)
        self.assertTrue(resp.get('error_message'))
        fault_string_expected = 'No certificate found for %s' % uuid
        self.assertIn(fault_string_expected, str(resp.get('error_message')))
