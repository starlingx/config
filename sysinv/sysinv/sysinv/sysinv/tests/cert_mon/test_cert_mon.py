# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


"""Test class for Sysinv CertMon"""

import filecmp
import json
import mock
import os.path

from sysinv.common import constants
from sysinv.cert_mon import service as cert_mon
from sysinv.cert_mon import utils as cert_mon_utils
from sysinv.openstack.common.keystone_objects import Token
from sysinv.tests.db import base


class CertMonTestCase(base.DbTestCase):

    def setUp(self):
        super(CertMonTestCase, self).setUp()

        # Set up objects for testing
        self.service = cert_mon.CertificateMonitorService()
        self.keystone_token = self.get_keystone_token()

        # Mock rest_api_request()
        self.rest_api_request_result = None

        def mock_rest_api_request(token, method, api_cmd,
                                    api_cmd_payload=None, timeout=10):
            return self.rest_api_request_result
        self.mocked_rest_api_request = mock.patch(
            'sysinv.cert_mon.utils.rest_api_request',
            mock_rest_api_request)
        self.mocked_rest_api_request.start()
        self.addCleanup(self.mocked_rest_api_request.stop)

    def tearDown(self):
        super(CertMonTestCase, self).tearDown()

    def test_platformcert_secret_and_ns_check(self):
        self.assertEqual("system-restapi-gui-certificate",
                            constants.PLATFORM_CERT_SECRET_NAME)
        self.assertEqual("deployment",
                            constants.CERT_NAMESPACE_PLATFORM_CERTS)

    def test_update_pemfile(self):
        reference_file = os.path.join(os.path.dirname(__file__),
                                        "data", "cert-with-key.pem")
        cert_filename = os.path.join(os.path.dirname(__file__),
                                        "data", "cert.pem")
        key_filename = os.path.join(os.path.dirname(__file__),
                                        "data", "key.pem")

        with open(cert_filename, 'r') as cfile:
            tls_cert = cfile.read()

        with open(key_filename, 'r') as kfile:
            tls_key = kfile.read()

        generated_file = cert_mon_utils.update_platformcert_pemfile(tls_cert, tls_key)
        assert os.path.exists(generated_file)
        assert filecmp.cmp(generated_file, reference_file, shallow=False)

        os.remove(generated_file)

    def get_keystone_token(self):
        token_file = os.path.join(os.path.dirname(__file__), "data", "keystone-token")
        with open(token_file, 'r') as tfile:
            token_json = json.load(tfile)

        token_id = 'fake-token-id'
        region_name = 'RegionOne'
        return Token(token_json, token_id, region_name)

    def test_get_isystems_uuid(self):
        isystems_file = os.path.join(os.path.dirname(__file__), "data", "isystems")
        with open(isystems_file, 'r') as ifile:
            self.rest_api_request_result = json.load(ifile)

        token = self.keystone_token
        ret = cert_mon_utils.get_isystems_uuid(token)
        assert ret == 'fdc60cf3-3330-4438-859d-b0da19e9663d'

    def test_enable_https(self):
        isystems_file = os.path.join(os.path.dirname(__file__), "data", "isystems")
        with open(isystems_file, 'r') as ifile:
            isystems_json = json.load(ifile)

        # The PATCH api response doesn't include the 'isystems[]' json list section
        self.rest_api_request_result = isystems_json['isystems'][0]
        token = self.keystone_token
        ret = cert_mon_utils.enable_https(token, 'fdc60cf3-3330-4438-859d-b0da19e9663d')
        assert ret is True
