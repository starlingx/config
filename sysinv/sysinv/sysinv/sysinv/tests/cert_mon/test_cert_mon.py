# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


"""Test class for Sysinv CertMon"""

import filecmp
import json
import mock
import os.path
import time

from sysinv.common import constants
from sysinv.cert_mon import service as cert_mon
from sysinv.cert_mon import certificate_mon_manager as cert_mon_manager
from sysinv.cert_mon import subcloud_audit_queue
from sysinv.cert_mon import utils as cert_mon_utils
from sysinv.cert_mon import watcher as cert_mon_watcher
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

    def test_platform_certs_secret_and_ns_check(self):
        self.assertEqual("system-restapi-gui-certificate",
                         constants.RESTAPI_CERT_SECRET_NAME)
        self.assertEqual("system-registry-local-certificate",
                         constants.REGISTRY_CERT_SECRET_NAME)
        self.assertEqual("deployment", constants.CERT_NAMESPACE_PLATFORM_CERTS)

    def test_update_pemfile(self):
        reference_file = self.get_data_file_path("cert-with-key.pem")
        cert_filename = self.get_data_file_path("cert.pem")
        key_filename = self.get_data_file_path("key.pem")

        with open(cert_filename, 'r') as cfile:
            tls_cert = cfile.read()

        with open(key_filename, 'r') as kfile:
            tls_key = kfile.read()

        generated_file = cert_mon_utils.update_pemfile(tls_cert, tls_key)
        assert os.path.exists(generated_file)
        assert filecmp.cmp(generated_file, reference_file, shallow=False)

        os.remove(generated_file)

    def get_keystone_token(self):
        token_file = self.get_data_file_path("keystone-token")
        with open(token_file, 'r') as tfile:
            token_json = json.load(tfile)

        token_id = 'fake-token-id'
        region_name = 'RegionOne'
        return Token(token_json, token_id, region_name)

    def test_get_isystems_uuid(self):
        isystems_file = self.get_data_file_path("isystems")
        with open(isystems_file, 'r') as ifile:
            self.rest_api_request_result = json.load(ifile)

        token = self.keystone_token
        ret = cert_mon_utils.get_isystems_uuid(token)
        assert ret == 'fdc60cf3-3330-4438-859d-b0da19e9663d'

    def test_enable_https(self):
        isystems_file = self.get_data_file_path("isystems")
        with open(isystems_file, 'r') as ifile:
            isystems_json = json.load(ifile)

        # The PATCH api response doesn't include the 'isystems[]' json list section
        self.rest_api_request_result = isystems_json['isystems'][0]
        token = self.keystone_token
        ret = cert_mon_utils.enable_https(token, 'fdc60cf3-3330-4438-859d-b0da19e9663d')
        assert ret is True

    def test_update_platform_cert_force_true(self):
        self.update_platform_cert(True)

    def test_update_platform_cert_force_false(self):
        self.update_platform_cert(False)

    def update_platform_cert(self, force):
        token = self.keystone_token
        cert_type = constants.CERT_MODE_DOCKER_REGISTRY
        pem_file_path = self.get_data_file_path('cert-with-key.pem')

        patcher = mock.patch('sysinv.cert_mon.utils.rest_api_upload')
        mocked_rest_api_upload = patcher.start()
        self.addCleanup(patcher.stop)
        mocked_rest_api_upload.return_value = {'error': ''}

        with mock.patch('sysinv.cert_mon.utils.os') as mocked_os:
            cert_mon_utils.update_platform_cert(token, cert_type, pem_file_path, force)

            mocked_os.remove.assert_called_once_with(pem_file_path)

        mocked_rest_api_upload.assert_called_once_with(token, pem_file_path, mock.ANY, mock.ANY)
        actual_data = mocked_rest_api_upload.call_args[0][3]

        self.assertEqual(actual_data['force'], str(force).lower())

    def get_data_file_path(self, file_name):
        return os.path.join(os.path.dirname(__file__), "data", file_name)

    @mock.patch('sysinv.cert_mon.watcher.watch.Watch')
    @mock.patch('sysinv.cert_mon.watcher.client')
    @mock.patch('sysinv.cert_mon.watcher.config')
    def test_expired_event(self, mock_config, mock_client, mock_watch):
        expired_event = {
            "object": {
                "api_version": "v1",
                "kind": "Status",
                "metadata": {},
            },
            "raw_object": {
                "apiVersion": "v1",
                "code": 410,
                "kind": "Status",
                "message": "too old resource version: 3856747 (5376715)",
                "metadata": {},
                "reason": "Expired",
                "status": "Failure"
            },
            "type": "ERROR"
        }
        self.check_bad_event(mock_watch, expired_event)

    @mock.patch('sysinv.cert_mon.watcher.watch.Watch')
    @mock.patch('sysinv.cert_mon.watcher.client')
    @mock.patch('sysinv.cert_mon.watcher.config')
    def test_unknown_event(self, mock_config, mock_client, mock_watch):
        unknown_event = {}
        self.check_bad_event(mock_watch, unknown_event)

    def check_bad_event(self, mock_watch, event_data):
        def stream_bad_event(*args, **kwargs):
            yield event_data

        mock_watch_instance = mock_watch.return_value
        mock_watch_instance.stream.side_effect = stream_bad_event

        cert_watcher = cert_mon_watcher.CertWatcher()
        # start_watch will raise an exception if it fails to parse
        # the event
        cert_watcher.start_watch(None, None)

        mock_watch_instance.stream.assert_called_once()
        mock_watch_instance.stop.assert_called_once()

    def _get_valid_certificate_pem(self):
        cert_filename = self.get_data_file_path("audit/cacert.pem")
        with open(cert_filename, 'r') as cfile:
            cert_file = cfile.read()
        return cert_file

    def _get_sc_intermediate_ca_secret(self):
        cert_filename = self.get_data_file_path("audit/ca-chain-bundle.cert.pem")
        key_filename = self.get_data_file_path("audit/cakey.pem")
        cacert_filename = self.get_data_file_path("audit/cacert.pem")
        with open(cert_filename, 'r') as cfile:
            tls_cert = cfile.read()
        with open(key_filename, 'r') as kfile:
            tls_key = kfile.read()
        with open(cacert_filename, 'r') as kfile:
            ca_cert = kfile.read()
        return {
            'data': {
                'tls.crt': tls_cert,
                'tls.key': tls_key,
                'ca.crt': ca_cert
            }
        }

    def test_audit_sc_cert_task_shallow(self):
        """Test the audit_sc_cert_task basic queuing functionality.
        Mocks beginning at do_subcloud_audit"""
        with mock.patch.object(cert_mon_manager.CertificateMonManager,
                               "do_subcloud_audit") as mock_do_subcloud_audit:
            mock_do_subcloud_audit.return_value = None

            cmgr = cert_mon_manager.CertificateMonManager()
            cmgr.use_sc_audit_pool = False  # easier for testing in serial

            cmgr.sc_audit_queue.enqueue(
                subcloud_audit_queue.SubcloudAuditData("test1"), delay_secs=1)
            cmgr.sc_audit_queue.enqueue(
                subcloud_audit_queue.SubcloudAuditData("test2"), delay_secs=2)

            self.assertEqual(cmgr.sc_audit_queue.qsize(), 2)
            # Run audit immediately, it should not have picked up anything
            cmgr.audit_sc_cert_task(None)
            mock_do_subcloud_audit.assert_not_called()
            self.assertEqual(cmgr.sc_audit_queue.qsize(), 2)

            time.sleep(3)
            cmgr.audit_sc_cert_task(None)
            # It should now be drained:
            mock_do_subcloud_audit.assert_called()
            self.assertEqual(cmgr.sc_audit_queue.qsize(), 0)

            mock_do_subcloud_audit.reset_mock()
            cmgr.audit_sc_cert_task(None)
            mock_do_subcloud_audit.assert_not_called()

    def test_audit_sc_cert_task_deep(self):

        """Test the audit_sc_cert_task basic queuing functionality"""
        with mock.patch.multiple("sysinv.cert_mon.utils",
                                 dc_get_subcloud_sysinv_url=mock.DEFAULT,
                                 get_endpoint_certificate=mock.DEFAULT,
                                 get_sc_intermediate_ca_secret=mock.DEFAULT,
                                 is_subcloud_online=mock.DEFAULT,
                                 get_dc_token=mock.DEFAULT,
                                 update_subcloud_status=mock.DEFAULT,
                                 update_subcloud_ca_cert=mock.DEFAULT) as mocks:
            # returns an SSL cert in PEM-encoded string
            mocks["dc_get_subcloud_sysinv_url"].return_value \
                = "https://example.com"
            mocks["get_endpoint_certificate"].return_value \
                = self._get_valid_certificate_pem()
            mocks["get_sc_intermediate_ca_secret"].return_value \
                = self._get_sc_intermediate_ca_secret()
            mocks["is_subcloud_online"].return_value = True
            mocks["get_dc_token"].return_value = None  # don"t care
            mocks["update_subcloud_status"].return_value = None
            mocks["update_subcloud_ca_cert"].return_value = None

            cmgr = cert_mon_manager.CertificateMonManager()
            cmgr.use_sc_audit_pool = False  # easier for testing in serial

            cmgr.sc_audit_queue.enqueue(
                subcloud_audit_queue.SubcloudAuditData("test1"), delay_secs=1)
            cmgr.sc_audit_queue.enqueue(
                subcloud_audit_queue.SubcloudAuditData("test2"), delay_secs=2)
            self.assertEqual(cmgr.sc_audit_queue.qsize(), 2)

            # Run audit immediately, it should not have picked up anything
            cmgr.audit_sc_cert_task(None)
            self.assertEqual(cmgr.sc_audit_queue.qsize(), 2)

            time.sleep(3)
            cmgr.audit_sc_cert_task(None)
            # It should now be drained:
            self.assertEqual(cmgr.sc_audit_queue.qsize(), 0)
