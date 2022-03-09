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

from oslo_serialization import base64

from sysinv.common import constants
from sysinv.common import exception
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
        self.token_cache_num = 1

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

    def test_list_platform_certificates(self):
        patcher = mock.patch('sysinv.cert_mon.utils.rest_api_request')
        mocked_rest_api_get = patcher.start()
        self.addCleanup(patcher.stop)

        mock_certificates = {
            'certificates': [
                {
                    'uuid': 'uuid',
                    'signature': 'docker_registry_1231345345',
                    'start_date': '2022-03-09 06:32:33+00:00',
                    'expiry_date': '2022-03-09 06:32:33+00:00'
                }
            ]
        }

        mocked_rest_api_get.return_value = mock_certificates
        actual_certificates = cert_mon_utils.list_platform_certificates(self.keystone_token)
        self.assertEqual(actual_certificates, mock_certificates)

    def get_registry_watcher(self):
        class FakeContext(object):
            def get_token(self):
                return self.get_keystone_token()

        registry_cert_watcher = cert_mon_watcher.RegistryCert_CertWatcher()
        return registry_cert_watcher

    def test_handle_secret_event_none_event(self):
        secret_event = {
            "type": None,
            "object": None,
            "raw_object": None
        }

        registry_cert_watcher = self.get_registry_watcher()
        self.assertRaises(exception.UnexpectedEvent,
                          registry_cert_watcher.handle_secret_event, secret_event, None, None)

    def test_handle_secret_event_error_event(self):
        secret_event = {
            "type": 'ERROR',
            "object": None,
            "raw_object": None
        }
        registry_cert_watcher = self.get_registry_watcher()
        self.assertRaises(exception.UnexpectedEvent,
                          registry_cert_watcher.handle_secret_event, secret_event, None, None)

    def test_handle_secret_event_good_event(self):

        certificate_file = 'cert-with-key.pem'
        pem_file_path = self.get_data_file_path('%s' % certificate_file)

        cert_content = None
        with open(pem_file_path) as f:
            cert_content = f.read()

        cert_content_base64 = base64.encode_as_text(cert_content)

        secret_event = {
            "type": 'ADDED',
            "object": None,
            "raw_object": {
                'data': {
                    'ca.crt': cert_content_base64,
                    'tls.crt': cert_content_base64,
                    'tls.key': cert_content_base64,
                },
                'metadata': {
                    'name': 'system-registry-local-certificate',
                    'creationTimestamp': '2022-03-07T17:33:21Z',
                    'managedFields': [
                        {
                            'operation': 'update',
                            'time': '2022-03-07T17:33:21Z'
                        }
                    ]
                }
            }
        }

        patcher_get_token = mock.patch('sysinv.cert_mon.utils.get_token')
        get_token_mock = patcher_get_token.start()
        self.addCleanup(patcher_get_token.stop)
        get_token_mock.return_value = self.get_keystone_token()

        patcher_context = \
            mock.patch('sysinv.cert_mon.watcher.MonitorContext.initialize')
        mock_monitor_context = patcher_context.start()
        self.addCleanup(patcher_context.stop)
        mock_monitor_context.return_value = None

        patcher_rest_api_upload = \
            mock.patch('sysinv.cert_mon.utils.rest_api_upload')
        mocked_rest_api_upload = patcher_rest_api_upload.start()
        self.addCleanup(patcher_rest_api_upload.stop)
        mocked_rest_api_upload.return_value = {'error': ''}

        patcher_rest_api_get = mock.patch('sysinv.cert_mon.utils.rest_api_request')
        mocked_rest_api_get = patcher_rest_api_get.start()
        self.addCleanup(patcher_rest_api_get.stop)

        patcher_rest_api_context_get_token = \
            mock.patch('sysinv.cert_mon.watcher.MonitorContext.get_token')
        mock_monitor_context = patcher_rest_api_context_get_token.start()
        self.addCleanup(patcher_rest_api_context_get_token.stop)
        mock_monitor_context.return_value = self.get_keystone_token()

        mocked_rest_api_get.return_value = {
            'certificates': [
                {
                    'signature': 'docker_registry_9999'
                }
            ]
        }

        registry_cert_watcher = self.get_registry_watcher()
        registry_cert_watcher.initialize()

        mock_on_success = mock.Mock()

        registry_cert_watcher.handle_secret_event(secret_event, mock_on_success, None)
        mock_on_success.assert_called_once()

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

    def test_update_platform_cert_with_already_installed_cert(self):
        # This is the serial number of 'cert-with-key.pem'
        # so it's expected that upload function (for installation) is never called
        bad_serial_number = 94501982348953436415103405232215009626
        expected_to_install = False
        self.update_platform_cert_with_check_for_already_installed(
            bad_serial_number, expected_to_install)

    def test_update_platform_cert_with_not_yet_installed_cert(self):
        # This is a different serial number of that of 'cert-with-key.pem'
        # so it's expected that upload function to be called to install new cert
        good_serial_number = 9999999999999999999999999999999999999
        expected_to_install = True
        self.update_platform_cert_with_check_for_already_installed(
            good_serial_number, expected_to_install)

    def update_platform_cert_with_check_for_already_installed(
            self, serial_number, expected_to_install):
        token = self.keystone_token

        cert_type = constants.CERT_MODE_DOCKER_REGISTRY
        certificate_file = 'cert-with-key.pem'
        certificate_serial_number = serial_number
        pem_file_path = self.get_data_file_path('%s' % certificate_file)

        cert_content = None
        with open(pem_file_path) as f:
            cert_content = f.read()

        key_starter = "-----BEGIN RSA PRIVATE KEY-----"
        cert_contents = cert_content.split(key_starter)

        cert_content = cert_contents[0]
        key_content = key_starter + cert_contents[1]

        patcher = mock.patch('sysinv.cert_mon.utils.rest_api_upload')
        mocked_rest_api_upload = patcher.start()
        self.addCleanup(patcher.stop)
        mocked_rest_api_upload.return_value = {'error': ''}

        patcher2 = mock.patch('sysinv.cert_mon.utils.rest_api_request')
        mocked_rest_api_get = patcher2.start()
        self.addCleanup(patcher2.stop)

        mocked_rest_api_get.return_value = {
            'certificates': [
                {
                    'signature': 'docker_registry_' + str(certificate_serial_number)
                }
            ]
        }

        class FakeEventData(object):
            tls_crt = cert_content
            tls_key = key_content

        class FakeContext(object):
            def get_token(self):
                return token

        registry_cert_renew = cert_mon_watcher.RegistryCertRenew(FakeContext())

        if expected_to_install:
            registry_cert_renew.update_platform_certificate(FakeEventData(), cert_type)
            mocked_rest_api_upload.assert_called_once_with(token, mock.ANY, mock.ANY, mock.ANY)
        else:
            registry_cert_renew.update_platform_certificate(FakeEventData(), cert_type)
            mocked_rest_api_upload.assert_not_called()

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
        cert_watcher.is_check_existing_certificates = False
        # start_watch will raise an exception if it fails to parse
        # the event
        cert_watcher.start_watch(None, None)

        mock_watch_instance.stream.assert_called_once()
        mock_watch_instance.stop.assert_called_once()

    @mock.patch('sysinv.cert_mon.watcher.watch.Watch')
    @mock.patch('sysinv.cert_mon.watcher.client')
    @mock.patch('sysinv.cert_mon.watcher.config')
    @mock.patch('sysinv.cert_mon.watcher.CertUpdateEventData')
    @mock.patch('sysinv.cert_mon.watcher.CertWatcher._update_latest_resource_version')
    def test_initial_secrets_listing_done_only_once(self, mock_config, mock_client,
                                                    mock_watch, mock_cert_update_event_data,
                                                    mock_update_latest_resource_version):
        cert_watcher = cert_mon_watcher.CertWatcher()

        patcher = mock.patch('sysinv.cert_mon.watcher.CertWatcher.handle_secret_event')
        mocked_handle_secret_event = patcher.start()
        self.addCleanup(patcher.stop)
        mocked_handle_secret_event.return_value = None

        secret = "{\"secret\": \"my-secret\"}"

        class Response(object):
            def read(self):
                return "{\"items\": [%s]}" % secret

        mock_k8_client = cert_watcher._get_kubernetes_core_client()
        mock_k8_client.list_namespaced_secret = mock.Mock(return_value=Response())

        # Calls start_watch multiple times
        cert_watcher.start_watch(None, None)
        cert_watcher.start_watch(None, None)

        secret_event = {
            "type": "EXISTING",
            "object": json.loads(secret),
            "raw_object": json.loads(secret)
        }
        # Checks that initial listing is done only once
        mocked_handle_secret_event.assert_called_once_with(secret_event, None, None)

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
                                 get_token=mock.DEFAULT,
                                 get_dc_token=mock.DEFAULT,
                                 update_subcloud_status=mock.DEFAULT,
                                 update_subcloud_ca_cert=mock.DEFAULT) \
                as utils_mock:
            # returns an SSL cert in PEM-encoded string
            utils_mock["dc_get_subcloud_sysinv_url"].return_value \
                = "https://example.com"
            utils_mock["get_endpoint_certificate"].return_value \
                = self._get_valid_certificate_pem()
            utils_mock["get_sc_intermediate_ca_secret"].return_value \
                = self._get_sc_intermediate_ca_secret()
            utils_mock["is_subcloud_online"].return_value = True
            utils_mock["get_dc_token"].return_value = None  # don"t care
            utils_mock["update_subcloud_status"].return_value = None
            utils_mock["update_subcloud_ca_cert"].return_value = None

            # also need to mock the TokenCache
            with mock.patch.multiple("sysinv.cert_mon.utils.TokenCache",
                                     get_token=mock.DEFAULT) \
                    as token_cache_mock:
                token_cache_mock["get_token"].return_value = None  # don"t care

                cmgr = cert_mon_manager.CertificateMonManager()
                cmgr.use_sc_audit_pool = False  # easier for testing in serial

                cmgr.sc_audit_queue.enqueue(
                    subcloud_audit_queue.SubcloudAuditData("test1"),
                    delay_secs=1)
                cmgr.sc_audit_queue.enqueue(
                    subcloud_audit_queue.SubcloudAuditData("test2"),
                    delay_secs=2)
                self.assertEqual(cmgr.sc_audit_queue.qsize(), 2)

                # Run audit immediately, it should not have picked up anything
                cmgr.audit_sc_cert_task(None)
                self.assertEqual(cmgr.sc_audit_queue.qsize(), 2)

                time.sleep(3)
                cmgr.audit_sc_cert_task(None)
                # It should now be drained:
                self.assertEqual(cmgr.sc_audit_queue.qsize(), 0)

    def test_token_cache(self):
        """Basic test case for TokenCache"""

        def get_cache_test_token():
            """This method replaces utils.get_token() for this test.
            Increments the token id each invocation.
            """
            token = self.get_keystone_token()
            token.token_id = "token{}".format(self.token_cache_num)
            self.token_cache_num += 1
            return token

        token_cache = cert_mon_utils.TokenCache('internal')

        # override the cache getter function for our test:
        token_cache._getter_func = get_cache_test_token

        token = token_cache.get_token()
        self.assertEqual(token.get_id(), "token1")
        self.assertFalse(token.is_expired())
        self.assertEqual(token_cache.get_token().get_id(), "token1")
        token.set_expired()
        self.assertTrue(token.is_expired())
        # should now get a new, unexpired token:
        token = token_cache.get_token()
        self.assertEqual(token.get_id(), "token2")
        self.assertFalse(token.is_expired())
        self.assertEqual(token_cache.get_token().get_id(), "token2")
        token_cache.get_token().set_expired()
        self.assertTrue(token.is_expired())
        token = token_cache.get_token()
        self.assertEqual(token.get_id(), "token3")
        self.assertFalse(token.is_expired())
        token = token_cache.get_token()
        self.assertEqual(token.get_id(), "token3")
        self.assertFalse(token.is_expired())
