# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from oslo_context import context

from sysinv.common import constants
from sysinv.conductor import manager
from sysinv.db import api as dbapi
from sysinv.tests.db import base
from sysinv.tests.db import utils


class FakeServiceParam(object):
    def __init__(self, name, value):
        self.name = name
        self.value = value


class TestUpdateNginxIngressTlsConfig(base.DbTestCase):
    """Tests for _update_nginx_ingress_tls_config in conductor."""

    def setUp(self):
        super(TestUpdateNginxIngressTlsConfig, self).setUp()

        self.service = manager.ConductorManager('test-host', 'test-topic')
        self.service.dbapi = dbapi.get_instance()
        self.service._kube = mock.MagicMock()
        self.context = context.get_admin_context()
        self.system = utils.create_test_isystem()

    def _mock_tls_params(self, version='VersionTLS12', ciphers=None):
        if ciphers is None:
            ciphers = constants.SERVICE_PARAM_PLATFORM_TLS_CIPHER_SUITE_DEFAULT
        params = [
            FakeServiceParam(
                constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION,
                version),
            FakeServiceParam(
                constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE,
                ciphers),
        ]
        p = mock.patch.object(self.service.dbapi,
                              'service_parameter_get_all',
                              return_value=params)
        p.start()
        self.addCleanup(p.stop)

    def test_tls12_produces_correct_ssl_protocols(self):
        self._mock_tls_params(version='VersionTLS12')
        self.service._update_nginx_ingress_tls_config()

        call_args = self.service._kube.kube_patch_config_map.call_args
        body = call_args[0][2]
        self.assertEqual(body['data']['ssl-protocols'],
                         'TLSv1.2 TLSv1.3')

    def test_tls13_produces_correct_ssl_protocols(self):
        self._mock_tls_params(version='VersionTLS13')
        self.service._update_nginx_ingress_tls_config()

        call_args = self.service._kube.kube_patch_config_map.call_args
        body = call_args[0][2]
        self.assertEqual(body['data']['ssl-protocols'], 'TLSv1.3')

    def test_default_ciphers_converted_to_openssl(self):
        self._mock_tls_params()
        self.service._update_nginx_ingress_tls_config()

        call_args = self.service._kube.kube_patch_config_map.call_args
        body = call_args[0][2]
        ssl_ciphers = body['data']['ssl-ciphers']
        self.assertIn('ECDHE-RSA-AES256-GCM-SHA384', ssl_ciphers)
        self.assertIn('ECDHE-RSA-AES128-GCM-SHA256', ssl_ciphers)
        self.assertIn('TLS_AES_256_GCM_SHA384', ssl_ciphers)

    def test_single_cipher_converted(self):
        self._mock_tls_params(
            ciphers='TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384')
        self.service._update_nginx_ingress_tls_config()

        call_args = self.service._kube.kube_patch_config_map.call_args
        body = call_args[0][2]
        self.assertEqual(body['data']['ssl-ciphers'],
                         'ECDHE-RSA-AES256-GCM-SHA384')

    def test_patches_correct_configmap(self):
        self._mock_tls_params()
        self.service._update_nginx_ingress_tls_config()

        self.service._kube.kube_patch_config_map.assert_called_once()
        call_args = self.service._kube.kube_patch_config_map.call_args
        self.assertEqual(call_args[0][0],
                         'ic-nginx-ingress-ingress-nginx-controller')
        self.assertEqual(call_args[0][1], 'kube-system')

    def test_db_failure_uses_defaults(self):
        p = mock.patch.object(self.service.dbapi,
                              'service_parameter_get_all',
                              side_effect=Exception("DB error"))
        p.start()
        self.addCleanup(p.stop)
        self.service._update_nginx_ingress_tls_config()

        call_args = self.service._kube.kube_patch_config_map.call_args
        body = call_args[0][2]
        self.assertEqual(body['data']['ssl-protocols'],
                         'TLSv1.2 TLSv1.3')

    def test_kube_patch_failure_does_not_raise(self):
        self._mock_tls_params()
        self.service._kube.kube_patch_config_map.side_effect = \
            Exception("K8s error")
        self.service._update_nginx_ingress_tls_config()

    def test_tls_handler_calls_nginx_update(self):
        """Verify individual TLS param change triggers nginx update."""
        mock.patch.object(
            self.service, '_config_update_hosts',
            return_value='fake-uuid').start()
        mock.patch.object(
            self.service, '_config_apply_runtime_manifest').start()
        mock_nginx = mock.patch.object(
            self.service, '_update_nginx_ingress_tls_config').start()

        self.service.update_service_config(
            self.context,
            service=constants.SERVICE_TYPE_PLATFORM,
            section=constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
            name=constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION)

        mock_nginx.assert_called_once()
