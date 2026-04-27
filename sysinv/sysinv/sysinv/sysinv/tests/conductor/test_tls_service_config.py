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


class TestUpdateServiceConfigTLS(base.DbTestCase):
    """Tests for TLS parameter handling in update_service_config."""

    def setUp(self):
        super(TestUpdateServiceConfigTLS, self).setUp()

        self.service = manager.ConductorManager('test-host', 'test-topic')
        self.service.dbapi = dbapi.get_instance()
        self.context = context.get_admin_context()
        self.system = utils.create_test_isystem()

        self.mock_config_update = mock.patch.object(
            self.service, '_config_update_hosts',
            return_value='fake-uuid').start()
        self.mock_config_apply = mock.patch.object(
            self.service, '_config_apply_runtime_manifest'
        ).start()

    def _call_update_service_config(self, section=None, name=None,
                                    do_apply=False):
        self.service.update_service_config(
            self.context,
            service=constants.SERVICE_TYPE_PLATFORM,
            do_apply=do_apply,
            section=section,
            name=name)

    def test_tls_min_version_triggers_haproxy_runtime(self):
        self._call_update_service_config(
            section=constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
            name=constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION)

        self.mock_config_update.assert_called_once()
        self.mock_config_apply.assert_called_once()
        config_dict = self.mock_config_apply.call_args[0][2]
        self.assertIn('platform::haproxy::runtime',
                       config_dict['classes'])

    def test_tls_cipher_suite_triggers_haproxy_runtime(self):
        self._call_update_service_config(
            section=constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
            name=constants.SERVICE_PARAM_NAME_PLATFORM_TLS_CIPHER_SUITE)

        self.mock_config_apply.assert_called_once()
        config_dict = self.mock_config_apply.call_args[0][2]
        self.assertIn('platform::haproxy::runtime',
                       config_dict['classes'])

    def test_apply_platform_includes_haproxy_runtime(self):
        self._call_update_service_config(do_apply=True)

        self.mock_config_apply.assert_called_once()
        config_dict = self.mock_config_apply.call_args[0][2]
        self.assertIn('platform::haproxy::runtime',
                       config_dict['classes'])
        self.assertIn('platform::mtce::runtime',
                       config_dict['classes'])

    def test_tls_handler_targets_controller_only(self):
        self._call_update_service_config(
            section=constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
            name=constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION)

        config_dict = self.mock_config_apply.call_args[0][2]
        self.assertEqual(config_dict['personalities'],
                         [constants.CONTROLLER])

    def test_tls_handler_no_reboot(self):
        """TLS parameter changes should not require reboot."""
        self._call_update_service_config(
            section=constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
            name=constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION)

        call_kwargs = self.mock_config_update.call_args
        if call_kwargs[1]:
            self.assertNotEqual(call_kwargs[1].get('reboot'), True)
