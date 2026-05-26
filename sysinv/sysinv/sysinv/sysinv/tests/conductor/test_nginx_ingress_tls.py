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


class TestTlsHandlerRuntimeManifest(base.DbTestCase):
    """Tests for TLS parameter handler in conductor."""

    def setUp(self):
        super(TestTlsHandlerRuntimeManifest, self).setUp()

        self.service = manager.ConductorManager('test-host', 'test-topic')
        self.service.dbapi = dbapi.get_instance()
        self.context = context.get_admin_context()
        self.system = utils.create_test_isystem()

    def test_tls_handler_calls_runtime_manifest(self):
        """Verify TLS param change triggers runtime manifest with all classes."""
        mock.patch.object(
            self.service, '_config_update_hosts',
            return_value='fake-uuid').start()
        mock_runtime = mock.patch.object(
            self.service, '_config_apply_runtime_manifest').start()

        self.service.update_service_config(
            self.context,
            service=constants.SERVICE_TYPE_PLATFORM,
            section=constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
            name=constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION)

        mock_runtime.assert_called_once()
        config_dict = mock_runtime.call_args[0][2]
        self.assertIn('platform::haproxy::runtime', config_dict['classes'])
        self.assertIn('platform::dockerdistribution::runtime', config_dict['classes'])
        self.assertIn('platform::ldap::tls::runtime', config_dict['classes'])
        self.assertIn('openstack::lighttpd::runtime', config_dict['classes'])

    def test_tls_handler_no_separate_reapply_call(self):
        """Verify TLS handler relies on _config_apply_runtime_manifest's
        internal evaluate_apps_reapply (no duplicate call)."""
        mock.patch.object(
            self.service, '_config_update_hosts',
            return_value='fake-uuid').start()
        mock.patch.object(
            self.service, '_config_apply_runtime_manifest').start()
        mock_eval = mock.patch.object(
            self.service, 'evaluate_apps_reapply').start()

        self.service.update_service_config(
            self.context,
            service=constants.SERVICE_TYPE_PLATFORM,
            section=constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
            name=constants.SERVICE_PARAM_NAME_PLATFORM_TLS_MIN_VERSION)

        # evaluate_apps_reapply should NOT be called directly by the handler
        # (it's called internally by _config_apply_runtime_manifest)
        mock_eval.assert_not_called()
