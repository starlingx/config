#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /health/ methods.
"""

import mock
from six.moves import http_client

from oslo_config import cfg

from sysinv.common import kubernetes

from sysinv.tests.api import base


class FakeConductorAPI(object):

    def __init__(self):
        self.get_system_health = mock.MagicMock(
            return_value=(True, 'fake health output'))


class TestHealth(base.FunctionalTest):

    def setUp(self):
        super(TestHealth, self).setUp()

        self.fake_conductor_api = FakeConductorAPI()
        p = mock.patch('sysinv.conductor.rpcapiproxy.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)

    def _get_kube_upgrade_health(self, path='/health/kube-upgrade', **params):
        response = self.get_json(path, **params)
        self.assertEqual(response, 'fake health output')
        return self.fake_conductor_api.get_system_health.call_args[1]


class TestHealthKubeUpgrade(TestHealth):

    def test_no_parameters(self):
        # Without parameters no alarm is ignored
        kwargs = self._get_kube_upgrade_health()
        self.assertEqual(kwargs['alarm_ignore_list'], [])
        self.assertTrue(kwargs['kube_upgrade'])
        self.assertFalse(kwargs['force'])
        # rootca is forwarded as received, so absent means None rather
        # than False; see test_rootca_is_forwarded_unparsed
        self.assertIsNone(kwargs['kube_rootca_update'])

    def test_alarm_ignore_list_is_parsed(self):
        # The comma separated query string value must reach the health
        # check as a list, so that alarm ids are matched exactly instead
        # of as a substring of the raw value
        kwargs = self._get_kube_upgrade_health(
            alarm_ignore_list='900.023,900.401')
        self.assertEqual(kwargs['alarm_ignore_list'],
                         ['900.023', '900.401'])

    def test_alarm_ignore_list_legacy_format_is_parsed(self):
        kwargs = self._get_kube_upgrade_health(
            alarm_ignore_list="['900.401',]")
        self.assertEqual(kwargs['alarm_ignore_list'], ['900.401'])

    def test_alarm_ignore_list_invalid_value_is_rejected(self):
        # A value that holds no alarm id is reported to the caller. The
        # shared parser cannot raise, because the kube-upgrade-start
        # request body uses it too, so the API boundary compares what it
        # got back against what was supplied. Failing quietly here would
        # leave the operator reading 'No alarms: [Fail]' with no way to
        # tell that their list was discarded.
        response = self.get_json(
            '/health/kube-upgrade', expect_errors=True,
            alarm_ignore_list='not-an-alarm-id')
        self.assertEqual(response.status_int, http_client.BAD_REQUEST)
        self.assertIn('alarm_ignore_list', response.json['error_message'])
        self.fake_conductor_api.get_system_health.assert_not_called()

    def test_alarm_ignore_list_typo_is_rejected(self):
        # A comma typed where a dot belongs is the realistic mistake:
        # '900,007' parses to two tokens that are not alarm ids
        response = self.get_json(
            '/health/kube-upgrade', expect_errors=True,
            alarm_ignore_list='900,007')
        self.assertEqual(response.status_int, http_client.BAD_REQUEST)
        self.assertIn('alarm_ignore_list', response.json['error_message'])

    def test_alarm_ignore_list_invalid_literal_is_rejected(self):
        # The serialized literal form is held to the same contract as the
        # comma separated one
        response = self.get_json(
            '/health/kube-upgrade', expect_errors=True,
            alarm_ignore_list="['not-an-alarm-id']")
        self.assertEqual(response.status_int, http_client.BAD_REQUEST)
        self.assertIn('alarm_ignore_list', response.json['error_message'])

    def test_alarm_ignore_list_empty_value_is_accepted(self):
        # An explicitly empty value is a deliberate empty list, not a
        # rejected one, and must not turn into an error
        kwargs = self._get_kube_upgrade_health(alarm_ignore_list='')
        self.assertEqual(kwargs['alarm_ignore_list'], [])

    def test_use_default_ignore_list_applies_server_default(self):
        kwargs = self._get_kube_upgrade_health(
            use_default_ignore_list='true')
        self.assertEqual(
            kwargs['alarm_ignore_list'],
            sorted(kubernetes.DEFAULT_KUBE_UPGRADE_ALARM_IGNORE_LIST))
        # The alarm raised by the upgrade itself is part of the default
        # list, which is what makes the check usable mid upgrade
        self.assertIn('900.007', kwargs['alarm_ignore_list'])

    def test_use_default_ignore_list_is_merged_with_client_list(self):
        # The two lists are merged, not replaced, so that an orchestrator
        # passing its own list keeps the server-side defaults
        kwargs = self._get_kube_upgrade_health(
            alarm_ignore_list='750.005',
            use_default_ignore_list='true')
        expected = sorted(
            set(kubernetes.DEFAULT_KUBE_UPGRADE_ALARM_IGNORE_LIST)
            | {'750.005'})
        self.assertEqual(kwargs['alarm_ignore_list'], expected)

    def test_use_default_ignore_list_off_by_default(self):
        # Omitting the parameter must leave the previous behaviour intact
        kwargs = self._get_kube_upgrade_health(
            alarm_ignore_list='750.005')
        self.assertEqual(kwargs['alarm_ignore_list'], ['750.005'])

    def test_use_default_ignore_list_false_is_honoured(self):
        # 'false' must read as False, not as a non-empty truthy string
        kwargs = self._get_kube_upgrade_health(
            alarm_ignore_list='750.005',
            use_default_ignore_list='false')
        self.assertEqual(kwargs['alarm_ignore_list'], ['750.005'])

    def test_use_default_ignore_list_invalid_value_is_rejected(self):
        response = self.get_json(
            '/health/kube-upgrade?use_default_ignore_list=maybe',
            expect_errors=True)
        self.assertEqual(response.status_int, http_client.BAD_REQUEST)
        self.assertIn('use_default_ignore_list',
                      response.json['error_message'])
        self.fake_conductor_api.get_system_health.assert_not_called()

    def test_use_default_ignore_list_without_a_value_is_true(self):
        # '?use_default_ignore_list' with no value is a flag: naming the
        # parameter is the caller asking for it. It must not be a 400.
        kwargs = self._get_kube_upgrade_health(
            path='/health/kube-upgrade?use_default_ignore_list')
        self.assertIn('900.007', kwargs['alarm_ignore_list'])

    def test_use_default_ignore_list_reads_the_config_option(self):
        # The default list is read from [kube_upgrade] alarm_ignore_list,
        # not from the module constant. Asserting against the constant
        # would still pass if the code read the constant directly, which
        # is the import-order dependency the move to common/kubernetes.py
        # exists to avoid.
        cfg.CONF.set_override('alarm_ignore_list', ['123.456'],
                              group='kube_upgrade')
        self.addCleanup(cfg.CONF.clear_override, 'alarm_ignore_list',
                        group='kube_upgrade')
        kwargs = self._get_kube_upgrade_health(
            use_default_ignore_list='true')
        self.assertEqual(kwargs['alarm_ignore_list'], ['123.456'])

    def test_relaxed_sets_force(self):
        kwargs = self._get_kube_upgrade_health(
            path='/health/kube-upgrade/relaxed')
        self.assertTrue(kwargs['force'])
        self.assertEqual(kwargs['alarm_ignore_list'], [])

    def test_rootca_is_forwarded_unparsed(self):
        # This asserts the behaviour as it is, not as it should be.
        # rootca reaches the health check as the raw query string text
        # and is tested there with a plain truthiness check, so
        # '?rootca=false' enables the rootca checks too (see the test
        # below). That is a pre-existing defect, deliberately left out of
        # scope for this change. Do not read this test as the contract
        # being correct.
        kwargs = self._get_kube_upgrade_health(rootca='True')
        self.assertEqual(kwargs['kube_rootca_update'], 'True')

    def test_rootca_false_is_also_forwarded_unparsed(self):
        # Pins the defect described above, so that fixing it has to be a
        # deliberate change with a failing test rather than a silent one
        kwargs = self._get_kube_upgrade_health(rootca='false')
        self.assertEqual(kwargs['kube_rootca_update'], 'false')

    def test_unsupported_upgrade_type_is_rejected(self):
        response = self.get_json('/health/not-an-upgrade-type',
                                 expect_errors=True)
        self.assertEqual(response.status_int, http_client.BAD_REQUEST)


class TestHealthPlatformUpgrade(TestHealth):

    def test_alarm_ignore_list_is_not_used(self):
        # The platform upgrade health check does not take an ignore list
        response = self.get_json('/health/upgrade')
        self.assertEqual(response, 'fake health output')
        kwargs = self.fake_conductor_api.get_system_health.call_args[1]
        self.assertTrue(kwargs['upgrade'])
        self.assertFalse(kwargs['force'])
        self.assertNotIn('alarm_ignore_list', kwargs)

    def test_relaxed_sets_force(self):
        response = self.get_json('/health/upgrade/relaxed')
        self.assertEqual(response, 'fake health output')
        kwargs = self.fake_conductor_api.get_system_health.call_args[1]
        self.assertTrue(kwargs['force'])
