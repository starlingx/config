#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from cgtsclient.tests import test_shell


class HealthShellTest(test_shell.ShellTest):

    def _query_kube_upgrade(self, *args):
        with mock.patch('cgtsclient.v1.health.HealthManager.'
                        'get_kube_upgrade') as mock_get:
            mock_get.return_value = 'fake health output'
            self.make_env()
            self.shell(' '.join(('health-query-kube-upgrade',) + args))
            return mock_get.call_args[0][0]

    def test_health_query_kube_upgrade_defaults(self):
        attributes = self._query_kube_upgrade()
        self.assertEqual(attributes, {'rootca': False,
                                      'alarm_ignore_list': None,
                                      'use_default_ignore_list': False})

    def test_health_query_kube_upgrade_alarm_ignore_list(self):
        attributes = self._query_kube_upgrade(
            '--alarm-ignore-list', '900.023,900.401')
        self.assertEqual(attributes['alarm_ignore_list'], '900.023,900.401')
        self.assertFalse(attributes['use_default_ignore_list'])

    def test_health_query_kube_upgrade_use_default_ignore_list(self):
        # The flag takes no value: being present means true
        attributes = self._query_kube_upgrade('--use-default-ignore-list')
        self.assertTrue(attributes['use_default_ignore_list'])
        self.assertIsNone(attributes['alarm_ignore_list'])

    def test_health_query_kube_upgrade_all_options(self):
        attributes = self._query_kube_upgrade(
            '--rootca', '--use-default-ignore-list',
            '--alarm-ignore-list', '750.005')
        self.assertEqual(attributes, {'rootca': True,
                                      'alarm_ignore_list': '750.005',
                                      'use_default_ignore_list': True})
