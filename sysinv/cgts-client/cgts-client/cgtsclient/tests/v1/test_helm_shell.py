#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from cgtsclient import exc
from cgtsclient.tests import test_shell
from cgtsclient.v1.helm import Helm


class HelmChartAttributeModifyShellTest(test_shell.ShellTest):

    APP = 'fake-app'
    CHART = 'fake-chart'
    NAMESPACE = 'fake-ns'

    def setUp(self):
        super(HelmChartAttributeModifyShellTest, self).setUp()
        self.make_env()

        find_app = mock.patch('cgtsclient.v1.app._find_app')
        self.mock_find_app = find_app.start()
        self.addCleanup(find_app.stop)
        self.mock_find_app.return_value = mock.Mock(**{'name': self.APP})

        list_charts = mock.patch('cgtsclient.v1.helm.HelmManager.list_charts')
        self.mock_list_charts = list_charts.start()
        self.addCleanup(list_charts.stop)
        self.mock_list_charts.return_value = [
            Helm(None, {'name': self.CHART, 'namespaces': [self.NAMESPACE]},
                 True)]

        update_chart = mock.patch('cgtsclient.v1.helm.HelmManager.'
                                  'update_chart')
        self.mock_update_chart = update_chart.start()
        self.addCleanup(update_chart.stop)
        self.mock_update_chart.return_value = Helm(
            None, {'name': self.CHART, 'namespace': self.NAMESPACE,
                   'attributes': {'enabled': True}}, True)

    def _modify(self, *args):
        return self.shell(' '.join(
            ('helm-chart-attribute-modify', self.APP, self.CHART,
             self.NAMESPACE) + args))

    def test_attribute_modify_without_enabled_is_refused(self):
        # An empty PATCH would be read by the API as a reset of the chart's
        # user overrides, so it must never be sent.
        self.assertRaises(exc.CommandError, self._modify)
        self.mock_update_chart.assert_not_called()

    def test_attribute_modify_without_enabled_fails_before_app_lookup(self):
        self.assertRaises(exc.CommandError, self._modify)
        self.mock_find_app.assert_not_called()
        self.mock_list_charts.assert_not_called()

    def test_attribute_modify_enabled_false(self):
        self._modify('--enabled', 'false')
        self.mock_update_chart.assert_called_once_with(
            self.APP, self.CHART, self.NAMESPACE, {'enabled': 'false'})

    def test_attribute_modify_enabled_true(self):
        self._modify('--enabled', 'true')
        self.mock_update_chart.assert_called_once_with(
            self.APP, self.CHART, self.NAMESPACE, {'enabled': 'true'})
