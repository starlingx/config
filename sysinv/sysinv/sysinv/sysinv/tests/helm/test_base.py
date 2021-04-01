# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from sysinv.helm.base import BaseHelm
from sysinv.helm.helm import HelmOperator

from sysinv.tests import base as test_base


class TestHelmBase(test_base.TestCase):
    def test_num_replicas_for_platform_app_0_controllers(self):
        self.check_num_replicas_for_platform_app(num_provisioned_controllers=0, expected_replicas=1)

    def test_num_replicas_for_platform_app_1_controllers(self):
        self.check_num_replicas_for_platform_app(num_provisioned_controllers=1, expected_replicas=1)

    def test_num_replicas_for_platform_app_2_controllers(self):
        self.check_num_replicas_for_platform_app(num_provisioned_controllers=2, expected_replicas=2)

    def check_num_replicas_for_platform_app(self, num_provisioned_controllers, expected_replicas):
        mock_operator = mock.MagicMock(spec=HelmOperator)
        mock_operator.dbapi = mock.MagicMock()
        mock_operator.dbapi.count_hosts_matching_criteria.return_value = num_provisioned_controllers

        base = BaseHelm(mock_operator)
        actual_replicas = base._num_replicas_for_platform_app()

        self.assertEqual(actual_replicas, expected_replicas)
