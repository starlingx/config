#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the physical volume agent operator.
"""

import mock

from sysinv.agent import pv
from sysinv.tests import base


class TestPVOperator(base.TestCase):

    def setUp(self):
        super(TestPVOperator, self).setUp()
        self.operator = pv.PVOperator()

    @mock.patch('sysinv.agent.pv.utils.subprocess_open')
    def test_ipv_get_uses_system_filter_only(self, mock_subprocess_open):
        """Only one pvdisplay runs and it keeps the system global_filter."""
        mock_subprocess_open.return_value = ('', '')

        self.operator.ipv_get()

        self.assertEqual(1, mock_subprocess_open.call_count)
        command = mock_subprocess_open.call_args[1]['command']
        self.assertNotIn('global_filter', command)

    @mock.patch('sysinv.agent.pv.utils.subprocess_open')
    def test_ipv_get_parses_pvs(self, mock_subprocess_open):
        mock_subprocess_open.return_value = (
            '  /dev/sda5;cgts-vg;uuid1;100;25;20\n', '')

        ipv = self.operator.ipv_get()

        self.assertEqual(1, len(ipv))
        self.assertEqual('/dev/sda5', ipv[0]['lvm_pv_name'])
        self.assertEqual('cgts-vg', ipv[0]['lvm_vg_name'])
        self.assertEqual(100, ipv[0]['lvm_pv_size'])
