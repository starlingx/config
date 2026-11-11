#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the logical volume group agent operator.
"""

import mock

from sysinv.agent import lvg
from sysinv.tests import base


@mock.patch.object(lvg.LVGOperator, 'count_lvs_in_thinpool',
                   return_value=0)
@mock.patch.object(lvg.LVGOperator, 'thinpools_in_vg', return_value=0)
class TestLVGOperator(base.TestCase):

    def setUp(self):
        super(TestLVGOperator, self).setUp()
        self.operator = lvg.LVGOperator()

    @mock.patch('sysinv.agent.lvg.utils.subprocess_open')
    def test_ilvg_get_uses_system_filter_only(self, mock_subprocess_open,
                                              mock_thinpools, mock_count):
        """Only one vgdisplay runs and it keeps the system global_filter."""
        mock_subprocess_open.return_value = ('', '')

        self.operator.ilvg_get()

        self.assertEqual(1, mock_subprocess_open.call_count)
        command = mock_subprocess_open.call_args[1]['command']
        self.assertNotIn('global_filter', command)

    @mock.patch('sysinv.agent.lvg.utils.subprocess_open')
    def test_ilvg_get_parses_cgts_vg(self, mock_subprocess_open,
                                     mock_thinpools, mock_count):
        mock_subprocess_open.return_value = (
            '  cgts-vg uuid1 wz--n- 0 7 0 1 200 50 10\n', '')
        mock_count.return_value = 2

        ilvg = self.operator.ilvg_get()

        self.assertEqual(['cgts-vg'], [vg['lvm_vg_name'] for vg in ilvg])
        self.assertEqual(200, ilvg[0]['lvm_vg_size'])
        self.assertEqual(7, ilvg[0]['lvm_cur_lv'])
        self.assertEqual({'thin_cur_lv': 2}, ilvg[0]['capabilities'])
