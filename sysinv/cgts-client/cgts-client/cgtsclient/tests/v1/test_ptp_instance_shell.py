#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Unit tests for the dpll-mgr structured 'config' section CLI validation
(story 2011783) in cgtsclient.v1.ptp_instance_shell."""

import contextlib
import io

import testtools

from cgtsclient import exc
from cgtsclient.v1 import ptp_instance_shell as shell


class TestDpllMgrConfigSectionValidation(testtools.TestCase):

    def _validate(self, *keypairs):
        shell._validate_dpll_mgr_config_section(list(keypairs))

    # ---- accept ----

    def test_known_scalar_keys_ok(self):
        self._validate('phc_interface=eno8703', 'operation_mode=SW_BASED',
                       'ptp_domain_number=24')

    def test_pin_priority_map_ok(self):
        self._validate('dpll0_pin_priority_map=GNSS_REF4P:0, SDP0_REF0N:12')

    def test_pin_priority_15_disconnect_ok(self):
        # 15 is the disconnect sentinel and is a valid priority value.
        self._validate('dpll0_pin_priority_map=GNSS_REF4P:0, SDP0_REF0N:15')

    def test_pin_alias_ok(self):
        self._validate('dpll1_pin_priority_map=gnss:0, pps-sdp0:12')

    def test_channel_keys_ok(self):
        self._validate('channel_ptp_bh=ptp01bh', 'channel_ts2_0=ts1',
                       'channel_ts2_1=ts2')

    def test_holdover_ok(self):
        self._validate('ho_0=480', 'ho_1=2', 'ho_2=3')

    # ---- reject ----

    def test_unknown_key_rejected(self):
        self.assertRaises(exc.CommandError, self._validate, 'bogus=1')

    def test_unknown_pin_rejected(self):
        self.assertRaises(exc.CommandError, self._validate,
                          'dpll0_pin_priority_map=NOPE_REF9Z:0')

    def test_priority_out_of_range_rejected(self):
        self.assertRaises(exc.CommandError, self._validate,
                          'dpll0_pin_priority_map=GNSS_REF4P:99')

    def test_malformed_pin_entry_rejected(self):
        self.assertRaises(exc.CommandError, self._validate,
                          'dpll0_pin_priority_map=GNSS_REF4P')

    def test_bad_operation_mode_rejected(self):
        self.assertRaises(exc.CommandError, self._validate,
                          'operation_mode=TURBO')

    def test_primary_key_rejected(self):
        # The 'primary' hint was removed; it is no longer an accepted key.
        self.assertRaises(exc.CommandError, self._validate, 'primary=gnss')

    def test_non_integer_holdover_rejected(self):
        self.assertRaises(exc.CommandError, self._validate, 'ho_0=eight')

    def test_missing_equals_rejected(self):
        self.assertRaises(exc.CommandError, self._validate, 'phc_interface')

    # ---- warn (accept) ----

    def test_ptp_0_channel_warns_but_accepts(self):
        # Should not raise; emits a warning (captured to avoid test noise).
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            self._validate('channel_ptp_0=ptpfwd')
        self.assertIn('WARNING', buf.getvalue())
        self.assertIn('ptp_0/1/2', buf.getvalue())
