#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Unit tests for the structured dpll-mgr config template / merge / derivation.

Covers spec 6.1 (story 2011783): deep_merge semantics, channel/domain
derivation, override precedence, closed-set pin validation + aliases, the
always-present dpll0/dpll1 defaults, required-minimum and output-completeness
guards.

The GNSS-primary golden shape is grounded in a live GNR-D config.
"""

from sysinv.common import dpll_mgr_config_template as tmpl
from sysinv.common.dpll_mgr_config_template import DpllMgrConfigError
from sysinv.tests import base


# A typical per-host sibling-instance lookup (name -> service type).
INSTANCE_LOOKUP = {
    'ptp01bh': 'ptp4l',
    'ts1': 'ts2phc',
    'ts2': 'ts2phc',
    'ptp01fh': 'ptp4l',
}


class TestDeepMerge(base.TestCase):

    def test_empty_overlay_returns_template_copy(self):
        base_dict = {'a': 1, 'b': {'c': 2}}
        merged = tmpl.deep_merge(base_dict, {})
        self.assertEqual(merged, base_dict)
        # Ensure it is a copy, not the same object.
        merged['b']['c'] = 99
        self.assertEqual(base_dict['b']['c'], 2)

    def test_scalar_overlay_replaces(self):
        merged = tmpl.deep_merge({'a': 1}, {'a': 2})
        self.assertEqual(merged['a'], 2)

    def test_nested_dict_merges(self):
        base_dict = {'g': {'x': 1, 'y': 2}}
        overlay = {'g': {'y': 20, 'z': 30}}
        merged = tmpl.deep_merge(base_dict, overlay)
        self.assertEqual(merged['g'], {'x': 1, 'y': 20, 'z': 30})

    def test_list_overlay_replaces_not_appends(self):
        merged = tmpl.deep_merge({'a': [1, 2, 3]}, {'a': [9]})
        self.assertEqual(merged['a'], [9])

    def test_key_only_in_base_preserved(self):
        merged = tmpl.deep_merge({'a': 1, 'b': 2}, {'a': 10})
        self.assertEqual(merged['b'], 2)

    def test_inputs_not_mutated(self):
        base_dict = {'g': {'x': 1}}
        overlay = {'g': {'x': 2}}
        tmpl.deep_merge(base_dict, overlay)
        self.assertEqual(base_dict['g']['x'], 1)
        self.assertEqual(overlay['g']['x'], 2)


class TestPinValidation(base.TestCase):

    def test_raw_pin_accepted(self):
        self.assertEqual(tmpl.resolve_pin_name('GNSS_REF4P'), 'GNSS_REF4P')

    def test_alias_resolves_to_raw(self):
        self.assertEqual(tmpl.resolve_pin_name('gnss'), 'GNSS_REF4P')
        self.assertEqual(tmpl.resolve_pin_name('pps-sdp0'), 'SDP0_REF0N')
        self.assertEqual(tmpl.resolve_pin_name('synce-a'), 'RCLKA_REF1P')

    def test_unknown_pin_rejected(self):
        self.assertRaises(DpllMgrConfigError,
                          tmpl.resolve_pin_name, 'NOPE_REF9Z')

    def test_holdover_pin_rejected_as_input(self):
        # Holdover/output pins are not operator inputs.
        self.assertRaises(DpllMgrConfigError,
                          tmpl.resolve_pin_name, 'HOLDOVER_0')
        self.assertRaises(DpllMgrConfigError,
                          tmpl.resolve_pin_name, 'DPLL_OUT0')

    def test_parse_priority_map_basic(self):
        pairs = tmpl.parse_pin_priority_map('GNSS_REF4P:0, SDP0_REF0N:12')
        self.assertEqual(pairs, [('GNSS_REF4P', 0), ('SDP0_REF0N', 12)])

    def test_parse_priority_map_resolves_aliases(self):
        out = tmpl.normalize_pin_priority_map('gnss:0, pps-sdp0:12')
        self.assertEqual(out, 'GNSS_REF4P:0, SDP0_REF0N:12')

    def test_priority_15_disconnect_sentinel_accepted(self):
        # 15 is a valid value: the daemon's disconnect sentinel (pin removed
        # from arbitration), used to disable the backhaul SDP pin on the EEC
        # plane. It must pass validation, not be rejected.
        pairs = tmpl.parse_pin_priority_map('GNSS_REF4P:0, SDP0_REF0N:15')
        self.assertEqual(pairs, [('GNSS_REF4P', 0), ('SDP0_REF0N', 15)])

    def test_priority_out_of_range_rejected(self):
        self.assertRaises(DpllMgrConfigError,
                          tmpl.parse_pin_priority_map, 'GNSS_REF4P:16')
        self.assertRaises(DpllMgrConfigError,
                          tmpl.parse_pin_priority_map, 'GNSS_REF4P:-1')

    def test_non_integer_priority_rejected(self):
        self.assertRaises(DpllMgrConfigError,
                          tmpl.parse_pin_priority_map, 'GNSS_REF4P:high')

    def test_malformed_entry_rejected(self):
        self.assertRaises(DpllMgrConfigError,
                          tmpl.parse_pin_priority_map, 'GNSS_REF4P')

    def test_duplicate_pin_rejected(self):
        self.assertRaises(DpllMgrConfigError,
                          tmpl.parse_pin_priority_map,
                          'GNSS_REF4P:0, GNSS_REF4P:5')

    def test_empty_map_rejected(self):
        self.assertRaises(DpllMgrConfigError,
                          tmpl.parse_pin_priority_map, '  ')


class TestChannelDerivation(base.TestCase):

    def test_ptp4l_socket_derived(self):
        channels = tmpl.derive_channels(
            {'ptp_bh': 'ptp01bh'}, INSTANCE_LOOKUP)
        self.assertEqual(
            channels['ptp_bh']['call_channel'],
            'uds:/var/run/ptp4l-ptp01bh')

    def test_ts2phc_socket_derived(self):
        channels = tmpl.derive_channels(
            {'ts2_0': 'ts1', 'ts2_1': 'ts2'}, INSTANCE_LOOKUP)
        self.assertEqual(channels['ts2_0']['call_channel'],
                         'uds:/var/run/ts2phc-ts1')
        self.assertEqual(channels['ts2_1']['call_channel'],
                         'uds:/var/run/ts2phc-ts2')

    def test_explicit_uds_override_used_verbatim(self):
        channels = tmpl.derive_channels(
            {'ptp_bh': 'uds:/custom/path'}, INSTANCE_LOOKUP)
        self.assertEqual(channels['ptp_bh']['call_channel'],
                         'uds:/custom/path')

    def test_missing_instance_rejected(self):
        self.assertRaises(DpllMgrConfigError, tmpl.derive_channels,
                          {'ptp_bh': 'does-not-exist'}, INSTANCE_LOOKUP)

    def test_wrong_service_type_rejected(self):
        # ptp_bh must name a ptp4l instance, not a ts2phc one.
        self.assertRaises(DpllMgrConfigError, tmpl.derive_channels,
                          {'ptp_bh': 'ts1'}, INSTANCE_LOOKUP)
        # ts2_0 must name a ts2phc instance, not a ptp4l one.
        self.assertRaises(DpllMgrConfigError, tmpl.derive_channels,
                          {'ts2_0': 'ptp01bh'}, INSTANCE_LOOKUP)


class TestBuildOverlayAndRender(base.TestCase):

    def _minimum(self):
        # Required-minimum only: dpll0/dpll1 come from the template default.
        return {
            'phc_interface': 'eno8703',
            'operation_mode': 'SW_BASED',
            'channel_ptp_bh': 'ptp01bh',
            'channel_ts2_0': 'ts1',
            'channel_ts2_1': 'ts2',
        }

    def test_render_minimum_gnss_primary_matches_golden_shape(self):
        config = tmpl.render_config(
            self._minimum(), INSTANCE_LOOKUP, domain_from_backhaul=24)
        # Operator-supplied values land where expected.
        self.assertEqual(config['global']['phc_interface'], 'eno8703')
        self.assertEqual(config['global']['operation_mode'], 'SW_BASED')
        self.assertEqual(config['global']['ptp_domain_number'], 24)
        self.assertEqual(config['channels']['ptp_bh']['call_channel'],
                         'uds:/var/run/ptp4l-ptp01bh')
        self.assertEqual(config['channels']['ts2_0']['call_channel'],
                         'uds:/var/run/ts2phc-ts1')
        # Both planes present from the template default (GNSS-primary):
        # dpll0/EEC disconnects the backhaul SDP pin (:15); dpll1/PPS keeps it
        # as a selectable failover (:12).
        self.assertEqual(config['dpll']['dpll0']['pin_priority_map'],
                         'GNSS_REF4P:0, SDP0_REF0N:15')
        self.assertEqual(config['dpll']['dpll1']['pin_priority_map'],
                         'GNSS_REF4P:0, SDP0_REF0N:12')
        # Boilerplate from the template is present.
        self.assertIn('ptp_primary_attributes', config['ptp'])
        self.assertIn('GNSS_REF4P', config['ptp']['ptp_primary_attributes'])
        self.assertIn('option1', config['ql_map'])
        self.assertEqual(config['dpll']['holdover_config']['ho_0'],
                         {'ho_duration': 30})

    def test_domain_derived_from_backhaul_when_absent(self):
        s = self._minimum()
        config = tmpl.render_config(s, INSTANCE_LOOKUP,
                                    domain_from_backhaul=44)
        self.assertEqual(config['global']['ptp_domain_number'], 44)

    def test_explicit_domain_overrides_derived(self):
        s = self._minimum()
        s['ptp_domain_number'] = '100'
        config = tmpl.render_config(s, INSTANCE_LOOKUP,
                                    domain_from_backhaul=24)
        self.assertEqual(config['global']['ptp_domain_number'], 100)

    def test_dpll0_override_replaces_template_default(self):
        # Overriding only dpll0 keeps the template dpll1 default.
        s = self._minimum()
        s['dpll0_pin_priority_map'] = 'synce-a:0, GNSS_REF4P:5, SDP0_REF0N:15'
        config = tmpl.render_config(s, INSTANCE_LOOKUP)
        self.assertEqual(config['dpll']['dpll0']['pin_priority_map'],
                         'RCLKA_REF1P:0, GNSS_REF4P:5, SDP0_REF0N:15')
        self.assertEqual(config['dpll']['dpll1']['pin_priority_map'],
                         'GNSS_REF4P:0, SDP0_REF0N:12')

    def test_dpll1_override_replaces_template_default(self):
        # PTP-backhaul-primary: swap the phase plane explicitly. dpll0 keeps
        # the template default.
        s = self._minimum()
        s['dpll1_pin_priority_map'] = 'GNSS_REF4P:12, SDP0_REF0N:0'
        config = tmpl.render_config(s, INSTANCE_LOOKUP)
        self.assertEqual(config['dpll']['dpll0']['pin_priority_map'],
                         'GNSS_REF4P:0, SDP0_REF0N:15')
        self.assertEqual(config['dpll']['dpll1']['pin_priority_map'],
                         'GNSS_REF4P:12, SDP0_REF0N:0')

    def test_both_planes_overridable_together(self):
        s = self._minimum()
        s['dpll0_pin_priority_map'] = 'GNSS_REF4P:0, SDP0_REF0N:15'
        s['dpll1_pin_priority_map'] = 'GNSS_REF4P:12, SDP0_REF0N:0'
        config = tmpl.render_config(s, INSTANCE_LOOKUP)
        self.assertEqual(config['dpll']['dpll0']['pin_priority_map'],
                         'GNSS_REF4P:0, SDP0_REF0N:15')
        self.assertEqual(config['dpll']['dpll1']['pin_priority_map'],
                         'GNSS_REF4P:12, SDP0_REF0N:0')

    def test_default_always_ships_both_planes(self):
        # Even the sparsest config renders both dpll0 and dpll1.
        config = tmpl.render_config(self._minimum(), INSTANCE_LOOKUP)
        self.assertIn('dpll0', config['dpll'])
        self.assertIn('dpll1', config['dpll'])
        s = self._minimum()
        s['ho_0'] = '480'
        config = tmpl.render_config(s, INSTANCE_LOOKUP)
        self.assertEqual(
            config['dpll']['holdover_config']['ho_0']['ho_duration'], 480)
        # untouched tiers keep template defaults
        self.assertEqual(
            config['dpll']['holdover_config']['ho_1']['ho_duration'], 60)

    def test_bad_operation_mode_rejected(self):
        s = self._minimum()
        s['operation_mode'] = 'TURBO'
        self.assertRaises(DpllMgrConfigError,
                          tmpl.build_overlay, s, INSTANCE_LOOKUP)

    def test_non_integer_holdover_rejected(self):
        s = self._minimum()
        s['ho_0'] = 'eight-hours'
        self.assertRaises(DpllMgrConfigError,
                          tmpl.build_overlay, s, INSTANCE_LOOKUP)

    def test_output_always_complete(self):
        # Even a sparse overlay yields a daemon-complete config.
        config = tmpl.render_config(
            {'dpll0_pin_priority_map': 'GNSS_REF4P:0'}, INSTANCE_LOOKUP)
        # Should not raise; required sections present.
        tmpl.assert_output_complete(config)

    def test_empty_config_rejected_by_completeness_guard(self):
        self.assertRaises(DpllMgrConfigError,
                          tmpl.assert_output_complete, {})


class TestLayer1Validation(base.TestCase):

    def test_unknown_key_rejected(self):
        self.assertRaises(DpllMgrConfigError,
                          tmpl.validate_structured_keys,
                          {'phc_interface': 'eno8703', 'bogus_key': '1'})

    def test_all_known_keys_accepted(self):
        # Should not raise.
        tmpl.validate_structured_keys({
            'phc_interface': 'eno8703',
            'operation_mode': 'SW_BASED',
            'ptp_domain_number': '24',
            'channel_ptp_bh': 'ptp01bh',
            'channel_ts2_0': 'ts1',
            'channel_ts2_1': 'ts2',
            'dpll0_pin_priority_map': 'GNSS_REF4P:0',
            'dpll1_pin_priority_map': 'GNSS_REF4P:0',
            'ho_0': '480',
            'ho_1': '2',
            'ho_2': '3',
        })

    def test_primary_key_now_rejected(self):
        # The 'primary' hint was removed; it is no longer an accepted key.
        self.assertRaises(DpllMgrConfigError,
                          tmpl.validate_structured_keys,
                          {'phc_interface': 'eno8703', 'primary': 'gnss'})


class TestLayer2RequiredMinimum(base.TestCase):

    def test_full_minimum_accepted(self):
        tmpl.validate_required_minimum({
            'phc_interface': 'eno8703',
            'operation_mode': 'SW_BASED',
            'channel_ptp_bh': 'ptp01bh',
        })

    def test_missing_phc_interface_rejected(self):
        self.assertRaises(DpllMgrConfigError,
                          tmpl.validate_required_minimum,
                          {'operation_mode': 'SW_BASED',
                           'channel_ptp_bh': 'ptp01bh'})

    def test_missing_channel_ptp_bh_rejected(self):
        self.assertRaises(DpllMgrConfigError,
                          tmpl.validate_required_minimum,
                          {'phc_interface': 'eno8703',
                           'operation_mode': 'SW_BASED'})

    def test_dpll_maps_not_required(self):
        # Neither dpll0 nor dpll1 maps are operator-required: both ship as a
        # GNSS-primary template default and are optional overrides.
        tmpl.validate_required_minimum({
            'phc_interface': 'eno8703',
            'operation_mode': 'SW_BASED',
            'channel_ptp_bh': 'ptp01bh',
        })
