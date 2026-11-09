#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

"""Structured dpll-mgr configuration template, deep-merge, and derivation.

This module is the engine behind the dpll-mgr ``config`` section (story
2011783). It lets an operator supply a small handful of structured
``name=value`` tunables (``--section config``) that are merged over a shipped
boilerplate template to produce the full ``config_json`` the dpll-mgr daemon
consumes.

Design (see the structured-config spec):

* ``DEFAULT_DPLL_MGR_TEMPLATE`` carries the daemon-required boilerplate
  (``ptp_primary_attributes``, ``ql_map``, ``inputs_ql``, ``dpll_policy``,
  ``synce``, holdover defaults, GNSS-primary pin priorities). It is grounded in
  a live GNR-D config.
* ``deep_merge`` overlays the operator's structured block on top of the
  template: scalars and lists replace, nested dicts merge recursively.
* ``derive_channels`` resolves ``channel_*`` keys (naming existing ptp4l/ts2phc
  instances) into the UDS socket paths sysinv already renders
  (``/var/run/<service>-<name>``).
* ``derive_domain`` pulls ``ptp_domain_number`` from the backhaul ptp4l
  instance's ``domainNumber`` global parameter unless explicitly overridden.
* Pin names are validated against a closed, board-fixed input-pin set so a
  typo is rejected instead of silently skipped by the daemon.

This module performs *no* I/O and raises only ``DpllMgrConfigError`` for
caller-surfaced validation; it is pure and unit-testable without a running
system. Cross-reference and required-minimum checks (Layer 2) live in the API
controller; this module provides the primitives they use.
"""

import copy


class DpllMgrConfigError(Exception):
    """Raised for structured dpll-mgr config validation failures.

    Callers (API Layer-1/Layer-2) translate this into a ClientSideError; the
    renderer (Layer-3) must never let it escape (it keeps last-good instead).
    """
    pass


# ---------------------------------------------------------------------------
# Closed input-pin vocabulary (spec 3.4). Raw names are canonical and are what
# the rendered config_json contains; aliases are an optional convenience that
# resolve to the raw name. Holdover / DPLL_OUT* pins are internal states /
# output pins, NOT operator inputs, and are deliberately excluded.
# ---------------------------------------------------------------------------
VALID_INPUT_PINS = frozenset([
    'GNSS_REF4P',    # GNSS 1PPS/freq (primary)
    'GNSS_REF4N',    # GNSS (alt)
    'SDP0_REF0N',    # PTP via SDP0 (backhaul failover input / distributed 1PPS)
    'SDP2_REF0P',    # PTP via SDP2
    'RCLKA_REF1P',   # SyncE recovered clock A
    'RCLKB_REF1N',   # SyncE recovered clock B
    'SMA1_REF3P',    # SMA1 external
    'SMA3_REF3N',    # SMA3 external
    'DPLL_REF2N',    # REF2N input
])

PIN_ALIASES = {
    'gnss': 'GNSS_REF4P',
    'gnss-n': 'GNSS_REF4N',
    'pps-sdp0': 'SDP0_REF0N',
    'pps-sdp2': 'SDP2_REF0P',
    'synce-a': 'RCLKA_REF1P',
    'synce-b': 'RCLKB_REF1N',
    'sma1': 'SMA1_REF3P',
    'sma3': 'SMA3_REF3N',
    'ref2n': 'DPLL_REF2N',
}

# Pin priority is 0 (highest) .. 15 per the zl3073x engine. 0..14 select the
# pin in descending precedence (0 wins); 15 is the daemon's DISCONNECT sentinel
# (dpll_utils.c set_pin_priority Policy 1: a pin requested at priority 15 is
# moved to DPLL_PIN_STATE_DISCONNECTED and removed from arbitration, not merely
# deprioritized). This matches GNSS_CLOCK_QUALITY_DNU=15 ("Do Not Use"). 15 is a
# valid, deliberate value (e.g. disconnecting the backhaul SDP pin on the EEC/
# frequency plane), so it must pass validation rather than be rejected.
PIN_PRIORITY_MIN = 0
PIN_PRIORITY_MAX = 15

# Gearshift channels the daemon actually consumes. ptp_0/1/2 re-arm the dormant
# forward path (collectd clockClass collision risk) and are WARNED, not emitted.
VALID_CHANNELS = frozenset(['ptp_bh', 'ts2_0', 'ts2_1'])
WARN_CHANNELS = frozenset(['ptp_0', 'ptp_1', 'ptp_2'])

# Channel -> required service type of the named instance (for Layer-2 checks and
# derivation). ptp_bh is a ptp4l backhaul instance; ts2_* are ts2phc instances.
CHANNEL_SERVICE_TYPE = {
    'ptp_bh': 'ptp4l',
    'ts2_0': 'ts2phc',
    'ts2_1': 'ts2phc',
}

# Required-minimum structured keys (spec 3.6 Layer 2). The dpll0/dpll1 pin
# priority maps are NOT required from the operator: both planes ship with a
# GNSS-primary default in DEFAULT_DPLL_MGR_TEMPLATE and the operator overrides
# either/both as needed.
REQUIRED_CONFIG_KEYS = (
    'phc_interface',
    'operation_mode',
    'channel_ptp_bh',
)

VALID_OPERATION_MODES = frozenset(['SW_BASED', 'HW_BASED'])

# Flat CLI keys accepted under --section config (spec 3.5).
STRUCTURED_SCALAR_KEYS = frozenset([
    'phc_interface',
    'operation_mode',
    'ptp_domain_number',
    'channel_ptp_bh',
    'channel_ts2_0',
    'channel_ts2_1',
    'dpll0_pin_priority_map',
    'dpll1_pin_priority_map',
    'ho_0',
    'ho_1',
    'ho_2',
])


# ---------------------------------------------------------------------------
# Shipped boilerplate template (grounded in a live GNR-D GNSS-primary config).
# Operator-supplied fields (phc_interface, operation_mode, channels, dpll pin
# maps) are intentionally absent / neutral here and filled by the overlay.
# ---------------------------------------------------------------------------
DEFAULT_DPLL_MGR_TEMPLATE = {
    "channels": {},
    "dpll": {
        "dpll0": {
            # EEC / frequency plane. The backhaul SDP pin is DISCONNECTED here
            # (:15) so the frequency plane never chases the recovered backhaul
            # clock; GNSS is primary.
            "name": "zl3073x",
            "pin_priority_map": "GNSS_REF4P:0, SDP0_REF0N:15",
        },
        "dpll1": {
            # PPS / phase plane. The backhaul SDP pin is a selectable failover
            # input (:12) behind GNSS (:0) -- this is where hybrid GNSS/backhaul
            # failover is arbitrated. PTP-primary is expressed by swapping these
            # (GNSS_REF4P:12, SDP0_REF0N:0) via dpll1_pin_priority_map.
            "name": "zl3073x",
            "pin_priority_map": "GNSS_REF4P:0, SDP0_REF0N:12",
        },
        "holdover_config": {
            # Holdover-tier dwell times in MINUTES. These drive ONLY the FM
            # holdover alarm severity escalation (ho_0 -> WARNING, ho_1 ->
            # MINOR, ho_2 -> MAJOR); they do not program the DPLL or change
            # holdover quality. Defaults match the Intel reference cadence and
            # align the MAJOR escalation (240 min) with collectd's in-spec
            # clockClass holdover window (holdover_seconds = 14400 s = 4 h).
            "ho_0": {"ho_duration": 30},
            "ho_1": {"ho_duration": 60},
            "ho_2": {"ho_duration": 240},
        },
    },
    "dpll_policy": {
        "rclkb": {
            "compare_source": "QL",
            "high_prio": 9,
            "low_prio": 11,
            "tie_break": "prefer_A",
        }
    },
    "global": {
        "force_same_ql_on_fronthaul": True,
        "guard_time_ms": 5000,
        "log_level": "INFO",
        "max_step_ns": 1000000,
        "operation_mode": "SW_BASED",
        "phase_adjust_factor": 1,
        "poll_interval_ms": 1000,
        "ptp_domain_number": 24,
    },
    "inputs_ql": {
        "GNSS_REF4P": "PRTC",
        "RCLKA_REF1P": "EEC1",
        "RCLKB_REF1N": "EEC1",
    },
    "ptp": {
        "ptp_primary_attributes": {
            "GNSS_REF4P": {
                "clockAccuracy": "0x22",
                "clockClass": 6,
                "frequencyTraceable": 1,
                "timeSource": "0x20",
                "timeTraceable": 1,
            },
            "Holdover_0": {
                "clockAccuracy": "0xFE",
                "clockClass": 248,
                "frequencyTraceable": 0,
                "timeSource": "0xA0",
                "timeTraceable": 0,
            },
            "Holdover_1": {
                "clockAccuracy": "0xFE",
                "clockClass": 248,
                "frequencyTraceable": 0,
                "timeSource": "0xA0",
                "timeTraceable": 0,
            },
            "Holdover_2": {
                "clockAccuracy": "0xFE",
                "clockClass": 248,
                "frequencyTraceable": 0,
                "timeSource": "0xA0",
                "timeTraceable": 0,
            },
            "Holdover_3": {
                "clockAccuracy": "0xFE",
                "clockClass": 248,
                "frequencyTraceable": 0,
                "timeSource": "0xA0",
                "timeTraceable": 0,
            },
            "RCLKA_REF1P": {
                "clockAccuracy": "0x22",
                "clockClass": 7,
                "frequencyTraceable": 1,
                "timeSource": "0xA0",
                "timeTraceable": 1,
            },
            "RCLKB_REF1N": {
                "clockAccuracy": "0x22",
                "clockClass": 7,
                "frequencyTraceable": 1,
                "timeSource": "0xA0",
                "timeTraceable": 1,
            },
        },
        "ptp_profiles": {
            "ptp_bh": {"profile": "G.8275.1"},
        },
        "ptp_secondary_attributes": {
            "currentUtcOffset": 37,
            "currentUtcOffsetValid": 1,
            "leap59": 0,
            "leap61": 0,
            "offsetScaledLogVariance": "0x4E20",
            "ptpTimescale": 1,
        },
    },
    "ql_map": {
        "option1": {
            "EEC1": {"QL": "0xB", "extQL": "0xFF"},
            "PRC": {"QL": "0x2", "extQL": "0xFF"},
            "PRTC": {"QL": "0x2", "extQL": "0x20"},
            "SSU_A": {"QL": "0x4", "extQL": "0xFF"},
            "SSU_B": {"QL": "0x8", "extQL": "0xFF"},
            "ePRTC": {"QL": "0x2", "extQL": "0x21"},
        },
        "option2": {
            "EEC2": {"QL": "0xA", "extQL": "0xFF"},
            "PROV": {"QL": "0xE", "extQL": "0xFF"},
            "PRS": {"QL": "0x1", "extQL": "0xFF"},
            "PRTC": {"QL": "0x1", "extQL": "0x20"},
            "ST2": {"QL": "0x7", "extQL": "0xFF"},
            "ST3E": {"QL": "0xD", "extQL": "0xFF"},
            "STU": {"QL": "0x0", "extQL": "0xFF"},
            "TNC": {"QL": "0x4", "extQL": "0xFF"},
            "ePRTC": {"QL": "0x1", "extQL": "0x21"},
        },
    },
    "synce": {
        "ql_type": 1,
        "use_extended_ql": True,
    },
}

# The daemon-required sections/keys that the merged output MUST always contain,
# else config_parser.c rejects and the daemon crash-loops (the crash-loop
# failure class). Pinned here as a golden contract (spec 6.2).
REQUIRED_OUTPUT_SECTIONS = (
    'channels',
    'dpll',
    'global',
    'ptp',
)


def get_default_template():
    """Return a deep copy of the shipped template (safe to mutate)."""
    return copy.deepcopy(DEFAULT_DPLL_MGR_TEMPLATE)


def deep_merge(base, overlay):
    """Recursively merge ``overlay`` onto ``base`` and return a new dict.

    Semantics (spec 6.1):
      * nested dicts are merged key-by-key;
      * scalars and lists in ``overlay`` REPLACE the value in ``base``;
      * keys present only in ``base`` are preserved;
      * an empty overlay yields a copy of ``base`` unchanged.

    Neither input is mutated.
    """
    result = copy.deepcopy(base)
    for key, value in overlay.items():
        if (key in result
                and isinstance(result[key], dict)
                and isinstance(value, dict)):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def resolve_pin_name(pin):
    """Resolve an alias to its raw pin name; validate against the closed set.

    Returns the canonical raw pin name. Raises DpllMgrConfigError for an
    unknown pin (the key defect of the raw path, where the daemon silently
    skips PIN_SOURCE_UNKNOWN).
    """
    name = pin.strip()
    if name in PIN_ALIASES:
        return PIN_ALIASES[name]
    if name in VALID_INPUT_PINS:
        return name
    raise DpllMgrConfigError(
        "Unknown dpll pin name '%s'. Valid input pins: %s (or aliases: %s)"
        % (pin, ', '.join(sorted(VALID_INPUT_PINS)),
           ', '.join(sorted(PIN_ALIASES))))


def parse_pin_priority_map(raw_map):
    """Parse and validate a ``pin:prio`` list into an ordered list of pairs.

    Input form (CLI value): ``"GNSS_REF4P:0, SDP0_REF0N:12"`` (raw names or
    aliases). Returns ``[(raw_pin, prio_int), ...]`` with aliases resolved and
    priorities range-checked. Raises DpllMgrConfigError on malformed entries,
    unknown pins, non-integer or out-of-range priorities, or duplicate pins.
    """
    pairs = []
    seen = set()
    for entry in raw_map.split(','):
        entry = entry.strip()
        if not entry:
            continue
        if entry.count(':') != 1:
            raise DpllMgrConfigError(
                "Malformed pin priority entry '%s' (expected 'pin:priority')"
                % entry)
        pin_part, prio_part = entry.split(':', 1)
        raw_pin = resolve_pin_name(pin_part)
        try:
            prio = int(prio_part.strip())
        except (TypeError, ValueError):
            raise DpllMgrConfigError(
                "Non-integer priority '%s' for pin '%s'"
                % (prio_part.strip(), pin_part.strip()))
        if prio < PIN_PRIORITY_MIN or prio > PIN_PRIORITY_MAX:
            raise DpllMgrConfigError(
                "Pin priority %d for '%s' out of range (%d..%d)"
                % (prio, raw_pin, PIN_PRIORITY_MIN, PIN_PRIORITY_MAX))
        if raw_pin in seen:
            raise DpllMgrConfigError(
                "Duplicate pin '%s' in priority map" % raw_pin)
        seen.add(raw_pin)
        pairs.append((raw_pin, prio))
    if not pairs:
        raise DpllMgrConfigError("Empty pin priority map")
    return pairs


def normalize_pin_priority_map(raw_map):
    """Return the canonical ``"RAW_PIN:prio, ..."`` string (aliases resolved).

    This is what the rendered config_json stores (raw names canonical, spec
    3.4).
    """
    pairs = parse_pin_priority_map(raw_map)
    return ', '.join('%s:%d' % (pin, prio) for pin, prio in pairs)


def derive_uds_path(service, instance_name):
    """Return the UDS socket path sysinv renders for a PTP instance.

    Mirrors the UDS path sysinv renders in networking.py:
    ``/var/run/<service>-<name>``.

    Note: this ``<service>-<name>`` form applies only to the ptp4l/ts2phc
    channels dpll-mgr consumes; synce4l uses a different socket scheme, so
    revisit this helper before deriving a UDS path for a synce channel.
    """
    return '/var/run/' + service + '-' + instance_name


def derive_channels(channel_refs, instance_lookup):
    """Resolve ``channel_*`` instance references into a ``channels`` dict.

    Args:
      channel_refs: dict of ``{channel_key: value}`` where channel_key is one
        of ``ptp_bh``/``ts2_0``/``ts2_1`` and value is either a PTP instance
        NAME (derived) or an explicit ``uds:...`` override.
      instance_lookup: dict of ``{instance_name: service_type}`` for the
        resolved per-host sibling instances (ptp4l/ts2phc), used to derive the
        socket path and validate the service type.

    Returns a ``channels`` dict: ``{channel: {"call_channel": "uds:..."}}``.
    Raises DpllMgrConfigError if a named instance is missing or has the wrong
    service type (Layer-2 cross-reference). An explicit ``uds:`` value is used
    verbatim (override).
    """
    channels = {}
    for channel_key, value in channel_refs.items():
        if channel_key not in CHANNEL_SERVICE_TYPE:
            raise DpllMgrConfigError(
                "Unknown channel '%s' (valid: %s)"
                % (channel_key, ', '.join(sorted(CHANNEL_SERVICE_TYPE))))
        value = value.strip()
        if value.startswith('uds:'):
            # Explicit override; trust operator.
            channels[channel_key] = {'call_channel': value}
            continue
        instance_name = value
        expected_service = CHANNEL_SERVICE_TYPE[channel_key]
        actual_service = instance_lookup.get(instance_name)
        if actual_service is None:
            raise DpllMgrConfigError(
                "Channel '%s' references instance '%s' which does not exist "
                "on this host" % (channel_key, instance_name))
        if actual_service != expected_service:
            raise DpllMgrConfigError(
                "Channel '%s' requires a '%s' instance but '%s' is a '%s' "
                "instance" % (channel_key, expected_service, instance_name,
                              actual_service))
        uds = derive_uds_path(actual_service, instance_name)
        channels[channel_key] = {'call_channel': 'uds:' + uds}
    return channels


def build_overlay(structured, instance_lookup, domain_from_backhaul=None):
    """Turn a flat ``config``-section dict into a nested config_json overlay.

    Args:
      structured: flat ``{key: value}`` from ``--section config`` (string
        values, as stored). Keys per STRUCTURED_SCALAR_KEYS.
      instance_lookup: ``{instance_name: service_type}`` for derivation.
      domain_from_backhaul: optional int domainNumber derived from the backhaul
        ptp4l instance; used when ``ptp_domain_number`` is not given explicitly.

    Returns a nested dict suitable for ``deep_merge`` over the template.
    Raises DpllMgrConfigError on validation failures (vocab/format and
    cross-reference). Does NOT enforce required-minimum — that is the API's
    Layer-2 responsibility, which calls validate_required_minimum separately.
    """
    overlay = {}

    # --- global scalars ---
    g = {}
    if 'phc_interface' in structured:
        g['phc_interface'] = structured['phc_interface']
    if 'operation_mode' in structured:
        mode = structured['operation_mode']
        if mode not in VALID_OPERATION_MODES:
            raise DpllMgrConfigError(
                "Invalid operation_mode '%s' (expected one of: %s)"
                % (mode, ', '.join(sorted(VALID_OPERATION_MODES))))
        g['operation_mode'] = mode
    if 'ptp_domain_number' in structured:
        g['ptp_domain_number'] = _coerce_int(
            structured['ptp_domain_number'], 'ptp_domain_number')
    elif domain_from_backhaul is not None:
        g['ptp_domain_number'] = int(domain_from_backhaul)
    if g:
        overlay['global'] = g

    # --- channels (derive from named instances) ---
    channel_refs = {}
    for ck in ('ptp_bh', 'ts2_0', 'ts2_1'):
        key = 'channel_' + ck
        if key in structured:
            channel_refs[ck] = structured[key]
    # warn-only channels are handled by the caller (CLI/API); strip here so we
    # never emit ptp_0/1/2.
    if channel_refs:
        overlay['channels'] = derive_channels(channel_refs, instance_lookup)

    # --- dpll pin priority maps ---
    dpll = {}
    dpll0_map = None
    if 'dpll0_pin_priority_map' in structured:
        dpll0_map = normalize_pin_priority_map(
            structured['dpll0_pin_priority_map'])
        dpll['dpll0'] = {
            'name': 'zl3073x',
            'pin_priority_map': dpll0_map,
        }

    dpll1_map = None
    if 'dpll1_pin_priority_map' in structured:
        dpll1_map = normalize_pin_priority_map(
            structured['dpll1_pin_priority_map'])
    if dpll1_map is not None:
        dpll['dpll1'] = {
            'name': 'zl3073x',
            'pin_priority_map': dpll1_map,
        }

    # --- holdover tiers (minutes) ---
    ho = {}
    for hk in ('ho_0', 'ho_1', 'ho_2'):
        if hk in structured:
            ho[hk] = {'ho_duration': _coerce_int(structured[hk], hk)}
    if ho:
        dpll['holdover_config'] = ho

    if dpll:
        overlay['dpll'] = dpll

    return overlay


def validate_required_minimum(structured):
    """Raise DpllMgrConfigError if any required-minimum key is absent.

    Required (spec 3.6 Layer 2): phc_interface, operation_mode, channel_ptp_bh.
    The dpll0/dpll1 pin priority maps are supplied by the shipped template
    default (GNSS-primary) and are optional operator overrides.
    """
    missing = [k for k in REQUIRED_CONFIG_KEYS if k not in structured]
    if missing:
        raise DpllMgrConfigError(
            "dpll-mgr structured config missing required key(s): %s"
            % ', '.join(missing))


def validate_structured_keys(structured):
    """Raise DpllMgrConfigError for any unknown flat ``config`` key (Layer 1)."""
    unknown = sorted(set(structured) - STRUCTURED_SCALAR_KEYS)
    if unknown:
        raise DpllMgrConfigError(
            "Unknown dpll-mgr config key(s): %s (valid: %s)"
            % (', '.join(unknown), ', '.join(sorted(STRUCTURED_SCALAR_KEYS))))


def assert_output_complete(config_json):
    """Raise DpllMgrConfigError if the merged output is missing a required
    section (regression guard for the crash-loop class, spec 6.2)."""
    if not config_json:
        raise DpllMgrConfigError("Rendered dpll-mgr config_json is empty")
    missing = [s for s in REQUIRED_OUTPUT_SECTIONS if s not in config_json]
    if missing:
        raise DpllMgrConfigError(
            "Rendered dpll-mgr config_json missing required section(s): %s"
            % ', '.join(missing))
    if 'holdover_config' not in config_json.get('dpll', {}):
        raise DpllMgrConfigError(
            "Rendered dpll-mgr config_json missing dpll.holdover_config")
    if 'dpll0' not in config_json.get('dpll', {}):
        raise DpllMgrConfigError(
            "Rendered dpll-mgr config_json missing dpll.dpll0")
    if 'dpll1' not in config_json.get('dpll', {}):
        raise DpllMgrConfigError(
            "Rendered dpll-mgr config_json missing dpll.dpll1")


def render_config(structured, instance_lookup=None,
                  domain_from_backhaul=None):
    """Build the full config_json from a structured ``config`` block.

    Merges the derived overlay over the shipped template and returns the
    complete config_json dict. This is the primary path used by the renderer
    (C3). It does NOT enforce required-minimum (Layer 2 does, before apply);
    it DOES guarantee output completeness.
    """
    if instance_lookup is None:
        instance_lookup = {}
    overlay = build_overlay(structured, instance_lookup, domain_from_backhaul)
    merged = deep_merge(DEFAULT_DPLL_MGR_TEMPLATE, overlay)
    assert_output_complete(merged)
    return merged


def _coerce_int(value, key):
    """Coerce a stored string value to int, raising a clear error."""
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        raise DpllMgrConfigError(
            "Value for '%s' must be an integer, got '%s'" % (key, value))
