########################################################################
#
# Copyright (c) 2021-2023, 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

import json
import sys

from cgtsclient.common import constants
from cgtsclient.common import unicast_master_table as umt
from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils
from cgtsclient.v1 import ptp_instance as ptp_instance_utils


def _print_ptp_instance_show(ptp_instance_obj):
    fields = ['uuid', 'name', 'service', 'hostnames', 'parameters',
              'created_at']
    data = [(f, getattr(ptp_instance_obj, f, '')) for f in fields]
    utils.print_tuple_list(
        data, formatters={'parameters': utils.truncate_json_value})


@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP instance")
@utils.arg('--to-json', action='store_true', default=False,
           help='Output in JSON format to stdout')
@utils.arg('--to-file', action='store_true', default=False,
           help='Output JSON to auto-generated file in /tmp')
def do_ptp_instance_show(cc, args):
    """Show PTP instance attributes."""
    ptp_instance = ptp_instance_utils._find_ptp_instance(cc, args.nameoruuid)
    if utils.output_as_json(ptp_instance._info, args,
                            'ptp-instance-show_' + args.nameoruuid):
        return
    _print_ptp_instance_show(ptp_instance)


def _print_ptp_instance_list(ptp_instance_list):
    field_labels = ['uuid', 'name', 'service']
    fields = ['uuid', 'name', 'service']
    utils.print_list(ptp_instance_list, fields, field_labels)


@utils.arg('--to-json', action='store_true', default=False,
           help='Output in JSON format to stdout')
@utils.arg('--to-file', action='store_true', default=False,
           help='Output JSON to auto-generated file in /tmp')
def do_ptp_instance_list(cc, args):
    """List all PTP instances."""
    ptp_instances = cc.ptp_instance.list()
    if utils.output_as_json([i._info for i in ptp_instances], args,
                            'ptp-instance-list'):
        return
    _print_ptp_instance_list(ptp_instances)


@utils.arg('name',
           metavar='<name>',
           help="Name of PTP instance [REQUIRED]")
@utils.arg('service',
           metavar='<service type>',
           choices=[
               'ptp4l', 'phc2sys', 'ts2phc', 'clock', 'synce4l',
               constants.PTP_INSTANCE_TYPE_GNSS_MONITOR,
               constants.PTP_INSTANCE_TYPE_DPLL_MGR
           ],
           help="Service type [REQUIRED]")
def do_ptp_instance_add(cc, args):
    """Add a PTP instance."""

    field_list = ['name', 'service']

    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    ptp_instance = cc.ptp_instance.create(**data)
    uuid = getattr(ptp_instance, 'uuid', '')
    try:
        ptp_instance = cc.ptp_instance.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('PTP instance just created not found: %s' %
                               uuid)
    _print_ptp_instance_show(ptp_instance)


@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP instance")
def do_ptp_instance_delete(cc, args):
    """Delete a PTP instance."""
    ptp_instance = ptp_instance_utils._find_ptp_instance(cc, args.nameoruuid)
    uuid = ptp_instance.uuid
    cc.ptp_instance.delete(uuid)
    print('Deleted PTP instance: %s' % uuid)


def _validate_dpll_mgr_parameters(section, parameters):
    """Validate dpll-mgr PTP instance parameter add requests.

    The 'monitoring' section carries collectd-consumed params (e.g.
    clockclass_passthrough) rendered to instance-monitoring.conf, separate
    from the config_json schema sections enumerated in
    PTP_INSTANCE_TYPE_DPLL_MGR_SUPPORTED_SECTIONS.
    """
    if section == 'monitoring':
        for param_keypair in parameters:
            if param_keypair.find("=") < 0:
                raise exc.CommandError(
                    f"Bad PTP parameter keypair: {param_keypair}")
            (param_name, _param_value) = param_keypair.split("=", 1)
            if param_name not in \
                    constants.PTP_INSTANCE_TYPE_DPLL_MGR_MONITORING_PARAMETERS:
                raise exc.CommandError(
                    f"Parameter '{param_name}' is not supported for dpll-mgr "
                    f"section=monitoring. Supported: "
                    f"{constants.PTP_INSTANCE_TYPE_DPLL_MGR_MONITORING_PARAMETERS}")
    elif section == 'config':
        _validate_dpll_mgr_config_section(parameters)
    elif section not in constants.PTP_INSTANCE_TYPE_DPLL_MGR_SUPPORTED_SECTIONS:
        raise exc.CommandError(
            f"Section '{section}' is not supported for dpll-mgr. "
            f"Supported: {constants.PTP_INSTANCE_TYPE_DPLL_MGR_SUPPORTED_SECTIONS} "
            f"(or 'monitoring')")


# Closed input-pin vocabulary for the structured 'config' section (mirrors
# sysinv.common.dpll_mgr_config_template; cgts-client cannot import the sysinv
# package, so the set is duplicated here for client-side rejection).
_DPLL_MGR_VALID_PINS = {
    'GNSS_REF4P', 'GNSS_REF4N', 'SDP0_REF0N', 'SDP2_REF0P', 'RCLKA_REF1P',
    'RCLKB_REF1N', 'SMA1_REF3P', 'SMA3_REF3N', 'DPLL_REF2N',
}
_DPLL_MGR_PIN_ALIASES = {
    'gnss': 'GNSS_REF4P', 'gnss-n': 'GNSS_REF4N', 'pps-sdp0': 'SDP0_REF0N',
    'pps-sdp2': 'SDP2_REF0P', 'synce-a': 'RCLKA_REF1P', 'synce-b': 'RCLKB_REF1N',
    'sma1': 'SMA1_REF3P', 'sma3': 'SMA3_REF3N', 'ref2n': 'DPLL_REF2N',
}
_DPLL_MGR_WARN_CHANNELS = {'channel_ptp_0', 'channel_ptp_1', 'channel_ptp_2'}


def _validate_dpll_mgr_config_section(parameters):
    """Client-side vocabulary/format validation for the structured 'config'
    section (story 2011783). Rejects an unknown flat key or pin and an
    out-of-range priority; warns (does not reject) on ptp_0/1/2 channels. The
    authoritative checks run server-side (sysinv API Layer 1/2).
    """
    for param_keypair in parameters:
        if param_keypair.find("=") < 0:
            raise exc.CommandError(
                f"Bad PTP parameter keypair: {param_keypair}")
        (param_name, param_value) = param_keypair.split("=", 1)

        if param_name in _DPLL_MGR_WARN_CHANNELS:
            print(f"WARNING: channel '{param_name}' configures a ptp_0/1/2 "
                  f"forward channel, which StarlingX does not act on and may "
                  f"re-arm a collectd clockClass collision. Prefer "
                  f"channel_ptp_bh / channel_ts2_0 / channel_ts2_1.")
            continue

        if param_name not in \
                constants.PTP_INSTANCE_TYPE_DPLL_MGR_STRUCTURED_KEYS:
            raise exc.CommandError(
                f"Key '{param_name}' is not supported for dpll-mgr "
                f"section=config. Supported: "
                f"{constants.PTP_INSTANCE_TYPE_DPLL_MGR_STRUCTURED_KEYS}")

        if param_name in ('dpll0_pin_priority_map', 'dpll1_pin_priority_map'):
            _validate_dpll_mgr_pin_map(param_name, param_value)
        elif param_name == 'operation_mode':
            if param_value not in ('SW_BASED', 'HW_BASED'):
                raise exc.CommandError(
                    f"Invalid operation_mode '{param_value}' "
                    f"(expected SW_BASED or HW_BASED)")
        elif param_name in ('ho_0', 'ho_1', 'ho_2', 'ptp_domain_number'):
            try:
                int(param_value)
            except (ValueError, TypeError):
                raise exc.CommandError(
                    f"Value for '{param_name}' must be an integer, "
                    f"got '{param_value}'")


def _validate_dpll_mgr_pin_map(param_name, raw_map):
    """Validate a pin:prio list client-side (unknown pin / bad priority)."""
    entries = [e.strip() for e in raw_map.split(',') if e.strip()]
    if not entries:
        raise exc.CommandError(f"Empty pin priority map for {param_name}")
    for entry in entries:
        if entry.count(':') != 1:
            raise exc.CommandError(
                f"Malformed pin priority entry '{entry}' "
                f"(expected 'pin:priority')")
        pin, prio = entry.split(':', 1)
        pin = pin.strip()
        if (pin not in _DPLL_MGR_VALID_PINS
                and pin not in _DPLL_MGR_PIN_ALIASES):
            raise exc.CommandError(
                f"Unknown dpll pin name '{pin}'. Valid input pins: "
                f"{sorted(_DPLL_MGR_VALID_PINS)} "
                f"(or aliases {sorted(_DPLL_MGR_PIN_ALIASES)})")
        try:
            value = int(prio.strip())
            if value < 0 or value > 15:
                raise ValueError()
        except (ValueError, TypeError):
            raise exc.CommandError(
                f"Invalid priority '{prio.strip()}' for pin '{pin}' "
                f"(must be integer 0-15; 15 disconnects the pin)")


def _ptp_instance_parameter_op(cc, op, instance, section, parameters):
    if len(parameters) == 0:
        raise exc.CommandError('Missing PTP parameter')
    ptp_instance = ptp_instance_utils._find_ptp_instance(cc, instance)

    # check for supported parameters in case of gnss-monitor type
    if (ptp_instance.service == constants.PTP_INSTANCE_TYPE_GNSS_MONITOR and op == "add"):
        for param_keypair in parameters:
            if param_keypair.find("=") < 0:
                raise exc.CommandError(f"Bad PTP parameter keypair: {param_keypair}")
            (param_name, param_value) = param_keypair.split("=", 1)

            if param_name not in constants.PTP_INSTANCE_TYPE_GNSS_MONITOR_SUPPORTED_PARAMETERS:
                raise exc.CommandError(
                    f"Parameter {param_name} is not supported. Supported parameters:"
                    f"{constants.PTP_INSTANCE_TYPE_GNSS_MONITOR_SUPPORTED_PARAMETERS}"
                )
    # check section whitelist for dpll-mgr type
    elif ptp_instance.service == constants.PTP_INSTANCE_TYPE_DPLL_MGR and op == "add":
        _validate_dpll_mgr_parameters(section, parameters)
    # validate section=dpll parameters for clock instance type
    elif (ptp_instance.service == constants.PTP_INSTANCE_TYPE_CLOCK
          and section == 'dpll' and op == "add"):
        for param_keypair in parameters:
            if param_keypair.find("=") < 0:
                raise exc.CommandError(f"Bad PTP parameter keypair: {param_keypair}")
            (param_name, param_value) = param_keypair.split("=", 1)
            if param_name not in constants.PTP_INSTANCE_TYPE_CLOCK_DPLL_SUPPORTED_PARAMS:
                raise exc.CommandError(
                    f"Parameter '{param_name}' is not supported for clock section=dpll. "
                    f"Supported: {constants.PTP_INSTANCE_TYPE_CLOCK_DPLL_SUPPORTED_PARAMS}")
            if param_name.startswith('pin_priority_'):
                try:
                    prio = int(param_value)
                    if prio < 0 or prio > 14:
                        raise ValueError()
                except (ValueError, TypeError):
                    raise exc.CommandError(
                        f"Invalid priority value '{param_value}' for {param_name}. "
                        f"Must be integer 0-14.")
            elif param_name.startswith('pin_state_'):
                if param_value not in constants.PTP_INSTANCE_TYPE_CLOCK_DPLL_VALID_STATES:
                    raise exc.CommandError(
                        f"Invalid state '{param_value}' for {param_name}. "
                        f"Must be one of: {constants.PTP_INSTANCE_TYPE_CLOCK_DPLL_VALID_STATES}")
    # sanity check for PTP4l's unicast_master_table sectional parameters
    elif (
        ptp_instance.service == constants.PTP_INSTANCE_TYPE_PTP4L
        and section.startswith("unicast_master_table")
    ):
        umt_data = umt.UnicastMasterTable()
        for param_keypair in parameters:
            if param_keypair.find("=") < 0:
                raise exc.CommandError(f"Bad PTP parameter keypair: {param_keypair}")
            (param_name, param_value) = param_keypair.split("=", 1)

            if param_name not in constants.PTP_INSTANCE_TYPE_PTP4L_UMT_SUPPORTED_PARAMETERS:
                raise exc.CommandError(
                    f"Parameter {param_name} is not supported. Supported parameters:"
                    f"{constants.PTP_INSTANCE_TYPE_PTP4L_UMT_SUPPORTED_PARAMETERS}"
                )
            # compliance to value format
            err_msg = umt_data.add(param_name, param_value)
            if err_msg is not None:
                raise exc.CommandError(
                    f"Bad PTP parameter keypair: {param_keypair} error: {err_msg}"
                )

        # check compliance
        err_msg = umt_data.comply()
        if err_msg is not None:
            raise exc.CommandError(f"Bad PTP parameter keypair, error: {err_msg}")

    patch = []
    for parameter in parameters:
        patch.append({'op': op,
                      'path': '/ptp_parameters/-',
                      'section': section,
                      'value': parameter})
    ptp_instance = cc.ptp_instance.update(ptp_instance.uuid, patch)
    _print_ptp_instance_show(ptp_instance)


def _ptp_instance_parameter_from_json(cc, instance, filepath=None,
                                      json_string=None):
    """Import dpll-mgr config from JSON. Replaces existing config_json."""

    ptp_instance = ptp_instance_utils._find_ptp_instance(cc, instance)

    if ptp_instance.service != constants.PTP_INSTANCE_TYPE_DPLL_MGR:
        raise exc.CommandError(
            '--from-file/--from-json only supported for dpll-mgr instances')

    # Read JSON from file or inline string
    if filepath:
        try:
            with open(filepath, 'r') as f:
                config = json.load(f)
        except (IOError, json.JSONDecodeError) as e:
            raise exc.CommandError(f"Failed to read config file: {e}")
    else:
        try:
            config = json.loads(json_string)
        except (json.JSONDecodeError, ValueError) as e:
            raise exc.CommandError(f"Invalid JSON: {e}")

    # Validate sections
    for section in config.keys():
        if section not in \
                constants.PTP_INSTANCE_TYPE_DPLL_MGR_SUPPORTED_SECTIONS:
            raise exc.CommandError(
                f"Unsupported section '{section}'. Supported: "
                f"{constants.PTP_INSTANCE_TYPE_DPLL_MGR_SUPPORTED_SECTIONS}")

    # Serialize JSON (compact)
    json_value = json.dumps(config, separators=(',', ':'))
    if len(json_value) > 50000:
        msg = (f"WARNING: config_json is {len(json_value)} characters. "
               "Large configs may impact performance.")
        print(msg, file=sys.stderr)

    # Add/replace config_json parameter (server handles upsert)
    patch = [{'op': 'add',
              'path': '/ptp_parameters/-',
              'section': 'config_json',
              'value': f"config_json={json_value}"}]
    ptp_instance = cc.ptp_instance.update(ptp_instance.uuid, patch)
    _print_ptp_instance_show(ptp_instance)


@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP instance")
@utils.arg('--section',
           metavar='<section_name>',
           default='global',
           help='Section name of PTP parameters (default: global)')
@utils.arg('--from-file',
           metavar='<json_file>',
           default=None,
           help='Import config from JSON file (replaces existing, '
                'dpll-mgr only)')
@utils.arg('--from-json',
           metavar='<json_string>',
           default=None,
           help='Import config from inline JSON string (replaces existing, '
                'dpll-mgr only)')
@utils.arg('parameters',
           metavar='<name=value>',
           nargs='*',
           action='append',
           default=[],
           help="PTP parameter to add")
def do_ptp_instance_parameter_add(cc, args):
    """Add parameter(s) to a PTP instance."""
    if args.from_file or args.from_json:
        _ptp_instance_parameter_from_json(cc, args.nameoruuid,
                                          filepath=args.from_file,
                                          json_string=args.from_json)
    else:
        if not args.parameters or not args.parameters[0]:
            raise exc.CommandError('Missing PTP parameter')
        _ptp_instance_parameter_op(cc, op='add', instance=args.nameoruuid,
                                   section=args.section,
                                   parameters=args.parameters[0])


@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP instance")
@utils.arg('--section',
           metavar='<section_name>',
           default='global',
           help='Section name of PTP parameters (default: global)')
@utils.arg('parameters',
           metavar='<name=value or uuid>',
           nargs='+',
           action='append',
           default=[],
           help="PTP parameter to remove (name=value or parameter UUID)")
def do_ptp_instance_parameter_delete(cc, args):
    """Delete parameter(s) from a PTP instance."""
    _ptp_instance_parameter_op(cc, op='remove', instance=args.nameoruuid,
                               section=args.section,
                               parameters=args.parameters[0])


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('--to-json', action='store_true', default=False,
           help='Output in JSON format to stdout')
@utils.arg('--to-file', action='store_true', default=False,
           help='Output JSON to auto-generated file in /tmp')
def do_host_ptp_instance_list(cc, args):
    """List PTP instances on host."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    ptp_instances = cc.ptp_instance.list_by_host(ihost.uuid)
    if utils.output_as_json([i._info for i in ptp_instances], args,
                            'host-ptp-instance-list_'
                            + args.hostnameorid):
        return
    _print_ptp_instance_list(ptp_instances)


def _host_ptp_instance_op(cc, op, host, instance):
    ihost = ihost_utils._find_ihost(cc, host)
    ptp_instance = ptp_instance_utils._find_ptp_instance(cc,
                                                         instance)
    patch = [{'op': op, 'path': '/ptp_instances/-', 'value': ptp_instance.id}]
    cc.ihost.update(ihost.uuid, patch)

    ptp_instances = cc.ptp_instance.list_by_host(ihost.uuid)
    _print_ptp_instance_list(ptp_instances)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP instance to assign")
def do_host_ptp_instance_assign(cc, args):
    """Associate PTP instance(s) to host."""
    _host_ptp_instance_op(cc, op='add', host=args.hostnameorid,
                          instance=args.nameoruuid)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP instance to remove")
def do_host_ptp_instance_remove(cc, args):
    """Disassociate PTP instance(s) from host."""
    _host_ptp_instance_op(cc, op='remove', host=args.hostnameorid,
                          instance=args.nameoruuid)


def do_ptp_instance_apply(cc, args):
    """Apply the PTP Instance config."""

    cc.ptp_instance.apply()

    print('Applying the PTP Instance configuration')
