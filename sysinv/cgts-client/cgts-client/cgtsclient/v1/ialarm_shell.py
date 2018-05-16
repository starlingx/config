#!/usr/bin/env python
#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from ceilometerclient.common import utils
from ceilometerclient.v2 import options
from cgtsclient.common import utils as cgts_utils
from cgtsclient.common import wrapping_formatters
from cgtsclient import exc


def _display_fault(fault):

    fields = ['uuid', 'alarm_id', 'alarm_state', 'entity_type_id', 'entity_instance_id',
              'timestamp', 'severity', 'reason_text', 'alarm_type',
              'probable_cause', 'proposed_repair_action', 'service_affecting',
              'suppression', 'suppression_status', 'mgmt_affecting', 'degrade_affecting']
    data = dict([(f, getattr(fault, f, '')) for f in fields])
    cgts_utils.print_dict(data, wrap=72)


@utils.arg('ialarm', metavar='<uuid>', help="ID of the alarm to show")
def do_alarm_show(cc, args={}):
    '''Show an active alarm.'''
    try:
        fault = cc.ialarm.get(args.ialarm)
    except exc.HTTPNotFound:
        raise exc.CommandError('Alarm not found: %s' % args.ialarm)
    else:
        _display_fault(fault)


@utils.arg('ialarm', metavar='<uuid>', help="ID of the alarm to show")
def do_alarm_delete(cc, args={}):
    '''Delete an active alarm.'''
    try:
        cc.ialarm.delete(args.ialarm)
    except exc.HTTPNotFound:
        raise exc.CommandError('Alarm not found: %s' % args.ialarm)


@utils.arg('-q', '--query', metavar='<QUERY>',
           help='key[op]data_type::value; list. data_type is optional, '
                'but if supplied must be string, integer, float, or boolean.')
@utils.arg('--uuid', action='store_true',
           help='Include UUID in output')
@utils.arg('--include_suppress',
           action='store_true',
           help='Include suppressed alarms in output')
@utils.arg('--mgmt_affecting',
           action='store_true',
           help='Include management affecting status in output')
@utils.arg('--degrade_affecting',
           action='store_true',
           help='Include degrade affecting status in output')
def do_alarm_list(cc, args={}):
    '''List all active alarms.'''

    includeUUID = args.uuid
    include_suppress = False

    if args.include_suppress:
        include_suppress = True

    include_mgmt_affecting = False
    if args.mgmt_affecting:
        include_mgmt_affecting = True

    include_degrade_affecting = False
    if args.degrade_affecting:
        include_degrade_affecting = True
    faults = cc.ialarm.list(q=options.cli_to_array(args.query), include_suppress=include_suppress)
    for f in faults:
        cgts_utils.normalize_field_data(f, ['entity_type_id', 'entity_instance_id',
                                            'reason_text', 'proposed_repair_action'])

    # omit action initially to keep output width sane
    # (can switch over to vertical formatting when available from CLIFF)

    def hightlightAlarmId(alarm):
        suppressed = hasattr(alarm, "suppression_status") and alarm.suppression_status == "suppressed"
        if suppressed:
            value = "S({})".format(alarm.alarm_id)
        else:
            value = alarm.alarm_id
        return value

    field_labels = ['Alarm ID', 'Reason Text', 'Entity ID', 'Severity', 'Time Stamp']
    fields = ['alarm_id', 'reason_text', 'entity_instance_id', 'severity', 'timestamp']
    # for best results, ensure width ratios add up to 1 (=100%)
    formatterSpec = {"alarm_id": {"formatter": hightlightAlarmId, "wrapperFormatter": .08},
                     "reason_text": .54,
                     "entity_instance_id": .15,
                     "severity": .10,
                     "timestamp": .10,
                     }

    if includeUUID:
        field_labels.insert(0, 'UUID')
        fields.insert(0, 'uuid')
        # for best results, ensure width ratios add up to 1 (=100%)
        formatterSpec['uuid'] = wrapping_formatters.UUID_MIN_LENGTH
        formatterSpec['reason_text'] -= .05
        formatterSpec['entity_instance_id'] -= .02

    if include_mgmt_affecting:
        field_labels.insert(4, 'Management Affecting')
        fields.insert(4, 'mgmt_affecting')
        # for best results, ensure width ratios add up to 1 (=100%)
        formatterSpec['mgmt_affecting'] = .08
        formatterSpec['reason_text'] -= .05
        formatterSpec['severity'] -= .03

    if include_degrade_affecting:
        field_labels.insert(5, 'Degrade Affecting')
        fields.insert(5, 'degrade_affecting')
        # for best results, ensure width ratios add up to 1 (=100%)
        formatterSpec['degrade_affecting'] = .08
        formatterSpec['reason_text'] -= .05
        formatterSpec['severity'] -= .03

    formatters = wrapping_formatters.build_wrapping_formatters(faults, fields, field_labels, formatterSpec)

    cgts_utils.print_list(faults, fields, field_labels, formatters=formatters,
                          sortby=fields.index('timestamp'), reversesort=True)


@utils.arg('--include_suppress',
           action='store_true',
           help='Include suppressed alarms in output')
def do_alarm_summary(cc, args={}):
    '''Show a summary of active alarms.'''

    include_suppress = False

    if args.include_suppress:
        include_suppress = True
    faults = cc.ialarm.summary(include_suppress)
    field_labels = ['Critical Alarms', 'Major Alarms', 'Minor Alarms', 'Warnings']
    fields = ['critical', 'major', 'minor', 'warnings']
    cgts_utils.print_list(faults, fields, field_labels)
