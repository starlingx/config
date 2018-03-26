#!/usr/bin/env python
#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from ceilometerclient.v2 import options
from cgtsclient.common import utils
from cgtsclient.common import wrapping_formatters
from cgtsclient import exc


def _display_event(log):

    fields = ['uuid', 'event_log_id', 'state', 'entity_type_id',
              'entity_instance_id',
              'timestamp', 'severity', 'reason_text', 'event_log_type',
              'probable_cause', 'proposed_repair_action',
              'service_affecting', 'suppression', 'suppression_status']
    data = dict([(f, getattr(log, f, '')) for f in fields])
    utils.print_dict(data, wrap=72)


@utils.arg('event_log', metavar='<uuid>',
           help="ID of the event log to show")
def do_event_show(cc, args={}):
    '''Show a event log.'''
    try:
        log = cc.event_log.get(args.event_log)
    except exc.HTTPNotFound:
        raise exc.CommandError('Event log not found: %s' % args.event_log)
    else:
        _display_event(log)


@utils.arg('-q', '--query', metavar='<QUERY>',
           help='key[op]data_type::value; list. data_type is optional, '
                'but if supplied must be string, integer, float, or boolean. '
                'Valid query fields (event_log_id, entity_type_id, '
                'entity_instance_id, severity, start, end)'
                '  Example: system event-list -q \'start=20160131 10:23:45;end=20171225\'')
@utils.arg('-l', '--limit', metavar='<NUMBER>',
           help='Maximum number of event logs to return.')
@utils.arg('--alarms',
           action='store_true',
           help='Show alarms only')
@utils.arg('--logs', action='store_true',
           help='Show logs only')
@utils.arg('--uuid', action='store_true',
           help='Include UUID in output')
@utils.arg('--include_suppress',
           action='store_true',
           help='Include suppressed alarms in output')
@utils.arg('--nopaging', action='store_true',
           help='Output is not paged')
def do_event_list(cc, args={}):
    '''List event logs.'''

    queryAsArray = options.cli_to_array(args.query)

    no_paging = args.nopaging

    alarms = False
    logs = False
    include_suppress = False

    includeUUID = args.uuid

    if args.alarms and not args.logs:
        alarms = True
    elif args.logs and not args.alarms:
        logs = True

    if args.include_suppress:
        include_suppress = True

    logs = cc.event_log.list(q=queryAsArray, limit=args.limit,
                             alarms=alarms, logs=logs, include_suppress=include_suppress)
    for l in logs:
        utils.normalize_field_data(l, ['entity_instance_id', 'reason_text'])

    # omit action initially to keep output width sane
    # (can switch over to vertical formatting when available from CLIFF)

    def hightlightEventId(event):
        suppressed = hasattr(event, "suppression_status") and event.suppression_status == "suppressed"
        if suppressed:
            value = "S({})".format(event.event_log_id)
        else:
            value = event.event_log_id
        return value

    if includeUUID:
        field_labels = ['UUID', 'Time Stamp', 'State', 'Event Log ID', 'Reason Text',
                        'Entity Instance ID', 'Severity']
        fields = ['uuid', 'timestamp', 'state', 'event_log_id', 'reason_text',
                  'entity_instance_id', 'severity']
        formatterSpec = {"uuid": wrapping_formatters.UUID_MIN_LENGTH,
                         "timestamp": .08,
                         "state": .08,
                         "event_log_id": {"formatter": hightlightEventId, "wrapperFormatter": .07},
                         "reason_text": .42,
                         "entity_instance_id": .13,
                         "severity": .12}
    else:
        field_labels = ['Time Stamp', 'State', 'Event Log ID', 'Reason Text',
                        'Entity Instance ID', 'Severity']
        fields = ['timestamp', 'state', 'event_log_id', 'reason_text',
                  'entity_instance_id', 'severity']
        # for best results, ensure width ratios add up to 1 (=100%)
        formatterSpec = {"timestamp": .08,
                         "state": .08,
                         "event_log_id": {"formatter": hightlightEventId, "wrapperFormatter": .07},
                         "reason_text": .52,
                         "entity_instance_id": .13,
                         "severity": .12}
    formatters = wrapping_formatters.build_wrapping_formatters(logs, fields,
                                                               field_labels, formatterSpec)

    utils.print_long_list(logs, fields, field_labels,
                          formatters=formatters, sortby=fields.index('timestamp'),
                          reversesort=True, no_paging=no_paging)
