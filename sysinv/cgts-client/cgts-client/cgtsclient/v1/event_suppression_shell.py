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


def _get_display_config(includeUUID):
    if includeUUID:
        field_labels = ['UUID', 'Event ID', 'Status']
        fields = ['uuid', 'alarm_id', 'suppression_status']

        formatterSpec = {"uuid": 40,
                         "alarm_id": 25,
                         "suppression_status": 15}
    else:
        field_labels = ['Event ID', 'Status']
        fields = ['alarm_id', 'suppression_status']

        formatterSpec = {"alarm_id": 25,
                         "suppression_status": 15}

    return {
        'field_labels': field_labels,
        'fields': fields,
        'formatterSpec': formatterSpec
    }


def _display_event_suppression(log):
    fields = ['uuid', 'alarm_id', 'description', 'suppression_status']
    data = dict([(f, getattr(log, f, '')) for f in fields])
    utils.print_dict(data, wrap=72)


def _get_suppressed_alarms_tuples(data):
    """Split the suppressed_alarms field from a comma separated list alarm id's to a

    real list of (start, end) tuples. ??????
    """

    suppressed_alarms = []
    for a in data['suppressed_alarms'].split(',') or []:
        suppressed_alarms.append((a))
    return suppressed_alarms


def _event_suppression_list(cc, include_unsuppressed=False):
    query = 'suppression_status=string::suppressed'
    queryAsArray = []

    if include_unsuppressed:
        query = None

    if query is not None:
        queryAsArray = options.cli_to_array(query)

    event_suppression_list = cc.event_suppression.list(q=queryAsArray)
    return event_suppression_list


def print_event_suppression_list(cc, no_paging, includeUUID):

    event_suppression_list = _event_suppression_list(cc, include_unsuppressed=False)

    displayCFG = _get_display_config(includeUUID)

    field_labels = displayCFG['field_labels']
    fields = displayCFG['fields']
    formatterSpec = displayCFG['formatterSpec']

    formatters = wrapping_formatters.build_wrapping_formatters(event_suppression_list, fields,
                                                               field_labels, formatterSpec)

    utils.print_long_list(event_suppression_list, fields, field_labels, formatters=formatters, sortby=1,
                          reversesort=False, no_paging=no_paging)


def event_suppression_update(cc, data, suppress=False):
        event_suppression_list = _event_suppression_list(cc, include_unsuppressed=True)

        alarm_id_list = []
        for alarm_id in data['alarm_id'].split(',') or []:
            alarm_id_list.append(alarm_id)

        if suppress:
            patch_value = 'suppressed'
        else:
            patch_value = 'unsuppressed'

        patch = []
        for event_id in event_suppression_list:
            if event_id.alarm_id in alarm_id_list:
                print "Alarm ID: {} {}.".format(event_id.alarm_id, patch_value)
                uuid = event_id.uuid
                patch.append(dict(path='/' + 'suppression_status', value=patch_value, op='replace'))
                cc.event_suppression.update(uuid, patch)


@utils.arg('--include-unsuppressed', action='store_true',
           help='Include unsuppressed Event ID\'s')
@utils.arg('--uuid', action='store_true',
           help='Include UUID in output')
@utils.arg('--nopaging', action='store_true',
           help='Output is not paged')
def do_event_suppress_list(cc, args={}):
    '''List Suppressed Event ID's '''

    include_unsuppressed = args.include_unsuppressed

    includeUUID = args.uuid

    event_suppression_list = _event_suppression_list(cc, include_unsuppressed=include_unsuppressed)

    no_paging = args.nopaging

    displayCFG = _get_display_config(includeUUID)

    field_labels = displayCFG['field_labels']
    fields = displayCFG['fields']
    formatterSpec = displayCFG['formatterSpec']

    formatters = wrapping_formatters.build_wrapping_formatters(event_suppression_list, fields,
                                                               field_labels, formatterSpec)

    utils.print_long_list(event_suppression_list, fields, field_labels, formatters=formatters, sortby=1,
                          reversesort=False, no_paging=no_paging)


@utils.arg('--alarm_id',
           metavar='<alarm_id>,...',
           help="The alarm_id list (comma separated) of alarm ID's to suppress.")
@utils.arg('--nopaging', action='store_true',
           help='Output is not paged')
@utils.arg('--uuid', action='store_true',
           help='Include UUID in output')
def do_event_suppress(cc, args={}):
    '''Suppress specified Event ID's.'''

    field_list = ['alarm_id']

    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    if 'alarm_id' in data:
        event_suppression_update(cc, data, suppress=True)

    no_paging = args.nopaging
    includeUUID = args.uuid

    print_event_suppression_list(cc, no_paging, includeUUID)


@utils.arg('--alarm_id',
           metavar='<alarm_id>,...',
           help="The alarm_id list (comma separated) of alarm ID's to unsuppress.")
@utils.arg('--nopaging', action='store_true',
           help='Output is not paged')
@utils.arg('--uuid', action='store_true',
           help='Include UUID in output')
def do_event_unsuppress(cc, args):
    '''Unsuppress specified Event ID's.'''

    field_list = ['alarm_id']
    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    if 'alarm_id' in data:
        event_suppression_update(cc, data, suppress=False)

    no_paging = args.nopaging
    includeUUID = args.uuid

    print_event_suppression_list(cc, no_paging, includeUUID)


@utils.arg('--nopaging', action='store_true',
           help='Output is not paged')
@utils.arg('--uuid', action='store_true',
           help='Include UUID in output')
def do_event_unsuppress_all(cc, args):
    '''Unsuppress all Event ID's.'''
    patch = []
    alarms_suppression_list = _event_suppression_list(cc, include_unsuppressed=True)

    for alarm_type in alarms_suppression_list:
        suppression_status = alarm_type.suppression_status

        if suppression_status == 'suppressed':
            uuid = alarm_type.uuid
            patch.append(dict(path='/' + 'suppression_status', value='unsuppressed', op='replace'))
            print "Alarm ID: {} unsuppressed.".format(alarm_type.alarm_id)
            cc.event_suppression.update(uuid, patch)

    no_paging = args.nopaging
    includeUUID = args.uuid

    print_event_suppression_list(cc, no_paging, includeUUID)
