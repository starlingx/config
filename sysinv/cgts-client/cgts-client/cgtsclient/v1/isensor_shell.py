#
# Copyright (c) 2013-2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils
from collections import OrderedDict


def _print_isensor_show(isensor):
    fields = ['sensorname', 'path',
              'sensortype', 'datatype',
              'status', 'state', 'state_requested',
              'audit_interval',
              'sensor_action_requested', 'actions_minor', 'actions_major',
              'actions_critical', 'suppress', 'algorithm', 'capabilities',
              'created_at', 'updated_at', 'uuid']

    fields_analog = ['unit_base', 'unit_modifier', 'unit_rate',
                     't_minor_lower', 't_minor_upper',
                     't_major_lower', 't_major_upper',
                     't_critical_lower', 't_critical_upper']

    labels = ['sensorname', 'path',
              'sensortype', 'datatype',
              'status', 'state', 'state_requested',
              'audit_interval',
              'sensor_action_requested', 'actions_minor', 'actions_major',
              'actions_critical', 'suppress', 'algorithm', 'capabilities',
              'created_at', 'updated_at', 'uuid']

    labels_analog = ['unit_base', 'unit_modifier', 'unit_rate',
                     't_minor_lower', 't_minor_upper',
                     't_major_lower', 't_major_upper',
                     't_critical_lower', 't_critical_upper']

    datatype = getattr(isensor, 'datatype') or ""
    if datatype == 'analog':
        fields.extend(fields_analog)
        labels.extend(labels_analog)

    data = dict([(f, getattr(isensor, f, '')) for f in fields])

    ordereddata = OrderedDict(sorted(data.items(), key=lambda t: t[0]))
    # utils.print_tuple_list(ordereddata, labels)
    utils.print_dict(ordereddata, wrap=72)


def _find_sensor(cc, ihost, sensor_uuid):
    sensors = cc.isensor.list(ihost.uuid)
    for p in sensors:
        if p.uuid == sensor_uuid:
            break
    else:
        raise exc.CommandError('Sensor not found: host %s sensor %s' %
                               (ihost.id, sensor_uuid))
    return p


@utils.arg('hostnameorid',
           metavar='<hostnameorid>',
           help='Name or ID of host associated with this sensor.')
@utils.arg('sensorname',
           metavar='<sensorname>',
           help='Name of the sensor.')
@utils.arg('sensortype',
           metavar='<sensortype>',
           choices=['temperature', 'voltage', 'power',
                    'current', 'tachometer', 'pressure',
                    'airflow', 'watchdog'],
           help='sensortype of the sensor.')
@utils.arg('datatype',
           metavar='<datatype>',
           choices=['discrete', 'analog'],
           help='datatype of sensor: "discrete" or "analog"')
@utils.arg('-p', '--actions_possible',
           metavar='<actions_possible>',
           help="Possible Actions for this sensor.  CSV format.")
@utils.arg('-m', '--actions_major',
           metavar='<actions_major>',
           help='Major Actions of the sensor. CSV format.')
@utils.arg('-c', '--actions_critical',
           metavar='<actions_critical>',
           help='Critical Actions of the sensor. CSV format.')
@utils.arg('-tcrl', '--t_critical_lower',
           metavar='<t_critical_lower>',
           help='Critical Lower Threshold of the sensor.')
@utils.arg('-tcru', '--t_critical_upper',
           metavar='<t_critical_upper>',
           help='Critical Upper Threshold of the sensor.')
# @utils.arg('-l', '--thresholds',
#        metavar='<thresholds>',
#        help='Thresholds. CSV of values: "t_minor_lower, t_minor_upper,
#             ' t_major_lower, '
#             't_major_upper', 't_critical_lower', 't_critical_upper. Applies'
#             'to sensortype=analog only.')
def donot_host_sensor_add(cc, args):
    """Add a new sensor to a host."""
    field_list = ['sensorname', 'sensortype', 'datatype',
                  'actions_minor', 'actions_major', 'actions_critical',
                  'actions_possible',
                  't_minor_lower', 't_minor_upper',
                  't_major_lower', 't_major_upper',
                  't_critical_lower', 't_critical_upper',
                  'suppress']

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    fields = dict((k, v) for (k, v) in vars(args).items()
                  if k in field_list and not (v is None))

    fields['host_uuid'] = ihost.uuid

    # if 'sensortype' in user_specified_fields.keys():
    #     if args.iftype == 'analog':

    isensor = cc.isensor.create(**fields)
    suuid = getattr(isensor, 'uuid', '')

    try:
        isensor = cc.isensor.get(suuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Sensor not found: %s' % suuid)
    else:
        _print_isensor_show(isensor)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('sensor_uuid', metavar='<sensor uuid>', help="UUID of sensor")
def do_host_sensor_show(cc, args):
    """Show host sensor details."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    isensor = _find_sensor(cc, ihost, args.sensor_uuid)
    isensor = cc.isensor.get(args.sensor_uuid)
    _print_isensor_show(isensor)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_sensor_list(cc, args):
    """List sensors."""

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    isensors = cc.isensor.list(ihost.uuid)

    field_labels = ['uuid', 'name', 'sensortype', 'state', 'status', ]
    fields = ['uuid', 'sensorname', 'sensortype', 'state', 'status', ]

    utils.print_list(isensors, fields, field_labels, sortby=1)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('sensor_uuid',
           metavar='<sensor uuid>',
           help="UUID of sensor")
@utils.arg('attributes',
           metavar='<path=value>',
           nargs='+',
           action='append',
           default=[],
           help="Attributes to modify ")
def do_host_sensor_modify(cc, args):
    """Modify a sensor."""

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    sensor = _find_sensor(cc, ihost, args.sensor_uuid)

    patch = utils.args_array_to_patch("replace", args.attributes[0])

    try:
        isensor = cc.isensor.update(sensor.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError("Sensor update failed: host %s sensor %s : "
                               "update %s" %
                               (args.hostnameorid,
                                args.sensor_uuid,
                                patch))

    _print_isensor_show(isensor)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('sensor_uuid',
           metavar='<sensor uuid>',
           help="UUID of sensor")
def donot_host_sensor_delete(cc, args):
    """Delete an sensor."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    i = _find_sensor(cc, ihost, args.sensor_uuid)
    cc.isensor.delete(i.uuid)
    print('Deleted sensor: host %s sensor %s' % (args.hostnameorid,
                                                 args.sensor_uuid))
