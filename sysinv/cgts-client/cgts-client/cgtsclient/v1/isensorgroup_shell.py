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
from cgtsclient.v1 import isensorgroup as isensorgroup_utils
from collections import OrderedDict


def _print_isensorgroup_show(isensorgroup):
    fields = ['uuid', 'sensorgroupname', 'path', 'sensortype', 'datatype',
              'audit_interval_group', 'algorithm', 'state',
              'possible_states', 'actions_critical_choices',
              'actions_major_choices', 'actions_minor_choices',
              'actions_minor_group',
              'actions_major_group',
              'actions_critical_group',
              'record_ttl',
              'sensors',
              'suppress',
              'created_at', 'updated_at']

    fields_analog = ['unit_base_group', 'unit_modifier_group',
                     'unit_rate_group',
                     't_minor_lower_group', 't_minor_upper_group',
                     't_major_lower_group', 't_major_upper_group',
                     't_critical_lower_group', 't_critical_upper_group']

    labels = ['uuid', 'sensorgroupname', 'path', 'sensortype', 'datatype',
              'audit_interval_group', 'algorithm', 'state',
              'possible_states', 'actions_critical_choices',
              'actions_major_choices', 'actions_minor_choices',
              'actions_minor_group', 'actions_major_group',
              'actions_critical_group',
              'record_ttl',
              'sensors',
              'suppress',
              'created_at', 'updated_at']

    labels_analog = ['unit_base_group', 'unit_modifier_group',
                     'unit_rate_group',
                     't_minor_lower_group', 't_minor_upper_group',
                     't_major_lower_group', 't_major_upper_group',
                     't_critical_lower_group', 't_critical_upper_group']

    datatype = getattr(isensorgroup, 'datatype') or ""
    if datatype == 'analog':
        fields.extend(fields_analog)
        labels.extend(labels_analog)

    data = dict([(f, getattr(isensorgroup, f, '')) for f in fields])
    ordereddata = OrderedDict(sorted(data.items(), key=lambda t: t[0]))
    utils.print_dict(ordereddata, wrap=72)


def _find_sensorgroup(cc, ihost, sensorgroup_uuid):
    sensorgroups = cc.isensorgroup.list(ihost.uuid)
    for p in sensorgroups:
        if p.uuid == sensorgroup_uuid:
            break
    else:
        raise exc.CommandError('SensorGroup not found: host %s' % ihost.id)
    return p


@utils.arg('hostnameorid',
           metavar='<hostnameorid>',
           help='Name or ID of host associated with this sensorgroup.')
@utils.arg('sensorgroupname',
           metavar='<sensorgroupname>',
           help='Name of the sensorgroup.')
@utils.arg('sensortype',
           metavar='<sensortype>',
           choices=['temperature', 'voltage', 'power',
                    'current', 'tachometer', 'pressure',
                    'airflow', 'watchdog'],
           help='sensortype of the sensorgroup.')
@utils.arg('datatype',
           metavar='<datatype>',
           choices=['discrete', 'analog'],
           help='datatype of sensorgroup: "discrete" or "analog"')
@utils.arg('-acrit', '--actions_critical_choices',
           metavar='<actions_critical_choices>',
           help="Configurable Critical severity Actions for this sensorgroup.  CSV format.")
@utils.arg('-amaj', '--actions_major_choices',
           metavar='<actions_major_choices>',
           help="Configurable Major severity Actions for this sensorgroup.  CSV format.")
@utils.arg('-amin', '--actions_minor_choices',
           metavar='<actions_minor_choices>',
           help="Configurable Minor severity Actions for this sensorgroup.  CSV format.")
@utils.arg('-m', '--actions_major_group',
           metavar='<actions_major_group>',
           help='Major Actions of the sensorgroup. CSV format.')
@utils.arg('-c', '--actions_critical_group',
           metavar='<actions_critical_group>',
           help='Critical Actions of the sensorgroup. CSV format.')
@utils.arg('-tcrl', '--t_critical_lower_group',
           metavar='<t_critical_lower_group>',
           help='Critical Lower Threshold of the sensorgroup.')
@utils.arg('-tcru', '--t_critical_upper',
           metavar='<t_critical_upper_group>',
           help='Critical Upper Threshold of the sensorgroup.')
def donot_host_sensorgroup_add(cc, args):
    """Add a new sensorgroup to a host."""
    field_list = ['sensorgroupname', 'sensortype', 'datatype',
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

    isensorgroup = cc.isensorgroup.create(**fields)
    suuid = getattr(isensorgroup, 'uuid', '')

    try:
        isensorgroup = cc.isensorgroup.get(suuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Sensor not found: %s' % suuid)
    else:
        _print_isensorgroup_show(isensorgroup)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('sensorgroup_uuid', metavar='<sensorgroup uuid>',
           help="UUID of sensorgroup")
def do_host_sensorgroup_show(cc, args):
    """Show host sensor group attributes."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    isensorgroup = _find_sensorgroup(cc, ihost, args.sensorgroup_uuid)
    isensorgroup = cc.isensorgroup.get(args.sensorgroup_uuid)

    isensorgroup_utils._get_sensors(cc, args.hostnameorid, isensorgroup)

    _print_isensorgroup_show(isensorgroup)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_sensorgroup_list(cc, args):
    """List sensor groups."""

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    isensorgroups = cc.isensorgroup.list(ihost.uuid)

    for i in isensorgroups[:]:
        isensorgroup_utils._get_sensors(cc, args.hostnameorid, i)

    fields = ['uuid', 'sensorgroupname', 'sensortype', 'sensors',
              'audit_interval_group', 'state']
    field_labels = ['uuid', 'name', 'sensortype', 'sensors',
                    'audit_interval_group', 'state']

    utils.print_list(isensorgroups, fields, field_labels, sortby=1)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_sensorgroup_relearn(cc, args):
    """Relearn sensor model."""

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    isensorgroups = cc.isensorgroup.relearn(ihost.uuid)

    print("%s sensor model and any related alarm assertions are being "
          "deleted." % (args.hostnameorid))
    print("Any sensor suppression settings at the group or sensor levels "
          "will be lost.")
    print("Will attempt to preserve customized group actions and monitor "
          "interval when the model is relearned on next audit interval.")
    print("The learning process may take several minutes. Please stand-by.")


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('sensorgroup_uuid',
           metavar='<sensorgroup uuid>',
           help="UUID of sensorgroup")
@utils.arg('attributes',
           metavar='<path=value>',
           nargs='+',
           action='append',
           default=[],
           help="Attributes to modify ")
def do_host_sensorgroup_modify(cc, args):
    """Modify sensor group of a host."""

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    sensorgroup = _find_sensorgroup(cc, ihost, args.sensorgroup_uuid)

    patch = utils.args_array_to_patch("replace", args.attributes[0])

    try:
        isensorgroup = cc.isensorgroup.update(sensorgroup.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError("Sensor update failed: host %s sensorgroup %s :"
                               " update %s" %
                               (args.hostnameorid,
                                args.sensorgroup_uuid,
                                patch))

    _print_isensorgroup_show(isensorgroup)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('sensorgroup_uuid',
           metavar='<sensorgroup uuid>',
           help="UUID of sensorgroup")
def donot_host_sensorgroup_delete(cc, args):
    """Delete an sensorgroup."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    i = _find_sensorgroup(cc, ihost, args.sensorgroup_uuid)
    cc.isensorgroup.delete(i.uuid)
    print('Deleted sensorgroup: host %s sensorgroup %s' %
          (args.hostnameorid, args.sensorgroup_uuid))
