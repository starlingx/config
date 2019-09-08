#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils
from cgtsclient.v1 import istor as istor_utils


def _print_istor_show(istor):
    fields = ['osdid', 'function', 'state', 'journal_location',
              'journal_size_mib', 'journal_path', 'journal_node',
              'uuid', 'ihost_uuid', 'idisk_uuid', 'tier_uuid', 'tier_name',
              'created_at', 'updated_at']
    labels = ['osdid', 'function', 'state', 'journal_location',
              'journal_size_gib', 'journal_path', 'journal_node',
              'uuid', 'ihost_uuid', 'idisk_uuid', 'tier_uuid', 'tier_name',
              'created_at', 'updated_at']
    data = [(f, getattr(istor, f, '')) for f in fields]
    utils.print_tuple_list(data, labels)


def _find_stor(cc, ihost, storuuid):
    stors = cc.istor.list(ihost.uuid)
    for i in stors:
        if i.uuid == storuuid:
            break
    else:
        raise exc.CommandError('Stor not found: host %s stor %s' %
                               (ihost.hostname, storuuid))
    return i


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           nargs='?',
           default=None,
           help="Name or ID of host")
@utils.arg('storuuid',
           metavar='<stor uuid>',
           help="UUID of stor")
def do_host_stor_show(cc, args):
    """Show storage attributes."""
    if args.hostnameorid:
        ihost_utils._find_ihost(cc, args.hostnameorid)

    i = cc.istor.get(args.storuuid)

    # convert journal size from mib to gib when display
    if i.journal_size_mib:
        i.journal_size_mib = i.journal_size_mib / 1024

    _print_istor_show(i)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_stor_list(cc, args):
    """List host storage."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    istors = cc.istor.list(ihost.uuid)
    for i in istors:
        istor_utils._get_disks(cc, ihost, i)

        # convert journal size from mib to gib when display
        if i.journal_size_mib:
            i.journal_size_mib = i.journal_size_mib / 1024

    field_labels = ['uuid', 'function', 'osdid', 'state',
                    'idisk_uuid', 'journal_path', 'journal_node',
                    'journal_size_gib', 'tier_name']
    fields = ['uuid', 'function', 'osdid', 'state',
              'idisk_uuid', 'journal_path', 'journal_node', 'journal_size_mib',
              'tier_name']
    utils.print_list(istors, fields, field_labels, sortby=0)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('function',
           metavar='<function>',
           choices=['osd', 'monitor', 'journal'],
           nargs='?',
           default='osd',
           help="Type of the stor (default: osd)")
@utils.arg('idisk_uuid',
           metavar='<idisk_uuid>',
           help="uuid of disk [REQUIRED]")
@utils.arg('--journal-location',
           metavar='<journal_location>',
           nargs='?',
           default=None,
           help="Location of stor's journal")
@utils.arg('--journal-size',
           metavar='<size of the journal (GiB)>',
           nargs='?',
           default=None,
           help="Size of stor's journal, in GiB")
@utils.arg('--tier-uuid',
           metavar='<storage tier uuid>',
           nargs='?',
           default=None,
           help="storage tier to assign this OSD")
def do_host_stor_add(cc, args):
    """Add a storage to a host."""

    field_list = ['function', 'idisk_uuid', 'journal_location', 'journal_size',
                  'tier_uuid']
    integer_fields = ['journal_size']

    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in field_list and not (v is None))

    for f in user_specified_fields:
        try:
            if f in integer_fields:
                user_specified_fields[f] = int(user_specified_fields[f])
        except ValueError:
            raise exc.CommandError('Journal size must be an integer '
                                   'greater than 0: %s' % user_specified_fields[f])

    if 'journal_size' in user_specified_fields.keys():
        user_specified_fields['journal_size_mib'] = \
            user_specified_fields.pop('journal_size') * 1024

    if 'function' in user_specified_fields.keys():
        user_specified_fields['function'] = \
            user_specified_fields['function'].replace(" ", "")

    if 'tier_uuid' in user_specified_fields.keys():
        user_specified_fields['tier_uuid'] = \
            user_specified_fields['tier_uuid'].replace(" ", "")

    # default values, name comes from 'osd add'
    fields = {'function': 'osd'}

    fields.update(user_specified_fields)

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    try:
        fields['ihost_uuid'] = ihost.uuid
        istor = cc.istor.create(**fields)
    except exc.HTTPNotFound:
        raise exc.CommandError('Stor create failed: host %s: fields %s'
                               % (args.hostnameorid, fields))

    suuid = getattr(istor, 'uuid', '')
    try:
        istor = cc.istor.get(suuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created Stor UUID not found: %s' % suuid)

    # istor_utils._get_disks(cc, ihost, istor)
    _print_istor_show(istor)


@utils.arg('osd',
           metavar='<osd stor uuid>',
           help="UUID of osd[REQUIRED]")
@utils.arg('--journal-location',
           metavar='<journal_location>',
           nargs='?',
           default=None,
           help="Location of stor's journal")
@utils.arg('--journal-size',
           metavar='<size of the journal (MiB)>',
           nargs='?',
           default=None,
           help="Size of stor's journal, in MiB")
def do_host_stor_update(cc, args):
    """Modify journal attributes for OSD."""

    field_list = ['function', 'idisk_uuid', 'journal_location', 'journal_size']
    integer_fields = ['journal_size']

    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in field_list and not (v is None))

    for f in user_specified_fields:
        try:
            if f in integer_fields:
                user_specified_fields[f] = int(user_specified_fields[f])
        except ValueError:
            raise exc.CommandError('Journal size must be an integer '
                                   'greater than 0: %s' % user_specified_fields[f])

    if 'journal_size' in user_specified_fields.keys():
        user_specified_fields['journal_size_mib'] = \
            user_specified_fields.pop('journal_size') * 1024

    patch = []
    for (k, v) in user_specified_fields.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})

    try:
        istor = cc.istor.update(args.osd, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('OSD update failed: OSD %s: patch %s'
                               % (args.osd, patch))

    _print_istor_show(istor)


@utils.arg('stor',
           metavar='<stor id or uuid>',
           help="UUID of stor[REQUIRED]")
def do_host_stor_delete(cc, args):
    """Delete a stor"""
    try:
        cc.istor.delete(args.stor)
    except exc.HTTPNotFound:
        raise exc.CommandError('Delete failed, stor: %s not found'
                               % args.stor)
