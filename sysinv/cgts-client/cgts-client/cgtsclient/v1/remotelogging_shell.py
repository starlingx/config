#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc


def _print_remotelogging_show(remotelogging):
    fields = ['uuid',
              'ip_address',
              'enabled',
              'transport',
              'port',
              'created_at',
              'updated_at']

    data = [(f, getattr(remotelogging, f, '')) for f in fields]
    utils.print_tuple_list(data)


def do_remotelogging_show(cc, args):
    """Show remotelogging attributes."""

    remoteloggings = cc.remotelogging.list()

    _print_remotelogging_show(remoteloggings[0])


def donot_config_remotelogging_list(cc, args):
    """List remoteloggings."""

    remoteloggings = cc.remotelogging.list()
    field_labels = ['IP Address', 'Enabled', 'Transport', 'Port', 'TLS key file']
    fields = ['ip_address',
              'enabled',
              'transport',
              'port',
              'key_file']
    utils.print_list(remoteloggings, fields, field_labels, sortby=1)


@utils.arg('--ip_address',
           metavar='<ip_address>',
           default=None,
           help="IP Address of remote log server.")
@utils.arg('--enabled',
           metavar='<true/false>',
           help="Remote log server enabled.")
@utils.arg('--transport',
           metavar='<transport>',
           default=None,
           help="Remote log server transport protocol.")
@utils.arg('--port',
           metavar='<port>',
           default=None,
           help="Remote log server port.")
def do_remotelogging_modify(cc, args):
    """Modify Remote Logging attributes."""

    remoteloggings = cc.remotelogging.list()
    remotelogging = remoteloggings[0]

    attributes = []
    if args.ip_address is not None:
        attributes.append('ip_address=%s' % args.ip_address)
    if args.enabled is not None:
        attributes.append('enabled=%s' % args.enabled)
    if args.transport is not None:
        attributes.append('transport=%s' % args.transport)
    if args.port is not None:
        attributes.append('port=%s' % args.port)
    if args.key_file is not None:
        attributes.append('key_file=%s' % args.key_file)
    if len(attributes) > 0:
        attributes.append('action=apply')
    else:
        print("No options provided.")
        return

    patch = utils.args_array_to_patch("replace", attributes)

    try:
        remotelogging = cc.remotelogging.update(remotelogging.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('remotelogging not found: %s' % remotelogging.uuid)

    _print_remotelogging_show(remotelogging)
