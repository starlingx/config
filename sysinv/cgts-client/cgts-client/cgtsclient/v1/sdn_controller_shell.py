#
# Copyright (c) 2015-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc


def _print_sdn_controller_show(obj):
    fields = ['uuid', 'state', 'ip_address', 'port', 'transport']
    labels = ['uuid', 'administrative state', 'ip address',
              'remote port', 'transport mode']

    data = [(f, getattr(obj, f, '')) for f in fields]
    utils.print_tuple_list(data, labels)


@utils.arg('uuid', metavar='<uuid>',
           help="ID of the SDN controller to show")
def do_sdn_controller_show(cc, args):
    """Show SDN Controller details and attributes."""

    try:
        controller = cc.sdn_controller.get(args.uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Create SDN Controller UUID not found: %s'
                               % args.uuid)
    _print_sdn_controller_show(controller)


def do_sdn_controller_list(cc, args):
    """List all SDN controllers."""

    controllers = cc.sdn_controller.list()

    field_labels = ['uuid', 'administrative state', 'ip address',
                    'remote port']
    fields = ['uuid', 'state', 'ip_address', 'port']
    utils.print_list(controllers, fields, field_labels, sortby=0)


@utils.arg('-a', '--ip_address',
           metavar='<ip_address>',
           help='The FQDN or IP address of the SDN controller')
@utils.arg('-p', '--port',
           metavar='<port>',
           help='The outbound listening port on the SDN controller')
@utils.arg('-t', '--transport',
           metavar='<transport>',
           choices=['TCP', 'UDP', 'TLS'],
           nargs='?',
           default='TCP',
           help="The transport protocol used for the SDN controller channel "
                "(default: %(default)s)")
@utils.arg('-s', '--state',
           metavar='<state>',
           choices=['enabled', 'disabled'],
           nargs='?',
           default='enabled',
           help="The administrative state of this SDN controller "
                "(default: %(default)s)")
def do_sdn_controller_add(cc, args):
    """Add an SDN controller."""

    field_list = ['ip_address', 'port', 'transport', 'state']

    # use field list as filter
    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in field_list and not (v is None))

    try:
        controller = cc.sdn_controller.create(**user_specified_fields)
    except exc.HTTPNotFound:
        raise exc.CommandError("Failed to create SDN controller entry: "
                               "fields %s" % user_specified_fields)
    uuid = getattr(controller, 'uuid', '')
    try:
        controller = cc.sdn_controller.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError("Created SDN Controller UUID not found: %s"
                               % uuid)
    _print_sdn_controller_show(controller)


@utils.arg('uuid',
           metavar='<uuid>',
           help="The UUID of the SDN Controller")
def do_sdn_controller_delete(cc, args):
    """Delete an SDN Controller."""

    try:
        cc.sdn_controller.delete(args.uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError("Failed to delete SDN controller entry: "
                               "invalid uuid: %s" % args.uuid)
    print('Deleted SDN controller: uuid %s' % args.uuid)


@utils.arg('uuid',
           metavar='<uuid>',
           help="UUID of the SDN Controller being modified [REQUIRED]")
@utils.arg('-a', '--ip_address',
           metavar='<ip_address>',
           help='The FQDN or IP address of the SDN controller')
@utils.arg('-p', '--port',
           metavar='<port>',
           help='The outbound listening port on the SDN controller')
@utils.arg('-t', '--transport',
           metavar='<transport>',
           choices=['TCP', 'UDP', 'TLS'],
           nargs='?',
           default='TCP',
           help="The transport protocol used for the SDN controller channel "
                "(default: %(default)s)")
@utils.arg('-s', '--state',
           metavar='<state>',
           choices=['enabled', 'disabled'],
           nargs='?',
           default='enabled',
           help="The administrative state of this SDN controller "
                "(default: %(default)s)")
def do_sdn_controller_modify(cc, args):
    """Modify SDN Controller attributes."""

    try:
        controller = cc.sdn_controller.get(args.uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError("SDN controller not found: uuid %s" % args.uuid)

    field_list = ['ip_address', 'port', 'transport', 'state']

    # use field list as filter
    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in field_list and not (v is None))

    # NOTE (knasim): Validate at SysInv so that we don't
    # have to do it twice for cgcs client and Horizon
    patch = []
    for (k, v) in user_specified_fields.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})
    updated_controller = cc.sdn_controller.update(controller.uuid, patch)
    _print_sdn_controller_show(updated_controller)
