#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils


def _print_inode_show(inode):
    fields = ['numa_node', 'capabilities',
              'uuid', 'ihost_uuid',
              'created_at', 'updated_at']
    data = [(f, getattr(inode, f, '')) for f in fields]
    utils.print_tuple_list(data)


def _find_node(cc, ihost, inodeuuid):
    nodes = cc.inode.list(ihost.uuid)
    for i in nodes:
        if i.uuid == inodeuuid:
            break
    else:
        raise exc.CommandError('Inode not found: host %s if %s' %
                               (ihost.hostname, inodeuuid))
    return i


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('inodeuuid',
           metavar='<node name or uuid>',
           help="Name or UUID of node")
def do_host_node_show(cc, args):
    """Show a node."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    # API actually doesnt need ihostid once it has node uuid

    i = _find_node(cc, ihost, args.inodeuuid)

    _print_inode_show(i)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_node_list(cc, args):
    """List nodes."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    inodes = cc.inode.list(ihost.uuid)

    field_labels = ['uuid', 'numa_node', 'capabilities']
    fields = ['uuid', 'numa_node', 'capabilities']
    utils.print_list(inodes, fields, field_labels, sortby=0)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('inodeuuid',
           metavar='<node name or uuid>',
           help="Name or UUID of node")
def do_host_node_delete(cc, args):
    """Delete a node."""

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    i = _find_node(cc, ihost, args.inodeuuid)

    # The following semantic checks should be in REST or DB API
    # if ihost.administrative != 'locked':
    #     raise exc.CommandError('Host must be locked.')
    # do no allow delete if cpu members

    try:
        cc.inode.delete(i.uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Delete node failed: host %s if %s' %
                               (args.hostnameorid, args.inodeuuid))
    print('Deleted node: host %s if %s' % (args.hostnameorid, args.inodeuuid))


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('inodeuuid',
           metavar='<node name or uuid>',
           help="Name or UUID of node [REQUIRED]")
@utils.arg('-c', '--capabilities',
           metavar='<key=value>',
           action='append',
           help="Record capabilities as key/value."
                "Can be specified multiple times")
def do_host_node_modify(cc, args):
    """Modify an node."""

    rwfields = ['capabilities']

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in rwfields and not (v is None))

    i = _find_node(cc, ihost, args.inodeuuid)
    fields = i.__dict__
    fields.update(user_specified_fields)

    patch = []
    for (k, v) in user_specified_fields.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})

    try:
        inode = cc.inode.update(i.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('Inode update failed: host %s if %s : patch %s' % (args.ihost, args.inodeuuid, patch))

    _print_inode_show(inode)
