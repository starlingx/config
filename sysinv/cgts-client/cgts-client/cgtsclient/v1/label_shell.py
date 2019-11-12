#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#


from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils


def _print_label_show(obj):
    fields = ['uuid', 'host_uuid', 'label_key', 'label_value']
    data = [(f, getattr(obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
def do_host_label_list(cc, args):
    """List kubernetes labels assigned to a host."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    host_label = cc.label.list(ihost.uuid)
    for i in host_label[:]:
        setattr(i, 'hostname', ihost.hostname)
    field_labels = ['hostname', 'label key', 'label value']
    fields = ['hostname', 'label_key', 'label_value']
    utils.print_list(host_label, fields, field_labels, sortby=1)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('attributes',
           metavar='<name=value>',
           nargs='+',
           action='append',
           default=[],
           help="List of Kubernetes labels")
@utils.arg('--overwrite',
           action='store_true',
           help="Allow labels to be overwritten")
def do_host_label_assign(cc, args):
    """Update the Kubernetes labels on a host."""
    attributes = utils.extract_keypairs(args)
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    parameters = ["overwrite=" + str(args.overwrite)]
    new_labels = cc.label.assign(ihost.uuid, attributes, parameters)
    for p in new_labels.labels:
        uuid = p['uuid']
        if uuid is not None:
            try:
                label_obj = cc.label.get(uuid)
            except exc.HTTPNotFound:
                raise exc.CommandError('Host label not found: %s' % uuid)
            _print_label_show(label_obj)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('attributes',
           metavar='<name>',
           nargs='+',
           action='append',
           default=[],
           help="List of Kubernetes label keys")
def do_host_label_remove(cc, args):
    """Remove Kubernetes label(s) from a host"""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    for i in args.attributes[0]:
        lbl = _find_host_label(cc, ihost, i)
        if lbl:
            cc.label.remove(lbl.uuid)
            print('Deleted host label %s for host %s' % (i, ihost.hostname))


def _find_host_label(cc, host, label):
    host_labels = cc.label.list(host.uuid)
    for lbl in host_labels:
        if lbl.host_uuid == host.uuid and lbl.label_key == label:
            break
    else:
        lbl = None
        print('Host label not found: host %s, label key %s ' %
              (host.hostname, label))
    return lbl
