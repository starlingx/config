#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# -*- encoding: utf-8 -*-
#

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import host_fs as fs_utils
from cgtsclient.v1 import ihost as ihost_utils


def _print_fs_show(fs):
    fields = ['uuid', 'name', 'size', 'logical_volume',
              'created_at', 'updated_at']

    labels = ['uuid', 'name', 'size', 'logical_volume',
              'created_at', 'updated_at']

    data = [(f, getattr(fs, f)) for f in fields]
    utils.print_tuple_list(data, labels)


def _print_fs_list(cc, ihost_uuid):
    fs_list = cc.host_fs.list(ihost_uuid)

    field_labels = ['UUID', 'FS Name', 'Size in GiB', 'Logical Volume']
    fields = ['uuid', 'name', 'size', 'logical_volume']
    utils.print_list(fs_list, fields, field_labels, sortby=1)


def _find_fs(cc, ihost, uuid):
    filesystems = cc.host_fs.list(ihost.uuid)
    for fs in filesystems:
        if fs.uuid == uuid:
            break
    else:
        raise exc.CommandError('Filesystem not found: host %s filesystem %s' %
                               (ihost.hostname, uuid))
    return fs


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('fsnameoruuid',
           metavar='<fs name or uuid>',
           help="Name or UUID of filesystem [REQUIRED]")
def do_host_fs_show(cc, args):
    """Show details of a host filesystem"""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    fs = fs_utils._find_fs(cc, ihost, args.fsnameoruuid)
    _print_fs_show(fs)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
def do_host_fs_list(cc, args):
    """Show list of host filesystems"""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    _print_fs_list(cc, ihost.uuid)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of the host [REQUIRED]")
@utils.arg('attributes',
           metavar='<fs_name=size>',
           nargs='+',
           action='append',
           default=[],
           help="Modify host filesystem sizes")
def do_host_fs_modify(cc, args):
    """Modify the size of a Filesystem."""

    patch_list = []
    for attr in args.attributes[0]:
        try:
            patch = []
            db_name, size = attr.split("=", 1)
            patch.append({'op': 'replace', 'path': '/name', 'value': db_name})
            patch.append({'op': 'replace', 'path': '/size', 'value': size})
            patch_list.append(patch)
        except ValueError:
            raise exc.CommandError('Attributes must be a list of '
                                   'FS_NAME=SIZE not "%s"' % attr)

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)

    try:
        cc.host_fs.update_many(ihost.uuid, patch_list)
    except exc.HTTPNotFound:
        raise exc.CommandError('Failed to modify filesystems')

    _print_fs_list(cc, ihost.uuid)
