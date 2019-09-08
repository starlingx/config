#
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc


def _find_fs(cc, name):
    fs_list = cc.controller_fs.list()
    for fs in fs_list:
        if fs.name == name:
            break
    else:
        raise exc.CommandError('Filesystem "%s" not found' % name)
    return fs


def _print_controller_fs_show(controller_fs):
    fields = ['uuid', 'name', 'size', 'logical_volume', 'replicated', 'state',
              'created_at', 'updated_at']

    labels = ['uuid', 'name', 'size', 'logical_volume', 'replicated', 'state',
              'created_at', 'updated_at']

    data = [(f, getattr(controller_fs, f)) for f in fields]
    utils.print_tuple_list(data, labels)


@utils.arg('attributes',
           metavar='<fs_name=size>',
           nargs='+',
           action='append',
           default=[],
           help="Modify controller filesystem sizes")
def do_controllerfs_modify(cc, args):
    """Modify controller filesystem sizes."""

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

    try:
        cc.controller_fs.update_many(cc.isystem.list()[0].uuid, patch_list)
    except exc.HTTPNotFound:
        raise exc.CommandError('Failed to modify controller filesystems')

    _print_controllerfs_list(cc)


@utils.arg('name',
           metavar='<name>',
           help='Name of the filesystem [REQUIRED]')
def do_controllerfs_show(cc, args):
    """Show details of a controller filesystem"""

    controller_fs = _find_fs(cc, args.name)
    _print_controller_fs_show(controller_fs)


def _print_controllerfs_list(cc):
    controller_fs_list = cc.controller_fs.list()

    field_labels = ['UUID', 'FS Name', 'Size in GiB', 'Logical Volume',
                    'Replicated', 'State']
    fields = ['uuid', 'name', 'size', 'logical_volume', 'replicated', 'state']
    utils.print_list(controller_fs_list, fields, field_labels, sortby=1)


def do_controllerfs_list(cc, args):
    """Show list of controller filesystems"""
    _print_controllerfs_list(cc)
