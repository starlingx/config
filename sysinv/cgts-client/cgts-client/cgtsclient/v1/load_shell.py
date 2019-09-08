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
import os.path


def _print_load_show(load):
    fields = ['id', 'state', 'software_version', 'compatible_version',
              'required_patches']
    data = [(f, getattr(load, f, '')) for f in fields]
    utils.print_tuple_list(data)


@utils.arg('loadid',
           metavar='<id>',
           help="ID of load")
def do_load_show(cc, args):
    """Show load attributes."""
    load = cc.load.get(args.loadid)

    _print_load_show(load)


def do_load_list(cc, args):
    """List all loads."""
    loads = cc.load.list()

    field_labels = ['id', 'state', 'software_version']
    fields = ['id', 'state', 'software_version']
    utils.print_list(loads, fields, field_labels, sortby=0)


@utils.arg('loadid',
           metavar='<id>',
           help="ID of load")
def do_load_delete(cc, args):
    """Delete a load."""

    load = cc.load.get(args.loadid)

    try:
        cc.load.delete(load.uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Delete load failed: load %s' % args.loadid)

    print('Deleted load: load %s' % args.loadid)


@utils.arg('isopath',
           metavar='<path to iso>',
           help="The full path of the iso to import [REQUIRED]")
@utils.arg('sigpath',
           metavar='<path to detached signature>',
           help="The full path of the detached signature file corresponding to the iso [REQUIRED]")
def do_load_import(cc, args):
    """Import a load."""
    # If absolute path is not specified, we assume it is the relative path.
    # args.isopath will then be set to the absolute path
    if not os.path.isabs(args.isopath):
        args.isopath = os.path.abspath(args.isopath)

    if not os.path.isabs(args.sigpath):
        args.sigpath = os.path.abspath(args.sigpath)

    # Here we pass the path_to_iso to the API
    # The API will perform any required actions to import the provided iso
    patch = {'path_to_iso': args.isopath, 'path_to_sig': args.sigpath}

    try:
        new_load = cc.load.import_load(**patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('Load import failed')

    if new_load:
        uuid = new_load["uuid"]
    else:
        raise exc.CommandError('load was not created')

    try:
        load = cc.load.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('load UUID not found: %s' % uuid)

    _print_load_show(load)
