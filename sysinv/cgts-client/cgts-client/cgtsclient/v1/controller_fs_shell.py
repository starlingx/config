#
# Copyright (c) 2013-2020,2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc

from oslo_serialization import jsonutils


def _find_fs(cc, name_or_uuid):
    if name_or_uuid.isdigit():
        try:
            fs = cc.controller_fs.get(name_or_uuid)
        except exc.HTTPNotFound:
            raise exc.CommandError('Filesystem not found by uuid: %s'
                                   % name_or_uuid)
        else:
            return fs
    else:
        fs_list = cc.controller_fs.list()
        for fs in fs_list:
            if fs.name == name_or_uuid:
                return fs
            if fs.uuid == name_or_uuid:
                return fs
        else:
            raise exc.CommandError('Filesystem not found by name or '
                                   'uuid: %s' % name_or_uuid)


def _print_controller_fs_show(controller_fs):
    fields = ['uuid', 'name', 'size', 'logical_volume', 'replicated', 'state',
              'capabilities', 'created_at', 'updated_at']

    labels = ['uuid', 'name', 'size', 'logical_volume', 'replicated', 'state',
              'capabilities', 'created_at', 'updated_at']

    data = [(f, getattr(controller_fs, f)) for f in fields]
    utils.print_tuple_list(data, labels)


@utils.arg('attributes',
           metavar='<fs_name=size>',
           nargs='+',
           action='append',
           default=[],
           help="Modify controller filesystem sizes")
@utils.arg('--column',
           action='append',
           default=[],
           help="Specify the column(s) to include, can be repeated")
@utils.arg('--format',
           choices=['table', 'yaml', 'value'],
           help="specify the output format, defaults to table")
@utils.arg('--functions',
           metavar='<function1,function2,...>',
           default=None,
           help='Controller filesystem functions')
def do_controllerfs_modify(cc, args):
    """Modify the size or functions of a filesystem"""

    field_list = ['functions']
    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                 if k in field_list and not (v is None))
    functions = user_specified_fields.get('functions')

    patch_list = []
    for attr in args.attributes[0]:
        try:
            patch = []
            db_name, size = attr.split("=", 1)
            patch.append({'op': 'replace', 'path': '/name', 'value': db_name})
            patch.append({'op': 'replace', 'path': '/size', 'value': size})
        except ValueError:
            if functions is None:
                raise exc.CommandError('Filesystem resize attributes must be '
                                       'FS_NAME=SIZE not "%s"' % attr)
            # Functions provided, but size was not specified.
            # Eg.: controllerfs-modify ceph-float --functions=monitor
            patch.append({'op': 'replace', 'path': '/name', 'value': attr})

        if functions is not None:
            if len(args.attributes[0]) == 1:
                capabilities = {}
                capabilities['functions'] = [f for f in functions.split(',') if f]
                patch.append({
                    'op': 'replace',
                    'path': '/capabilities',
                    'value': jsonutils.dumps(capabilities)
                })
            else:
                raise exc.CommandError('Alter functions are only supported '
                                       'for one filesystem at a time.')

        patch_list.append(patch)

    try:
        cc.controller_fs.update_many(cc.isystem.list()[0].uuid, patch_list)
    except exc.HTTPNotFound:
        raise exc.CommandError('Failed to modify controller filesystems')

    _print_controllerfs_list(cc, args)


@utils.arg('fsnameoruuid',
           metavar='<fs name or uuid>',
           help="Name or UUID of filesystem [REQUIRED]")
def do_controllerfs_show(cc, args):
    """Show details of a controller filesystem"""

    controller_fs = _find_fs(cc, args.fsnameoruuid)
    _print_controller_fs_show(controller_fs)


def _print_controllerfs_list(cc, args):
    controller_fs_list = cc.controller_fs.list()

    if args.column:
        fields = args.column
        field_labels = args.column
    else:
        field_labels = ['UUID', 'FS Name', 'Size in GiB', 'Logical Volume',
                        'Replicated', 'State', 'Capabilities']
        fields = ['uuid', 'name', 'size', 'logical_volume', 'replicated',
                  'state', 'capabilities']

    utils.print_list(controller_fs_list, fields, field_labels,
                     sortby=0, output_format=args.format)


@utils.arg('--column',
           action='append',
           default=[],
           help="Specify the column(s) to include, can be repeated")
@utils.arg('--format',
           choices=['table', 'yaml', 'value'],
           help="specify the output format, defaults to table")
def do_controllerfs_list(cc, args):
    """Show list of controller filesystems"""
    _print_controllerfs_list(cc, args)


@utils.arg('fsnameoruuid',
           metavar='<fs name or uuid>',
           help="Name or UUID of filesystem [REQUIRED]")
def do_controllerfs_delete(cc, args):
    """Delete a controller filesystem."""

    controller_fs = _find_fs(cc, args.fsnameoruuid)

    try:
        cc.controller_fs.delete(controller_fs.uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Filesystem delete failed: '
                               'name %s' % (args.name))
    setattr(args, 'column', None)
    setattr(args, 'format', None)
    _print_controllerfs_list(cc, args)


@utils.arg('name',
           metavar='<fs name=size>',
           nargs=1,
           action='append',
           help="Name of the Filesystem [REQUIRED]")
def do_controllerfs_add(cc, args):
    """Add a controller filesystem"""
    fields = {}
    for attr in args.name[0]:
        try:
            fs_name, size = attr.split("=", 1)

            fields['name'] = fs_name
            fields['size'] = size
        except ValueError:
            raise exc.CommandError('Filesystem creation attributes must be '
                                   'FS_NAME=SIZE not "%s"' % attr)
    try:
        fs = cc.controller_fs.create(**fields)
    except exc.HTTPNotFound:
        raise exc.CommandError('Failed to create filesystem: fields %s' %
                               (fields))

    _print_controller_fs_show(fs)
