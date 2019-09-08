#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

import argparse

from cgtsclient.common import utils
from cgtsclient.v1 import storage_backend as storage_backend_utils


def _list_formatter(values):
    if values is not None:
        result = [x.decode('unicode_escape').encode('ascii', 'ignore')
                  for x in values]
        return (", ".join(result))
    else:
        return None


@utils.arg('--asdict',
           action='store_true',
           default=False,
           help=('Format capabilities field as dictionary.'))
def do_storage_backend_list(cc, args):
    """List storage backends."""

    asdict = args.asdict if 'asdict' in args else None
    storage_backends = cc.storage_backend.list(asdict)

    field_labels = ['uuid', 'name', 'backend', 'state', 'task', 'services',
                    'capabilities']
    fields = ['uuid', 'name', 'backend', 'state', 'task', 'services',
              'capabilities']
    utils.print_list(storage_backends, fields, field_labels, sortby=0)


@utils.arg('backend_name_or_uuid',
           metavar='<backend name or uuid>',
           help="Name or UUID of the backend [REQUIRED]")
@utils.arg('--asdict',
           action='store_true',
           default=False,
           help=('Format capabilities field as dictionary.'))
def do_storage_backend_show(cc, args):
    """Show a storage backend."""

    asdict = args.asdict if 'asdict' in args else None
    storage_backend_utils.backend_show(
        cc, args.backend_name_or_uuid, asdict)


@utils.arg('backend',
           metavar='<backend>',
           choices=['ceph', 'ceph-external', 'file', 'lvm', 'external'],
           help='The storage backend to add [REQUIRED]')
@utils.arg('-s', '--services',
           metavar='<services>',
           help=('Comma separated list of services to be added to the '
                 'backend. Allowed values: [cinder, glance, swift]'))
@utils.arg('-n', '--name',
           metavar='<name>',
           help=('Optional backend name used for adding additional backends.'))
@utils.arg('-t', '--tier_uuid',
           metavar='<tier_uuid>',
           help=('Optional storage tier uuid for additional backends (ceph '
                 'only)'))
@utils.arg('-c', '--ceph_conf',
           metavar='<ceph_conf>',
           help='Location of the Ceph configuration file used for provisioning'
                ' an external backend.')
@utils.arg('--confirmed',
           action='store_true',
           help='Provide acknowledgement that the operation should continue as'
           ' the action is not reversible.')
@utils.arg('attributes',
           metavar='<parameter=value>',
           nargs='*',
           default=[],
           help="Required backend/service parameters to apply.")
# Parameters specific to Ceph monitors, these should be moved to system
# ceph-mon-add when that command is available.
@utils.arg('--ceph-mon-gib',
           metavar='<ceph-mon-gib>',
           help='The ceph-mon-lv size in GiB')
def do_storage_backend_add(cc, args):
    """Add a storage backend."""

    backend = vars(args).get('backend', None)
    storage_backend_utils.backend_add(cc, backend, args)
    do_storage_backend_list(cc, args)


@utils.arg('backend_name_or_uuid',
           metavar='<backend name or uuid>',
           help="Name or UUID of the backend [REQUIRED]")
@utils.arg('attributes',
           metavar='<parameter=value>',
           nargs='*',
           default=[],
           help="Required backend/service parameters to apply.")
@utils.arg('-s', '--services',
           metavar='<services>',
           help=('Optional string of comma separated services to add/update. '
                 'Valid values are: "cinder, glance, swift"'))
@utils.arg('-c', '--ceph_conf',
           metavar='<ceph_conf>',
           help=('Location of the Ceph configuration file used for provisioning'
                 ' an external backend.'))
def do_storage_backend_modify(cc, args):
    """Modify a storage backend."""

    storage_backend_utils.backend_modify(cc, args)


@utils.arg('backend_name_or_uuid',
           metavar='<backend name or uuid>',
           help="Name or UUID of the backend [REQUIRED]")
@utils.arg('-f', '--force',
           action='store_true',
           default=False,
           help=argparse.SUPPRESS)
def do_storage_backend_delete(cc, args):
    """Delete a storage backend."""

    if args.force:
        storage_backend_utils.backend_delete(
            cc, args.backend_name_or_uuid)
    else:
        print("Deleting a storage backend is not supported.")
