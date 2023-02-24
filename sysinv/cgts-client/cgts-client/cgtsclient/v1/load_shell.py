#
# Copyright (c) 2015-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc
import os.path
from oslo_utils._i18n import _
import sys
import threading
import time

IMPORTED_LOAD_MAX_COUNT = 1


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
@utils.arg('-a', '--active',
           action='store_true',
           default=False,
           help=("Perform an active load import operation. "
                 "Applicable only for SystemController to allow import of "
                 "an active load for subcloud install"))
@utils.arg('-i', '--inactive',
           action='store_true',
           default=False,
           help=("Perform an inactive load import operation. "
                 "Import a previous release load for subcloud install"))
@utils.arg('--local',
           action='store_true',
           default=False,
           help=("Import the load locally from the active controller. "
                 "To use this option, first upload the .iso and .sig files to "
                 "the active controller and then specify the absolute path of "
                 "both files as 'isopath' and 'sigpath'"))
def do_load_import(cc, args):
    """Import a load."""

    local = args.local
    active = args.active
    inactive = args.inactive

    # If absolute path is not specified, we assume it is the relative path.
    # args.isopath will then be set to the absolute path
    if not os.path.isabs(args.isopath):
        args.isopath = os.path.abspath(args.isopath)

    if not os.path.isabs(args.sigpath):
        args.sigpath = os.path.abspath(args.sigpath)

    if not os.path.isfile(args.isopath):
        raise exc.CommandError(_("File %s does not exist." % args.isopath))

    if not os.path.isfile(args.sigpath):
        raise exc.CommandError(_("File %s does not exist." % args.sigpath))

    if not active and not inactive:
        # The following logic is taken from sysinv api as it takes a while for
        # this large POST request to reach the server.
        #
        # Ensure the request does not exceed load import limit before sending.

        loads = cc.load.list()
        if len(loads) > IMPORTED_LOAD_MAX_COUNT:
            raise exc.CommandError(_(
                "Max number of loads (2) reached. Please remove the "
                "old or unused load before importing a new one."))

    patch = {
        'path_to_iso': args.isopath,
        'path_to_sig': args.sigpath,
        'inactive': inactive,
        'active': active,
        'local': local,
    }

    try:
        print("This operation will take a while. Please wait.")
        wait_task = WaitThread()
        wait_task.start()
        imported_load = cc.load.import_load(**patch)
        wait_task.join()
    except Exception as e:
        wait_task.join()
        raise exc.CommandError(_("Load import failed. Reason: %s" % e))
    else:
        _print_load_show(imported_load)


class WaitThread(threading.Thread):
    def __init__(self):
        super(WaitThread, self).__init__()
        self.stop = threading.Event()

    def run(self):
        while not self.stop.is_set():
            sys.stdout.write(".")
            sys.stdout.flush()
            time.sleep(10)

    def join(self, timeout=None):  # pylint: disable=arguments-differ
        self.stop.set()
        super(WaitThread, self).join(timeout)
        sys.stdout.write("\n")
        sys.stdout.flush()
