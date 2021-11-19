########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils
from cgtsclient.v1 import ptp_instance as ptp_instance_utils


def _print_ptp_instance_show(ptp_instance_obj):
    fields = ['uuid',
              'name',
              'service',
              'created_at']
    data = [(f, getattr(ptp_instance_obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


def _print_ptp_instance_list(ptp_instance_list):
    field_labels = ['uuid', 'name', 'service']
    fields = ['uuid', 'name', 'service']
    utils.print_list(ptp_instance_list, fields, field_labels)


def do_ptp_instance_list(cc, args):
    """List all PTP instances."""
    ptp_instances = cc.ptp_instance.list()
    _print_ptp_instance_list(ptp_instances)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_ptp_instance_list(cc, args):
    """List PTP instances on host."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    ptp_instances = cc.ptp_instance.list_by_host(ihost.uuid)
    _print_ptp_instance_list(ptp_instances)


@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP instance")
def do_ptp_instance_show(cc, args):
    """Show PTP instance attributes."""
    ptp_instance = ptp_instance_utils._find_ptp_instance(cc, args.nameoruuid)
    _print_ptp_instance_show(ptp_instance)


@utils.arg('name',
           metavar='<name>',
           help="Name of PTP instance [REQUIRED]")
@utils.arg('service',
           metavar='<service type>',
           choices=['ptp4l', 'phc2sys', 'ts2phc'],
           help="Service type [REQUIRED]")
def do_ptp_instance_add(cc, args):
    """Add a PTP instance."""

    field_list = ['name', 'service']

    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    ptp_instance = cc.ptp_instance.create(**data)
    uuid = getattr(ptp_instance, 'uuid', '')
    try:
        ptp_instance = cc.ptp_instance.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('PTP instance just created not found: %s' %
                               uuid)
    _print_ptp_instance_show(ptp_instance)


@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP instance")
def do_ptp_instance_delete(cc, args):
    """Delete a PTP instance."""
    ptp_instance = ptp_instance_utils._find_ptp_instance(cc, args.nameoruuid)
    uuid = ptp_instance.uuid
    cc.ptp_instance.delete(uuid)
    print('Deleted PTP instance: %s' % uuid)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP instance [REQUIRED]")
def do_host_ptp_instance_add(cc, args):
    """Associate PTP instance to host."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    ptp_instance = ptp_instance_utils._find_ptp_instance(cc, args.nameoruuid)
    try:
        cc.ptp_instance.apply(ihost.uuid, ptp_instance.id)
    except exc.HTTPNotFound:
        raise exc.CommandError(
            "Failed to apply PTP instance '%s' to host '%s'"
            % (ihost.hostname, ptp_instance.name))
    print("Applying PTP instance '%s' to host '%s'"
          % (ihost.hostname, ptp_instance.name))


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP instance")
def do_host_ptp_instance_delete(cc, args):
    """Disassociate PTP instance on host."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    ptp_instance = ptp_instance_utils._find_ptp_instance(cc, args.nameoruuid)
    try:
        cc.ptp_instance.remove(ihost.uuid, ptp_instance.id)
    except exc.HTTPNotFound:
        raise exc.CommandError(
            "Failed to remove PTP instance '%s' from host '%s'"
            % (ihost.hostname, ptp_instance.name))
    print("Removing PTP instance '%s' from host '%s'"
          % (ihost.hostname, ptp_instance.name))
