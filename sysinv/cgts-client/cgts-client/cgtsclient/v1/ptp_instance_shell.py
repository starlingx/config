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
              'hostname',
              'created_at']
    data = [(f, getattr(ptp_instance_obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


def do_ptp_instance_list(cc, args):
    """List all PTP instances, in any host."""
    ptp_instances = cc.ptp_instance.list()
    for instance in ptp_instances[:]:
        ihost = ihost_utils._find_ihost(cc, instance.host_uuid)
        setattr(instance, 'hostname', ihost.hostname)

    field_labels = ['name', 'service', 'hostname']
    fields = ['name', 'service', 'hostname']
    utils.print_list(ptp_instances, fields, field_labels)


@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host")
def do_host_ptp_instance_list(cc, args):
    """List PTP instances on host."""
    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    ptp_instances = cc.ptp_instance.list_by_host(ihost.uuid)

    field_labels = ['name', 'service', 'uuid']
    fields = ['name', 'service', 'uuid']
    utils.print_list(ptp_instances, fields, field_labels)


@utils.arg('nameoruuid',
           metavar='<name or UUID>',
           help="Name or UUID of PTP instance")
def do_ptp_instance_show(cc, args):
    """Show PTP instance attributes."""
    ptp_instance = ptp_instance_utils._find_ptp_instance(cc, args.nameoruuid)
    ihost = ihost_utils._find_ihost(cc, ptp_instance.host_uuid)
    setattr(ptp_instance, 'hostname', ihost.hostname)
    _print_ptp_instance_show(ptp_instance)


@utils.arg('name',
           metavar='<name>',
           help="Name of PTP instance [REQUIRED]")
@utils.arg('service',
           metavar='<service type>',
           choices=['ptp4l', 'phc2sys', 'ts2phc'],
           help="Service type [REQUIRED]")
@utils.arg('hostnameorid',
           metavar='<hostname or id>',
           help="Name or ID of host [REQUIRED]")
def do_ptp_instance_add(cc, args):
    """Add a PTP instance."""

    field_list = ['name', 'service']

    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    data.update({'host_uuid': ihost.uuid})

    ptp_instance = cc.ptp_instance.create(**data)
    uuid = getattr(ptp_instance, 'uuid', '')
    try:
        ptp_instance = cc.ptp_instance.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('PTP instance just created not found: %s' %
                               uuid)
    if ptp_instance:
        setattr(ptp_instance, 'hostname', ihost.hostname)
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
