########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from cgtsclient.common import utils
from cgtsclient import exc


@utils.arg('parameter_uuid',
           metavar='<parameter uuid>',
           help="UUID of PTP parameter [REQUIRED]")
@utils.arg('owner_uuid',
           metavar='<owner uuid>',
           help="UUID of PTP instance or PTP interface [REQUIRED]")
def do_ptp_parameter_set_owner(cc, args):
    """Set ownership of a PTP parameter."""

    field_list = ['parameter_uuid', 'owner_uuid']

    # Prune input fields down to required/expected values
    data = dict((k, v) for (k, v) in vars(args).items()
                if k in field_list and not (v is None))

    ptp_paramownership = cc.ptp_paramownership.create(**data)
    uuid = getattr(ptp_paramownership, 'uuid', '')
    try:
        ptp_paramownership = cc.ptp_paramownership.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('PTP ownership just set not found: %s' % uuid)
    fields = ['uuid', 'parameter_uuid', 'owner_uuid', 'created_at']
    labels = ('uuid', 'parameter', 'owner', 'created_at')
    data = [(f, getattr(ptp_paramownership, f, '')) for f in fields]
    utils.print_tuple_list(data, labels)


@utils.arg('parameter_uuid',
           metavar='<parameter uuid>',
           help="UUID of PTP parameter")
@utils.arg('owner_uuid',
           metavar='<owner uuid>',
           help="UUID of PTP instance or PTP interface")
def do_ptp_parameter_unset_owner(cc, args):
    """Remove ownership of a PTP parameter."""
    cc.ptp_paramownership.delete(args.parameter_uuid, args.owner_uuid)
    print('Removed association to PTP parameter %s', args.parameter_uuid)
