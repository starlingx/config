########################################################################
#
# Copyright (c) 2018-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from cgtsclient.common import utils
from cgtsclient import exc


def _print_ptp_show(ptp):
    fields = ['uuid', 'mode', 'transport', 'mechanism',
              'isystem_uuid', 'created_at', 'updated_at']
    data = [(f, getattr(ptp, f, '')) for f in fields]
    utils.print_tuple_list(data)


def do_ptp_show(cc, args):
    """Show PTP (Precision Time Protocol) attributes."""

    ptps = cc.ptp.list()

    _print_ptp_show(ptps[0])


def donot_config_ptp_list(cc, args):
    """List ptps."""

    ptps = cc.ptp.list()

    field_labels = ['uuid', 'mode', 'transport', 'mechanism']
    fields = ['uuid', 'mode', 'transport', 'mechanism']
    utils.print_list(ptps, fields, field_labels, sortby=1)


@utils.arg('--mode',
           metavar='<mode>',
           default=None,
           help="PTP time stamping mode.")
@utils.arg('--transport',
           metavar='<transport>',
           default=None,
           help="PTP transport protocol.")
@utils.arg('--mechanism',
           metavar='<mechanism>',
           default=None,
           help="PTP delay mechanism.")
def do_ptp_modify(cc, args):
    """Modify PTP attributes."""

    ptps = cc.ptp.list()
    ptp = ptps[0]
    op = "replace"

    attributes = []

    if args.mode is not None:
        attributes.append('mode=%s' % args.mode)
    if args.transport is not None:
        attributes.append('transport=%s' % args.transport)
    if args.mechanism is not None:
        attributes.append('mechanism=%s' % args.mechanism)
    if len(attributes) == 0:
        print("No options provided.")
        return

    patch = utils.args_array_to_patch("replace", attributes)
    try:
        ptp = cc.ptp.update(ptp.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('PTP not found: %s' % ptp.uuid)

    _print_ptp_show(ptp)


def do_ptp_apply(cc, args):
    """Apply the PTP config."""

    cc.ptp.apply()

    print('Applying PTP configuration')
