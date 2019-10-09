#
# Copyright (c) 2013-2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import constants
from cgtsclient.common import utils
from cgtsclient import exc
from collections import OrderedDict


def _print_iextoam_show(iextoam, cc):
    fields = ['uuid',
              'oam_subnet',
              'oam_gateway_ip',
              'oam_floating_ip',
              'oam_c0_ip',
              'oam_c1_ip',
              'isystem_uuid',
              'created_at',
              'updated_at']
    fields_region = ['oam_start_ip', 'oam_end_ip']

    region_config = getattr(iextoam, 'region_config') or False
    if region_config:
        fields.extend(fields_region)
        # labels.extend(labels_region)

    data = dict([(f, getattr(iextoam, f, '')) for f in fields])
    # Rename the floating IP field and remove the
    # fields that are not applicable for a simplex system
    if cc.isystem.list()[0].system_mode == constants.SYSTEM_MODE_SIMPLEX:
        data['oam_ip'] = data.pop('oam_floating_ip')
        del data['oam_c0_ip']
        del data['oam_c1_ip']

    ordereddata = OrderedDict(sorted(data.items(), key=lambda t: t[0]))

    utils.print_dict(ordereddata, wrap=72)


def do_oam_show(cc, args):
    """Show external OAM attributes."""

    iextoams = cc.iextoam.list()

    iextoam = iextoams[0]

    # iextoam = cc.iextoam.get(args.uuid)
    _print_iextoam_show(iextoam, cc)


def donot_config_oam_list(cc, args):
    """List external oams."""

    iextoams = cc.iextoam.list()

    field_labels = ['uuid', 'oam_subnet', 'oam_gateway_ip',
                    'oam_floating_ip', 'oam_c0_ip',
                    'oam_c1_ip']

    fields = ['uuid', 'oam_subnet', 'oam_gateway_ip',
              'oam_floating_ip', 'oam_c0_ip',
              'oam_c1_ip']
    utils.print_list(iextoams, fields, field_labels, sortby=1)


@utils.arg('attributes',
           metavar='<path=value>',
           nargs='+',
           action='append',
           default=[],
           help="OAM IP attributes to modify ")
def do_oam_modify(cc, args):
    """Modify external OAM attributes."""

    iextoams = cc.iextoam.list()

    iextoam = iextoams[0]

    if cc.isystem.list()[0].system_mode == constants.SYSTEM_MODE_SIMPLEX:
        for i, elem in enumerate(args.attributes[0]):
            path, value = elem.split("=", 1)
            if path == 'oam_ip':
                args.attributes[0][i] = 'oam_floating_ip=' + value
            if path in ['oam_floating_ip', 'oam_c0_ip', 'oam_c1_ip']:
                raise exc.CommandError('%s is not supported on '
                                       'a simplex system' % path)

    patch = utils.args_array_to_patch("replace", args.attributes[0])
    try:
        iextoam = cc.iextoam.update(iextoam.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('OAM IP not found: %s' % iextoam.uuid)

    _print_iextoam_show(iextoam, cc)
