#!/usr/bin/env python
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc


def _print_firewallrules_show(firewallrules):
    fields = ['uuid', 'firewall_sig', 'updated_at']
    if type(firewallrules) is dict:
        data = [(f, firewallrules.get(f, '')) for f in fields]
    else:
        data = [(f, getattr(firewallrules, f, '')) for f in fields]
    utils.print_tuple_list(data)


def do_firewall_rules_show(cc, args):
    """Show Firewall Rules attributes."""

    firewallrules = cc.firewallrules.list()

    _print_firewallrules_show(firewallrules[0])


@utils.arg('firewall_rules_path',
           metavar='<firewall rules path>',
           default=None,
           help="Path to custom firewall rule file to install.")
def do_firewall_rules_install(cc, args):
    """Install firewall rules."""
    filename = args.firewall_rules_path
    try:
        fw_file = open(filename, 'rb')
    except Exception:
        raise exc.CommandError("Error: Could not open file %s for read." %
                               filename)
    try:
        response = cc.firewallrules.import_firewall_rules(fw_file)
        error = response.get('error')
        if error:
            raise exc.CommandError("%s" % error)
        else:
            _print_firewallrules_show(response.get('firewallrules'))
    except exc.HTTPNotFound:
        raise exc.CommandError('firewallrules not installed %s' %
                               filename)
