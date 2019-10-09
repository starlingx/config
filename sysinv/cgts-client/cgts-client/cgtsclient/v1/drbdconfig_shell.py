#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from __future__ import print_function
import argparse
import sys
import time

from cgtsclient.common import utils
from cgtsclient import exc

CONTROLLER = 'controller'


def _print_drbdsync_show(drbdconfig):
    fields = ['uuid',
              'isystem_uuid',
              'created_at',
              'updated_at',
              'link_util',
              'num_parallel',
              'rtt_ms']
    data = [(f, getattr(drbdconfig, f, '')) for f in fields]
    utils.print_tuple_list(data)


def _print_controller_config_show(ihosts):
    fields = ['id', 'hostname', 'personality',
              'administrative', 'operational', 'availability',
              'config_status']
    field_labels = list(fields)
    utils.print_list(ihosts, fields, field_labels, sortby=0)


def do_drbdsync_show(cc, args):
    """Show DRBD sync config details."""

    drbdconfigs = cc.drbdconfig.list()
    _print_drbdsync_show(drbdconfigs[0])
    print('')

    ihosts = cc.ihost.list_personality(personality=CONTROLLER)
    _print_controller_config_show(ihosts)


@utils.arg('--util',
           metavar='<percent>',
           default=None,
           help="Engineered percentage of link utilization for DRBD sync.")
@utils.arg('--rtt_ms',
           metavar='<round-trip-time ms>',
           default=None,
           help=argparse.SUPPRESS)
def do_drbdsync_modify(cc, args):
    """Modify DRBD sync rate parameters."""

    drbdconfigs = cc.drbdconfig.list()
    drbd = drbdconfigs[0]

    attributes = []
    if args.util is not None:
        attributes.append('link_util=%s' % args.util)
    if args.rtt_ms is not None:
        attributes.append('rtt_ms=%s' % args.rtt_ms)
    if len(attributes) > 0:
        attributes.append('action=apply')
    else:
        print("No options provided.")
        return

    patch = utils.args_array_to_patch("replace", attributes)
    rwfields = ['link_util', 'rtt_ms', 'action']
    for pa in patch:
        key = pa['path'][1:]
        if key not in rwfields:
            raise exc.CommandError('Invalid or Read-Only attribute: %s'
                                   % pa['path'][1:])

    # Prevent update if controllers are mid-configuration
    personality = 'controller'
    is_config = False
    ihosts = cc.ihost.list_personality(personality=CONTROLLER)
    for ihost in ihosts:
        if ihost.config_target and ihost.config_applied != ihost.config_target:
            is_config = True
            print("host %s is configuring ..." % (ihost.hostname))
    if is_config:
        print("Cannot apply update while controller configuration in progress.")
        return

    try:
        drbd = cc.drbdconfig.update(drbd.uuid, patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('DRBD Config not found: %s' % drbd.uuid)

    _print_drbdsync_show(drbd)

    # Wait for configuration to finish.
    wait_interval = 8
    configuration_timeout = 90
    do_wait = True
    LOOP_MAX = int(configuration_timeout / wait_interval)
    for x in range(0, LOOP_MAX):
        ihosts = cc.ihost.list_personality(personality=CONTROLLER)
        do_wait = False
        hosts = []
        for ihost in ihosts:
            if ihost.config_target and ihost.config_applied != ihost.config_target:
                do_wait = True
                hosts.append(ihost.hostname)
        if do_wait:
            if x == 0:
                print(("waiting for hosts: %s to finish configuring" %
                       ', '.join(hosts)), end=' ')
                sys.stdout.flush()
            else:
                print(".", end=' ')
                sys.stdout.flush()
            time.sleep(wait_interval)
        else:
            print('')
            print("DRBD configuration finished.")
            break
    if do_wait:
        print("DRBD configuration timed out.")
