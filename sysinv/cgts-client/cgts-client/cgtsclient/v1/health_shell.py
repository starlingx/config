#
# Copyright (c) 2016-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils


def do_health_query(cc, args):
    """Run the Health Check."""
    print(cc.health.get())


def do_health_query_upgrade(cc, args):
    """Run the Health Check for an Upgrade."""
    print(cc.health.get_upgrade())


@utils.arg('--rootca',
           action='store_true',
           default=False,
           help='Whether additional RootCA verifications should be executed')
@utils.arg('--alarm-ignore-list',
           metavar='<alarm_id,alarm_id,...>',
           default=None,
           help='Comma separated list of alarm IDs to ignore during the '
                'health check')
@utils.arg('--use-default-ignore-list',
           action='store_true',
           default=False,
           help='Also ignore the alarms that are expected during a '
                'Kubernetes upgrade, as configured on the system. The '
                'list is added to the one given by --alarm-ignore-list')
def do_health_query_kube_upgrade(cc, args):
    """Run the Health Check for a Kubernetes Upgrade."""
    attributes = {
        'rootca': args.rootca,
        'alarm_ignore_list': args.alarm_ignore_list,
        'use_default_ignore_list': args.use_default_ignore_list,
    }
    print(cc.health.get_kube_upgrade(attributes))
