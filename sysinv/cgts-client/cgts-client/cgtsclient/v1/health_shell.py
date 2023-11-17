#
# Copyright (c) 2016-2023 Wind River Systems, Inc.
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
def do_health_query_kube_upgrade(cc, args):
    """Run the Health Check for a Kubernetes Upgrade."""
    attributes = {}
    if args.rootca is not None:
        attributes.update({'rootca': args.rootca})
    print(cc.health.get_kube_upgrade(attributes))
