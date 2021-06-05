#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import utils
from cgtsclient import exc
from collections import OrderedDict


def _print_kube_cluster_show(kube_cluster):
    ordereddata = OrderedDict(sorted(kube_cluster.to_dict().items(),
                                     key=lambda t: t[0]))
    utils.print_dict(ordereddata, wrap=72)


def do_kube_cluster_list(cc, args):
    """List all kubernetes clusters"""
    versions = cc.kube_cluster.list()
    fields = ['cluster_name', 'cluster_version', 'cluster_api_endpoint']
    labels = fields
    utils.print_list(versions, fields, labels, sortby=0)


@utils.arg('name', metavar="<cluster-name>",
           help="Kubernetes cluster name", default=None)
def do_kube_cluster_show(cc, args):
    """Show kubernetes cluster details"""
    try:
        name = cc.kube_cluster.get(args.name)
        _print_kube_cluster_show(name)
    except exc.HTTPNotFound:
        raise exc.CommandError('kubernetes cluster not found: %s' % args.name)
