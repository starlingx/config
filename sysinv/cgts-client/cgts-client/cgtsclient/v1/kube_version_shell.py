#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import utils
from cgtsclient import exc
from collections import OrderedDict


def _print_kube_version_show(kube_version):
    ordereddata = OrderedDict(sorted(kube_version.to_dict().items(),
                                     key=lambda t: t[0]))
    utils.print_dict(ordereddata, wrap=72)


def do_kube_version_list(cc, args):
    """List all kubernetes versions"""
    versions = cc.kube_version.list()
    labels = ['version', 'target', 'state']
    fields = ['version', 'target', 'state']
    utils.print_list(versions, fields, labels, sortby=0)


@utils.arg('version', metavar='<kubernetes version>',
           help="Kubernetes version")
def do_kube_version_show(cc, args):
    """Show kubernetes version details"""
    try:
        version = cc.kube_version.get(args.version)
        _print_kube_version_show(version)
    except exc.HTTPNotFound:
        raise exc.CommandError('kubernetes version not found: %s' %
                               args.version)
