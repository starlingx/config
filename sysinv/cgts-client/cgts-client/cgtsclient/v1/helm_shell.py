#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from collections import OrderedDict
import yaml

from cgtsclient.common import utils
from cgtsclient import exc


def _print_helm_chart(chart):
    # We only want to print the fields that are in the response, that way
    # we can reuse this function for printing the override update output
    # where the system overrides aren't included.
    ordereddata = OrderedDict(sorted(chart.to_dict().items(),
                                     key=lambda t: t[0]))
    utils.print_dict(ordereddata)


def do_helm_chart_list(cc, args):
    """List system helm charts."""
    charts = cc.helm.list_charts()
    utils.print_list(charts, ['name'], ['chart name'], sortby=0)


@utils.arg('chart', metavar='<chart name>',
           help="Name of chart")
def do_helm_override_show(cc, args):
    """Show overrides for chart."""
    chart = cc.helm.get_overrides(args.chart)
    _print_helm_chart(chart)


@utils.arg('chart',
           metavar='<chart name>',
           nargs='+',
           help="Name of chart")
def do_helm_override_delete(cc, args):
    """Delete overrides for one or more charts."""
    for chart in args.chart:
        try:
            cc.helm.delete_overrides(chart)
            print 'Deleted chart %s' % chart
        except exc.HTTPNotFound:
            raise exc.CommandError('chart not found: %s' % chart)


@utils.arg('chart',
           metavar='<chart name>',
           help="Name of chart")
@utils.arg('--reuse-values', action='store_true', default=False,
           help='Should we reuse existing helm chart user override values. '
                'If --reset-values is set this is ignored')
@utils.arg('--reset-values', action='store_true', default=False,
           help='Replace any existing helm chart overrides with the ones '
                'specified.')
@utils.arg('--values', metavar='<file_name>', action='append', dest='files',
           default=[],
           help='Specify a YAML file containing helm chart override values. '
                'Can specify multiple times.')
@utils.arg('--set', metavar='<commandline_overrides>', action='append',
           default=[],
           help='Set helm chart override values on the command line (can '
                'specify multiple times or separate values with commas: '
                'key1=val1,key2=val2). These are processed after "--values" '
                'files.')
def do_helm_override_update(cc, args):
    """Update helm chart user overrides."""

    # This logic results in similar behaviour to "helm upgrade".
    flag = 'reset'
    if args.reuse_values and not args.reset_values:
        flag = 'reuse'

    # Overrides can be specified three different ways.  To preserve helm's
    # behaviour we will process all "--values" files first, then all "--set"
    # values, then finally all "--set-string" values.

    override_files = []
    # need to handle missing files
    if args.files:
        try:
            for filename in args.files:
                with open(filename, 'r') as input_file:
                    overrides = yaml.load(input_file)
                    override_files.append(yaml.dump(overrides))
        except IOError as ex:
            raise exc.CommandError('error opening values file: %s' % ex)

    override_set = []
    for override in args.set:
        override_set.append(override)

    overrides = {
        'files': override_files,
        'set': override_set,
    }

    try:
        chart = cc.helm.update_overrides(args.chart, flag, overrides)
    except exc.HTTPNotFound:
        raise exc.CommandError('helm chart not found: %s' % args.chart)
    _print_helm_chart(chart)
