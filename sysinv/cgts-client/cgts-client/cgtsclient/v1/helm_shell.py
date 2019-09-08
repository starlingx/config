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
from cgtsclient.v1 import app as app_utils


def _print_helm_chart(chart):
    # We only want to print the fields that are in the response, that way
    # we can reuse this function for printing the override update output
    # where the system overrides aren't included.
    ordereddata = OrderedDict(sorted(chart.to_dict().items(),
                                     key=lambda t: t[0]))
    utils.print_dict(ordereddata)


def _find_overrides(cc, app, chart, namespace):
    charts = cc.helm.list_charts(app.name)
    for c in charts:
        if chart == c.name and namespace in c.namespaces:
            break
    else:
        raise exc.CommandError('Chart overrides %s:%s for application '
                               '%s not found' %
                               (chart, namespace, app.name))

    return c


@utils.arg('app',
           metavar='<app name>',
           help="Name of the application")
@utils.arg('-l', '--long',
           action='store_true',
           help='List additional fields in output')
def do_helm_override_list(cc, args):
    """List system helm charts."""
    app = app_utils._find_app(cc, args.app)
    charts = cc.helm.list_charts(app.name)

    keys = ['name', 'namespaces']
    labels = ['chart name', 'overrides namespaces']
    if args.long:
        keys.append('enabled')
        labels.append('chart enabled')

    utils.print_list(charts, keys, labels, sortby=0)


@utils.arg('app',
           metavar='<app name>',
           help="Name of the application")
@utils.arg('chart', metavar='<chart name>',
           help="Name of chart")
@utils.arg('namespace',
           metavar='<namespace>',
           help="namespace of chart overrides")
def do_helm_override_show(cc, args):
    """Show overrides for chart."""
    app = app_utils._find_app(cc, args.app)
    _find_overrides(cc, app, args.chart, args.namespace)
    chart = cc.helm.get_overrides(args.app, args.chart, args.namespace)
    _print_helm_chart(chart)


@utils.arg('app',
           metavar='<app name>',
           help="Name of the application")
@utils.arg('chart',
           metavar='<chart name>',
           help="Name of chart")
@utils.arg('namespace',
           metavar='<namespace>',
           help="namespace of chart overrides")
def do_helm_override_delete(cc, args):
    """Delete overrides for a chart."""
    app = app_utils._find_app(cc, args.app)
    _find_overrides(cc, app, args.chart, args.namespace)
    cc.helm.delete_overrides(args.app, args.chart, args.namespace)
    print('Deleted chart overrides %s:%s for application %s' %
          (args.chart, args.namespace, args.app))


@utils.arg('app',
           metavar='<app name>',
           help="Name of the application")
@utils.arg('chart',
           metavar='<chart name>',
           help="Name of chart")
@utils.arg('namespace',
           metavar='<namespace>',
           help="namespace of chart overrides")
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
           help='Set helm chart override values on the command line. Multiple '
                'override values can be specified with multiple --set arguments.'
                'These are processed after "--values" files.')
def do_helm_override_update(cc, args):
    """Update helm chart user overrides."""

    app = app_utils._find_app(cc, args.app)
    _find_overrides(cc, app, args.chart, args.namespace)

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

    chart = cc.helm.update_overrides(args.app, args.chart, args.namespace,
                                     flag, overrides)
    _print_helm_chart(chart)


@utils.arg('app',
           metavar='<app name>',
           help="Name of the application")
@utils.arg('chart',
           metavar='<chart name>',
           help="Name of the chart")
@utils.arg('namespace',
           metavar='<namespace>',
           help="Namespace of the chart")
@utils.arg('--enabled',
           metavar='<true/false>',
           help="Chart enabled.")
def do_helm_chart_attribute_modify(cc, args):
    """Modify helm chart attributes.

    This function is provided to modify system behaviorial attributes related to
    a chart. This does not modify a chart nor does it modify chart overrides
    which are managed through the helm-override-update command.
    """

    # Make sure the chart is present
    app = app_utils._find_app(cc, args.app)
    chart = _find_overrides(cc, app, args.chart, args.namespace)

    attributes = {}
    if args.enabled is not None:
        attributes.update({'enabled': args.enabled})

    chart = cc.helm.update_chart(args.app, args.chart, args.namespace,
                                 attributes)

    _print_helm_chart(chart)
