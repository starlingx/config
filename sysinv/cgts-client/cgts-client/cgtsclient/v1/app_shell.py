#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import os
import re

from cgtsclient.common import utils
from cgtsclient import exc
from collections import OrderedDict


def _print_application_show(app):
    ordereddata = OrderedDict(sorted(app.to_dict().items(),
                                     key=lambda t: t[0]))
    utils.print_dict(ordereddata, wrap=72)


def _print_reminder_msg(app_name):
    print("Please use 'system application-list' or 'system "
          "application-show %s' to view the current progress." % app_name)


def _is_url(url_str):
    # Django url validation patterns
    r = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)'  # domain...
        r'+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    url = r.match(url_str)
    if url:
        return True
    else:
        return False


def _application_check(args):
    tarfile = args.tarfile

    if not _is_url(tarfile):
        if not os.path.isabs(tarfile):
            tarfile = os.path.join(os.getcwd(), tarfile)

        if not os.path.isfile(tarfile):
            raise exc.CommandError("Error: Tar file %s does not exist" % tarfile)
        if not tarfile.endswith('.tgz') and not tarfile.endswith('.tar.gz'):
            raise exc.CommandError("Error: File %s has unrecognizable tar file "
                                   "extension. Supported extensions are: .tgz "
                                   "and .tar.gz" % tarfile)

    data = {'tarfile': tarfile}
    if args.app_name:
        data.update({'name': args.app_name})
    if args.app_version:
        data.update({'app_version': args.app_version})
    return data


def do_application_list(cc, args):
    """List all containerized applications"""
    apps = cc.app.list()
    labels = ['application', 'version', 'manifest name', 'manifest file', 'status', 'progress']
    fields = ['name', 'app_version', 'manifest_name', 'manifest_file', 'status', 'progress']
    utils.print_list(apps, fields, labels, sortby=0)


@utils.arg('name', metavar='<app name>',
           help="Name of the application")
def do_application_show(cc, args):
    """Show application details"""
    try:
        app = cc.app.get(args.name)
        _print_application_show(app)
    except exc.HTTPNotFound:
        raise exc.CommandError('application not found: %s' % args.name)


@utils.arg('tarfile', metavar='<tar file>',
           help='Tarball containing application manifest, Helm charts and'
                ' config file')
@utils.arg('-n', '--app-name',
           metavar='<app name>',
           help='Name of the application')
@utils.arg('-v', '--app-version',
           metavar='<app version>',
           help='Version of the application')
def do_application_upload(cc, args):
    """Upload application Helm chart(s) and manifest"""
    data = _application_check(args)
    response = cc.app.upload(data)
    _print_application_show(response)
    _print_reminder_msg(response.name)


@utils.arg('tarfile', metavar='<tar file>',
           help='Tarball containing application manifest, Helm charts and'
                ' config file')
@utils.arg('-n', '--app-name',
           metavar='<app name>',
           help='Name of the application')
@utils.arg('-v', '--app-version',
           metavar='<app version>',
           help='Version of the application')
def do_application_update(cc, args):
    """Update the deployed application to a different version"""
    data = _application_check(args)
    response = cc.app.update(data)
    _print_application_show(response)
    _print_reminder_msg(response.name)


@utils.arg('name', metavar='<app name>',
           help='Name of the application')
@utils.arg('-m', '--mode',
           metavar='<mode>',
           default=None,
           help=('The mode is application specific. It controls how applicaton'
                 ' manifest is applied.'))
def do_application_apply(cc, args):
    """Apply/reapply the application manifest"""
    try:
        fields = ['mode']

        data = dict((k, v) for (k, v) in vars(args).items()
                    if k in fields and not (v is None))

        response = cc.app.apply(args.name, data)
        _print_application_show(response)
        _print_reminder_msg(args.name)
    except exc.HTTPNotFound:
        raise exc.CommandError('Application not found: %s' % args.name)


@utils.arg('name', metavar='<app name>',
           help='Name of the application to be uninstalled')
def do_application_remove(cc, args):
    """Uninstall the application"""
    try:
        response = cc.app.remove(args.name)
        _print_application_show(response)
        _print_reminder_msg(args.name)
    except exc.HTTPNotFound:
        raise exc.CommandError('Application not found: %s' % args.name)


@utils.arg('name', metavar='<application name>',
           help='Name of the application, the current operation of which '
                'is to be aborted.')
def do_application_abort(cc, args):
    """Abort the current application operation"""
    try:
        cc.app.abort(args.name)
        print('Application abort request has been accepted. If the '
              'previous operation has not completed/failed, it will '
              'be cancelled shortly.')
    except exc.HTTPNotFound:
        raise exc.CommandError('Application not found: %s' % args.name)


@utils.arg('name', metavar='<application name>',
           help='Name of the application to be deleted')
def do_application_delete(cc, args):
    """Remove the uninstalled application from the system"""
    try:
        cc.app.delete(args.name)
        print('Application %s deleted.' % args.name)
    except exc.HTTPNotFound:
        raise exc.CommandError('Application not found: %s' % args.name)
