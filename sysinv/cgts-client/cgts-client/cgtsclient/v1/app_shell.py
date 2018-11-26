#!/usr/bin/env python
# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import os

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


def do_application_list(cc, args):
    """List all containerized applications"""
    apps = cc.app.list()
    labels = ['application', 'manifest name', 'manifest file', 'status', 'progress']
    fields = ['name', 'manifest_name', 'manifest_file', 'status', 'progress']
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


@utils.arg('name', metavar='<app name>',
           help='Name of the application')
@utils.arg('tarfile', metavar='<tar file>',
           help='Tarball containing application manifest, helm charts and'
                ' config file')
def do_application_upload(cc, args):
    """Upload application Helm chart(s) and manifest"""
    tarfile = args.tarfile
    if not os.path.isabs(tarfile):
        tarfile = os.path.join(os.getcwd(), tarfile)

    if not os.path.isfile(tarfile):
        raise exc.CommandError("Error: Tar file %s does not exist" % tarfile)
    if not tarfile.endswith('.tgz') and not tarfile.endswith('.tar.gz'):
        raise exc.CommandError("Error: File %s has unrecognizable tar file "
                               "extension. Supported extensions are: .tgz "
                               "and .tar.gz" % tarfile)

    data = {'name': args.name,
            'tarfile': tarfile}
    response = cc.app.upload(data)
    _print_application_show(response)
    _print_reminder_msg(args.name)


@utils.arg('name', metavar='<app name>',
           help='Name of the application')
def do_application_apply(cc, args):
    """Apply/reapply the application manifest"""
    try:
        response = cc.app.apply(args.name)
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
           help='Name of the application to be deleted')
def do_application_delete(cc, args):
    """Remove the uninstalled application from the system"""
    try:
        cc.app.delete(args.name)
        print('Application %s deleted.' % args.name)
    except exc.HTTPNotFound:
        raise exc.CommandError('Application not found: %s' % args.name)
