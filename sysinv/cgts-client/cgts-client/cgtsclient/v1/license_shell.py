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


@utils.arg('-a', '--all',
           action='store_true',
           help='List all licenses information')
def do_license_list(cc, args):
    """List all licenses"""
    labels = ['name', 'status', 'expiry_date']
    fields = ['name', 'status', 'expiry_date']

    licenses = cc.license.list()
    for license in licenses[:]:
        if not args.all:
            if license.status == 'Not-installed':
                licenses.remove(license)

    utils.print_list(licenses, fields, labels, sortby=0)


@utils.arg('license_file_path',
           metavar='<license file path>',
           default=None,
           help="Path to license file to install.")
def do_license_install(cc, args):
    """Install license file."""
    filename = args.license_file_path
    try:
        license_file = open(filename, 'rb')
    except Exception:
        raise exc.CommandError(
            "Error: Could not open file %s for read." % filename)

    response = cc.license.install_license(license_file)
    success = response.get('success')
    error = response.get('error')
    if success:
        print(success + "\n")
    if error:
        print(error + "\n")
