#
# Copyright (c) 2017-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc


def do_license_show(cc, args):
    """Show license file content"""
    response = cc.license.show()
    error = response.get('error')
    content = response.get('content')
    if error != "":
        print("Error: %s" % error + "\n")
    else:
        print(content + "\n")


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
