#!/usr/bin/env python
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#
import os
from cgtsclient import exc
from cgtsclient.common import utils


def _print_certificate_show(certificate):
    fields = ['uuid', 'certtype', 'signature', 'start_date', 'expiry_date']
    if type(certificate) is dict:
        data = [(f, certificate.get(f, '')) for f in fields]
    else:
        data = [(f, getattr(certificate, f, '')) for f in fields]
    utils.print_tuple_list(data)


@utils.arg('certificate_uuid', metavar='<certificate_uuid>',
           help="UUID of certificate")
def do_certificate_show(cc, args):
    """Show Certificate details."""
    certificate = cc.certificate.get(args.certificate_uuid)
    if certificate:
        _print_certificate_show(certificate)
    else:
        print "No Certificates installed"


def do_certificate_list(cc, args):
    """List certificates."""
    certificates = cc.certificate.list()
    fields = ['uuid', 'certtype', 'expiry_date']
    field_labels = fields
    utils.print_list(certificates, fields, field_labels, sortby=0)


@utils.arg('certificate_file',
           metavar='<certificate_file>',
           help='Path to Certificate file (PEM format) to install. '
                'WARNING: For security reasons, the original certificate_file '
                'will be removed. Installing an invalid certificate '
                'could cause service interruption.')
@utils.arg('-p', '--passphrase',
           metavar='<passphrase>',
           help='The passphrase for the PEM file')
@utils.arg('-m', '--mode',
           metavar='<mode>',
           help="optional mode: 'tpm_mode', 'murano', 'murano_ca'. "
                "Default is 'ssl'.")
def do_certificate_install(cc, args):
    """Install certificate."""

    certificate_file = args.certificate_file
    try:
        sec_file = open(certificate_file, 'rb')
    except:
        raise exc.CommandError("Error: Could not open file %s." %
                               certificate_file)

    data = {'passphrase': args.passphrase,
            'mode': args.mode,
            'certificate_file': os.path.abspath(args.certificate_file)}

    print "WARNING: For security reasons, the original certificate, "
    print "containing the private key, will be removed, "
    print "once the private key is processed."

    try:
        response = cc.certificate.certificate_install(sec_file, data=data)
        error = response.get('error')
        if error:
            raise exc.CommandError("%s" % error)
        else:
            _print_certificate_show(response.get('certificates'))
    except exc.HTTPNotFound:
        raise exc.CommandError('Certificate not installed %s. No response.' %
                               certificate_file)
    except Exception as e:
        raise exc.CommandError('Certificate %s not installed: %s' %
                               (certificate_file, e))
