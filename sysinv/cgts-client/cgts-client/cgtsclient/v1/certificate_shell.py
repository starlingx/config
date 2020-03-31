#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#
import os

from cgtsclient.common import utils
from cgtsclient import exc


def _print_certificate_show(certificate):
    fields = ['uuid', 'certtype', 'signature', 'start_date', 'expiry_date']
    if type(certificate) is dict:
        data = [(f, certificate.get(f, '')) for f in fields]
        details = ('details', certificate.get('details', ''))
    else:
        data = [(f, getattr(certificate, f, '')) for f in fields]
        details = ('details', getattr(certificate, 'details', ''))
    if details[1]:
        data.append(details)

    utils.print_tuple_list(data)


@utils.arg('certificate_uuid', metavar='<certificate_uuid>',
           help="UUID of certificate or the reserved word 'tpm' "
                "to show TPM certificate")
def do_certificate_show(cc, args):
    """Show Certificate details."""
    if args.certificate_uuid == 'tpm':
        certificates = cc.certificate.list()
        for cert in certificates:
            if cert.certtype == 'tpm_mode':
                args.certificate_uuid = cert.uuid
                break
        else:
            print("No TPM certificate installed")
            return

    certificate = cc.certificate.get(args.certificate_uuid)
    if certificate:
        _print_certificate_show(certificate)
    else:
        print("No Certificates installed")


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
           help="optional mode: 'tpm_mode',"
                "'docker_registry, 'openstack', 'openstack_ca', 'ssl_ca'. "
                "Default is 'ssl'.")
def do_certificate_install(cc, args):
    """Install certificate."""

    certificate_file = args.certificate_file
    try:
        sec_file = open(certificate_file, 'rb')
    except Exception:
        raise exc.CommandError("Error: Could not open file %s." %
                               certificate_file)

    data = {'passphrase': args.passphrase,
            'mode': args.mode}

    print("WARNING: For security reasons, the original certificate, ")
    print("containing the private key, will be removed, ")
    print("once the private key is processed.")

    try:
        response = cc.certificate.certificate_install(sec_file, data=data)
        error = response.get('error')
        if error:
            raise exc.CommandError("%s" % error)
    except exc.HTTPNotFound:
        raise exc.CommandError('Certificate not installed %s. No response.' %
                               certificate_file)
    except Exception as e:
        raise exc.CommandError('Certificate %s not installed: %s' %
                               (certificate_file, e))
    else:
        certificates = response.get('certificates')
        for certificate in certificates:
            _print_certificate_show(certificate)
        try:
            os.remove(certificate_file)
        except OSError:
            raise exc.CommandError('Error: Could not remove the '
                                   'certificate %s' % certificate_file)

@utils.arg('certificate_uuid', metavar='<certificate_uuid>',
           help="UUID of certificate to uninstall")
@utils.arg('-m', '--mode',
           metavar='<mode>',
           help="Supported mode: 'ssl_ca'.")
def do_certificate_uninstall(cc, args):
    """Uninstall certificate."""

    supported_modes = ['ssl_ca']
    if args.mode not in supported_modes:
        raise exc.CommandError('Unsupported mode: %s' % args.mode)

    cc.certificate.certificate_uninstall(args.certificate_uuid)
    print('Uninstalled certificate: %s' % (args.certificate_uuid))
