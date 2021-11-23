#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# All Rights Reserved.
#

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils


# Kubernetes constants
KUBE_ROOTCA_UPDATE_COMPLETED = 'update-completed'
KUBE_ROOTCA_UPDATE_ABORTED = 'update-aborted'


def _print_kube_rootca_update_show(obj):
    fields = ['uuid', 'state', 'from_rootca_cert', 'to_rootca_cert',
              'created_at', 'updated_at']
    optional_fields = []
    data = [(f, getattr(obj, f, '')) for f in fields]
    if optional_fields:
        data += [(f, getattr(obj, f, '')) for f in optional_fields
                 if hasattr(obj, f)]
    utils.print_tuple_list(data)


def _print_kube_rootca_host_update_show(obj):
    fields = ['uuid', 'state', 'effective_rootca_cert',
              'target_rootca_cert', 'created_at', 'updated_at']
    optional_fields = []
    data = [(f, getattr(obj, f, '')) for f in fields]
    if optional_fields:
        data += [(f, getattr(obj, f, '')) for f in optional_fields
                 if hasattr(obj, f)]
    utils.print_tuple_list(data)


@utils.arg('hostnameorid', metavar='<hostname or id>',
           help="Name or ID of host")
@utils.arg('--phase',
           choices=['trust-both-cas', 'update-certs', 'trust-new-ca'],
           help="Specify the phase of the update")
def do_kube_rootca_host_update(cc, args):
    """Update root CA certificate on a host."""

    ihost = ihost_utils._find_ihost(cc, args.hostnameorid)
    if args.phase in ['trust-both-cas', 'update-certs', 'trust-new-ca']:
        kube_update_host_rootca = cc.ihost.kube_update_rootca(ihost.uuid,
                                                              args.phase)
    else:
        raise exc.CommandError('Invalid phase value: %s' % args.phase)

    _print_kube_rootca_host_update_show(kube_update_host_rootca)


@utils.arg('--phase',
           choices=['trust-both-cas', 'trust-new-ca'],
           help="Specify the phase of the update")
def do_kube_rootca_pods_update(cc, args):
    """Update root CA certificate for pods."""

    if args.phase in ['trust-both-cas', 'trust-new-ca']:
        kube_rootca_update = \
            cc.kube_rootca_update.rootCA_pods_update(args.phase)
    else:
        raise exc.CommandError('Invalid phase value: %s' % args.phase)

    _print_kube_rootca_update_show(kube_rootca_update)


@utils.arg('-f', '--force',
           action='store_true',
           default=False,
           help="Ignore non management-affecting alarms")
def do_kube_rootca_update_start(cc, args):
    """Start a new procedure for kubernetes rootCA update """

    kube_rootca_update = cc.kube_rootca_update.create(args.force)
    uuid = getattr(kube_rootca_update, 'uuid', '')

    try:
        kube_rootca_update = cc.kube_rootca_update.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created kubernetes rootca update UUID not found: %s'
                               % uuid)

    _print_kube_rootca_update_show(kube_rootca_update)


@utils.arg('certificate_file',
           metavar='<certificate_file>',
           help='Path to the kubernetes certificate file (in PEM format) to upload.')
def do_kube_rootca_update_upload_cert(cc, args):
    """Upload new kubernetes rootCA """

    certificate_file = args.certificate_file
    try:
        with open(certificate_file, 'rb') as sec_file:
            cert_upload = cc.kube_rootca_update.rootCA_upload(sec_file)
    except Exception:
        raise exc.CommandError("Error: Could not open file %s." %
                               certificate_file)

    if cert_upload.get("error"):
        print(cert_upload.get("error"))
    else:
        # Show new rootca certificate identifier <issuer_hash>-<serial_number>
        print("Uploaded new rootca certificate: %s" % cert_upload.get("success"))


@utils.arg('--expiry-date',
           default=None,
           help='Optional argument to define expiry date '
                'in the format of YYYY-MM-DD for k8s root'
                'CA to be generated')
@utils.arg('--subject',
           default=None,
           help='Subject to be set on new kubernetes root CA.Should '
                'have the format <parameter_initials>=<value> and '
                'supports C(Country), ST(State/Province), L(Locality) '
                'O(Organization), OU(OrganizationalUnit), '
                'CN(CommonName) subject parameters. An example is an '
                'entry like C=US ST=California L=San Francisco '
                'O=StarlingX OU=Company1 CN=Subject Example')
def do_kube_rootca_update_generate_cert(cc, args):
    """Generate new kubernetes rootCA"""

    certificate = cc.kube_rootca_update.rootCA_generate(args.expiry_date, args.subject)

    if certificate.error:
        print(certificate.error)
    else:
        # Show new rootca certificate identifier <issuer_hash>-<serial_number>
        print("Generated new rootca certificate: %s" % certificate.success)


def do_kube_rootca_update_show(cc, args):
    """Retrieves kubernetes rootCA update status"""

    update_status = cc.kube_rootca_update.get_list()

    fields = ['uuid', 'state', 'from_rootca_cert', 'to_rootca_cert',
              'created_at', 'updated_at']

    utils.print_list(update_status, fields, fields)


def do_kube_rootca_host_update_list(cc, args):
    """Retrieves kubernetes rootCA update status on each host"""

    update_status_list = cc.kube_rootca_update.host_update_list()

    fields = ['hostname', 'personality', 'state', 'effective_rootca_cert',
              'target_rootca_cert', 'created_at', 'updated_at']

    utils.print_list(update_status_list, fields, fields)


def do_kube_rootca_update_complete(cc, args):
    """Marks the rootca update as complete"""

    patch = []
    patch.append({'op': 'replace',
                  'path': '/state',
                  'value': KUBE_ROOTCA_UPDATE_COMPLETED})

    update_status = cc.kube_rootca_update.update_complete(patch)
    _print_kube_rootca_update_show(update_status)


def do_kube_rootca_update_abort(cc, args):
    """Marks the rootca update as aborted"""

    patch = []
    patch.append({'op': 'replace',
                  'path': '/state',
                  'value': KUBE_ROOTCA_UPDATE_ABORTED})

    update_status = cc.kube_rootca_update.update_complete(patch)
    _print_kube_rootca_update_show(update_status)
