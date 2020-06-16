#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from cgtsclient.common import utils
from cgtsclient import exc
import os


def _print_device_image_show(obj):
    fields = ['uuid', 'bitstream_type',
              'pci_vendor', 'pci_device',
              'bitstream_id', 'key_signature', 'revoke_key_id',
              'name', 'description', 'image_version', 'applied_labels']

    if type(obj) is dict:
        data = [(f, obj.get(f, '')) for f in fields]
    else:
        data = [(f, getattr(obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


@utils.arg('device_image_id',
           metavar='<device_image_id>',
           help="UUID or name of device_image")
def do_device_image_show(cc, args):
    """Show device image details."""

    device_image = cc.device_image.get(args.device_image_id)
    _print_device_image_show(device_image)


def do_device_image_list(cc, args):
    """List device images."""

    labels = ['uuid', 'bitstream_type', 'pci_vendor', 'pci_device',
              'bitstream_id', 'key_signature', 'revoke_key_id',
              'name', 'description', 'image_version', 'applied_labels']
    fields = ['uuid', 'bitstream_type', 'pci_vendor', 'pci_device',
              'bitstream_id', 'key_signature', 'revoke_key_id',
              'name', 'description', 'image_version', 'applied_labels']
    device_images = cc.device_image.list()
    utils.print_list(device_images, fields, labels, sortby=1)


@utils.arg('bitstream_file',
           metavar='<bitstream_file>',
           help='Path to Bitstream file [REQUIRED] ')
@utils.arg('bitstream_type',
           metavar='<bitstream_type>',
           choices=['root-key', 'functional', 'key-revocation'],
           help="Type of the device image bitstream [REQUIRED]")
@utils.arg('pci_vendor',
           metavar='<pci_vendor>',
           help="PCI vendor (hexadecimal) of the device image [REQUIRED]")
@utils.arg('pci_device',
           metavar='<pci_device>',
           help="PCI device (hexadecimal) of the device image [REQUIRED]")
@utils.arg('--bitstream-id',
           metavar='<bitstream_id>',
           help='Bitstream ID (hexadecimal) of the functional device image')
@utils.arg('--key-signature',
           metavar='<key_signature>',
           help='Key signature (hexadecimal) of the root-key device image')
@utils.arg('--revoke-key-id',
           metavar='<revoke_key_id>',
           help='Key ID of the key revocation device image')
@utils.arg('--name',
           metavar='<name>',
           help='Name of the device image')
@utils.arg('--description',
           metavar='<description>',
           help='Description of the device image')
@utils.arg('--image-version',
           metavar='<version>',
           help='Version of the device image')
@utils.arg('-u', '--uuid',
           metavar='<uuid>',
           help='UUID of the device image')
def do_device_image_upload(cc, args):
    """Upload a device image."""

    if not os.path.isfile(args.bitstream_file):
        raise exc.CommandError('Bitstream file does not exist: %s' %
                               args.bitstream_file)

    field_list = ['uuid', 'bitstream_type', 'pci_vendor', 'pci_device',
                  'bitstream_id', 'key_signature', 'revoke_key_id',
                  'name', 'description', 'image_version']

    # Prune input fields down to required/expected values
    user_fields = dict((k, v) for (k, v) in vars(args).items()
                       if k in field_list and not (v is None))

    try:
        response = cc.device_image.upload(args.bitstream_file, **user_fields)
        error = response.get('error')
        if error:
            raise exc.CommandError("%s" % error)
    except exc.HTTPNotFound:
        raise exc.CommandError(
            'Device image not uploaded for %s. No response.' % args.bitstream_file)
    except Exception as e:
        raise exc.CommandError('Device image not uploaded for %s: %s' %
                               (args.bitstream_file, e))
    else:
        device_image = response.get('device_image')
        _print_device_image_show(device_image)


@utils.arg('device_image_uuid', metavar='<device_image_uuid>',
           help='UUID of the device image')
@utils.arg('attributes',
           metavar='<name=value>',
           nargs='*',
           action='append',
           default=[],
           help="List of device labels")
def do_device_image_apply(cc, args):
    """Apply the device image"""
    attributes = utils.extract_keypairs(args)
    try:
        response = cc.device_image.apply(args.device_image_uuid,
                                         attributes)
        _print_device_image_show(response)
    except exc.HTTPNotFound:
        raise exc.CommandError('Device image apply failed')


@utils.arg('device_image_uuid', metavar='<device_image_uuid>',
           help='UUID of the device image')
@utils.arg('attributes',
           metavar='<name=value>',
           nargs='*',
           action='append',
           default=[],
           help="List of device labels")
def do_device_image_remove(cc, args):
    """Remove the device image"""
    attributes = utils.extract_keypairs(args)
    try:
        response = cc.device_image.remove(args.device_image_uuid,
                                          attributes)
        _print_device_image_show(response)
    except exc.HTTPNotFound:
        raise exc.CommandError('Device image remove failed')


@utils.arg('device_image_uuid',
           metavar='<device_image_uuid>',
           help="UUID of device image entry")
def do_device_image_delete(cc, args):
    """Delete a device image."""

    cc.device_image.delete(args.device_image_uuid)
    print('Deleted device image: %s' % args.device_image_uuid)
