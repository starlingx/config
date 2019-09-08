# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import utils
from cgtsclient import exc


def do_registry_image_list(cc, args):
    """List all images in local docker registry"""
    images = cc.registry_image.list()
    labels = ['Image Name']
    fields = ['name']
    utils.print_list(images, fields, labels, sortby=0)


@utils.arg('name', metavar='<image name>',
           help="Name of an image")
def do_registry_image_tags(cc, args):
    """List all tags for a Docker image from the local registry"""
    images = cc.registry_image.tags(args.name)
    labels = ['Image Tag']
    fields = ['tag']
    utils.print_list(images, fields, labels, sortby=0)


@utils.arg('name_and_tag', metavar='<image name and tag>',
           help="Name and tag of an image, in the form name:tag")
def do_registry_image_delete(cc, args):
    """Remove the specified Docker image from the local registry"""
    try:
        cc.registry_image.delete(args.name_and_tag)
        print('Image %s deleted, please run garbage collect to free disk space.' % args.name_and_tag)
    except exc.HTTPNotFound:
        raise exc.CommandError('Image not found: %s' % args.name_and_tag)


def do_registry_garbage_collect(cc, args):
    """Run the registry garbage collector"""

    cc.registry_image.garbage_collect()
    print('Running docker registry garbage collect')
