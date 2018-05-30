#!/usr/bin/env python
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

import argparse
import sys
import time

from cgtsclient.common import utils
from cgtsclient import exc


def _print_tpmconfig_show(tpmconfig):
    fields = ['uuid',
              'tpm_path',
              'created_at',
              'updated_at',
              'state',
             ]
    data = [(f, getattr(tpmconfig, f, '')) for f in fields]
    utils.print_tuple_list(data)

def do_tpmconfig_show(cc, args):
    """Show TPM config details."""

    tpmconfigs = cc.tpmconfig.list()
    if not tpmconfigs:
        return
    _print_tpmconfig_show(tpmconfigs[0])

@utils.arg('--cert_path',
           metavar='<cert_path>',
           default=None,
           help="Path to certificate to upload to TPM.")
@utils.arg('--public_path',
           metavar='<public_path>',
           default=None,
           help="Path to store public certificate.")
@utils.arg('--tpm_path',
           metavar='<tpm_path>',
           default=None,
           help="Path to store TPM object context")
def do_tpmconfig_add(cc, args):
    """Add TPM configuration."""

    field_list = ['cert_path', 'public_path', 'tpm_path']

    # use field list as filter
    user_specified_fields = dict((k, v) for (k, v) in vars(args).items()
                                if k in field_list and not (v is None))
    try:
        tpmconfig = cc.tpmconfig.create(**user_specified_fields)
    except exc.HTTPNotFound:
        raise exc.CommandError("Failed to create TPM configuration entry: "
                                "fields %s" % user_specified_fields)
    uuid = getattr(tpmconfig, 'uuid', '')
    try:
        tpmconfig = cc.tpmconfig.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError("Created TPM configuration UUID not found: %s"
                               % uuid)
    _print_tpmconfig_show(tpmconfig)

def do_tpmconfig_delete(cc, args):
    """Delete a TPM configuration."""
    try:
        tpmconfigs = cc.tpmconfig.list()
        if not tpmconfigs:
            return
        tpmconfig = tpmconfigs[0]

        cc.tpmconfig.delete(tpmconfig.uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError("Failed to delete TPM configuration entry: "
                               "no configuration found")
    print  'Deleted TPM configuration: uuid %s' % tpmconfig.uuid

@utils.arg('--cert_path',
           metavar='<cert_path>',
           default=None,
           help="Path to certificate to upload to TPM.")
@utils.arg('--public_path',
           metavar='<public_path>',
           default=None,
           help="Path to store public certificate.")
@utils.arg('--tpm_path',
           metavar='<tpm_path>',
           default=None,
           help="Path to store TPM object context")
def do_tpmconfig_modify(cc, args):
    """Modify a TPM configuration."""
    # find the TPM configuration first
    tpmconfig = None
    try:
        tpmconfigs = cc.tpmconfig.list()
        if tpmconfigs:
            tpmconfig = tpmconfigs[0]

            field_list = ['cert_path', 'public_path', 'tpm_path']
            # use field list as filter
            user_fields = dict((k, v) for (k, v) in vars(args).items()
                                if k in field_list and not (v is None))
            configured_fields = tpmconfig.__dict__
            configured_fields.update(user_fields)

            patch = []
            for (k,v) in user_fields.items():
                patch.append({'op': 'replace', 'path': '/' + k, 'value': v})
            try:
                updated_tpmconfig = cc.tpmconfig.update(tpmconfig.uuid, patch)
            except:
                raise exc.CommandError("Failed to modify TPM configuration: "
                                       "tpmconfig %s : patch %s" % 
                                       (tpmconfig.uuid, patch))

            _print_tpmconfig_show(updated_tpmconfig)
            return
    except exc.HTTPNotFound:
        pass
    finally:
        if not tpmconfig:
            raise exc.CommandError("Failed to modify TPM configuration: "
                                   "no configuration found")
