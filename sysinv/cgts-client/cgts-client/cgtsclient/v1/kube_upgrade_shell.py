#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import utils
from cgtsclient import exc

# Kubernetes constants
KUBE_UPGRADE_STATE_DOWNLOADING_IMAGES = 'downloading-images'
KUBE_UPGRADE_STATE_UPGRADING_NETWORKING = 'upgrading-networking'
KUBE_UPGRADE_STATE_COMPLETE = 'upgrade-complete'


def _print_kube_upgrade_show(obj):
    fields = ['uuid', 'from_version', 'to_version', 'state', 'created_at',
              'updated_at']
    data = [(f, getattr(obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


def do_kube_upgrade_show(cc, args):
    """Show kubernetes upgrade details and attributes."""

    kube_upgrades = cc.kube_upgrade.list()
    if kube_upgrades:
        _print_kube_upgrade_show(kube_upgrades[0])
    else:
        print('A kubernetes upgrade is not in progress')


@utils.arg('to_version', metavar='<target kubernetes version>',
           help="target Kubernetes version")
@utils.arg('-f', '--force',
           action='store_true',
           default=False,
           help="Ignore non management-affecting alarms")
def do_kube_upgrade_start(cc, args):
    """Start a kubernetes upgrade. """

    kube_upgrade = cc.kube_upgrade.create(args.to_version, args.force)
    uuid = getattr(kube_upgrade, 'uuid', '')
    try:
        kube_upgrade = cc.kube_upgrade.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created kubernetes upgrade UUID not found: %s'
                               % uuid)
    _print_kube_upgrade_show(kube_upgrade)


def do_kube_upgrade_download_images(cc, args):
    """Download kubernetes images."""

    data = dict()
    data['state'] = KUBE_UPGRADE_STATE_DOWNLOADING_IMAGES

    patch = []
    for (k, v) in data.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})
    try:
        kube_upgrade = cc.kube_upgrade.update(patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('Kubernetes upgrade UUID not found')

    _print_kube_upgrade_show(kube_upgrade)


def do_kube_upgrade_networking(cc, args):
    """Upgrade kubernetes networking."""

    data = dict()
    data['state'] = KUBE_UPGRADE_STATE_UPGRADING_NETWORKING

    patch = []
    for (k, v) in data.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})
    try:
        kube_upgrade = cc.kube_upgrade.update(patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('Kubernetes upgrade UUID not found')

    _print_kube_upgrade_show(kube_upgrade)


def do_kube_upgrade_complete(cc, args):
    """Complete a kubernetes upgrade."""

    data = dict()
    data['state'] = KUBE_UPGRADE_STATE_COMPLETE

    patch = []
    for (k, v) in data.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})
    try:
        kube_upgrade = cc.kube_upgrade.update(patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('Kubernetes upgrade UUID not found')

    _print_kube_upgrade_show(kube_upgrade)


def do_kube_upgrade_delete(cc, args):
    """Delete a kubernetes upgrade."""

    try:
        cc.kube_upgrade.delete()
    except exc.HTTPNotFound:
        raise exc.CommandError('Kubernetes upgrade not found')

    print("Kubernetes upgrade deleted")
