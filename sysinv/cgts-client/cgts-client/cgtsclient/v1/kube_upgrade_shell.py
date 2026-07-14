#
# Copyright (c) 2019-2023,2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import json
import os

from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import ihost as ihost_utils

# Kubernetes constants
KUBE_UPGRADE_STATE_PRE_UPDATING_APPS = 'pre-updating-apps'
KUBE_UPGRADE_STATE_DOWNLOADING_IMAGES = 'downloading-images'
KUBE_UPGRADE_STATE_UPGRADING_NETWORKING = 'upgrading-networking'
KUBE_UPGRADE_STATE_UPGRADING_STORAGE = 'upgrading-storage'
KUBE_UPGRADE_STATE_COMPLETE = 'upgrade-complete'
KUBE_UPGRADE_STATE_UPGRADING_FIRST_MASTER = 'upgrading-first-master'
KUBE_UPGRADE_STATE_UPGRADING_SECOND_MASTER = 'upgrading-second-master'
KUBE_UPGRADE_STATE_ABORTING = 'upgrade-aborting'
KUBE_UPGRADE_STATE_CORDON = 'cordon-started'
KUBE_UPGRADE_STATE_UNCORDON = 'uncordon-started'
KUBE_UPGRADE_STATE_POST_UPDATING_APPS = 'post-updating-apps'

SOFTWARE_STORAGE_DIR = "/opt/software"
SYSTEM_DEPLOY_JSON_FILE = "%s/system_deploy.json" % SOFTWARE_STORAGE_DIR


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


@utils.arg('to_version',
           metavar='<target kubernetes version>',
           nargs='?',
           const='',
           help="target Kubernetes version")
@utils.arg('-f', '--force',
           action='store_true',
           default=False,
           help="Ignore non management-affecting alarms")
def do_kube_upgrade_start(cc, args):
    """Start a kubernetes upgrade. """
    if not os.path.exists(SYSTEM_DEPLOY_JSON_FILE):
        # This is a legacy k8s upgrade
        if not args.to_version:
            raise Exception('Missing <target kubernetes version>. '
                            'To see help, run "system help kube-upgrade-start"')
        to_version = args.to_version
    else:
        try:
            with open(SYSTEM_DEPLOY_JSON_FILE) as file:
                deploy_state = json.load(file)
            to_k8s_version = deploy_state["system_deploy"]["to_k8s_version"]
            to_k8s_version = to_k8s_version if to_k8s_version.startswith("v") \
                else "v" + to_k8s_version
        except Exception as ex:
            print("Failed to get to_k8s_version from file %s. \nError: %s"
                  % (SYSTEM_DEPLOY_JSON_FILE, ex))
            to_k8s_version = ''

        if args.to_version:
            args_to_version = args.to_version if args.to_version.startswith("v") \
                else "v" + args.to_version
            if to_k8s_version and args_to_version != to_k8s_version:
                raise Exception('Provided target kubernetes version: %s not same as the one '
                                'provided to the software system-deploy init command: %s. '
                                'Either provide same version or leave empty.'
                                % (args_to_version, to_k8s_version))
            to_version = args_to_version
        else:
            if not to_k8s_version:
                raise Exception('Missing <target kubernetes version>. '
                                'To see help, run "system help kube-upgrade-start"')
            to_version = to_k8s_version

    kube_upgrade = cc.kube_upgrade.create(to_version, args.force)
    uuid = getattr(kube_upgrade, 'uuid', '')
    try:
        kube_upgrade = cc.kube_upgrade.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created kubernetes upgrade UUID not found: %s'
                               % uuid)
    _print_kube_upgrade_show(kube_upgrade)


def patch_kube_upgrade(cc, data):
    """" Call patch HTTP method for kube upgrades"""

    patch = []
    for (k, v) in data.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})
    try:
        kube_upgrade = cc.kube_upgrade.update(patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('Kubernetes upgrade UUID not found')

    _print_kube_upgrade_show(kube_upgrade)


def do_kube_upgrade_download_images(cc, args):
    """Download kubernetes images."""

    data = dict()
    data['state'] = KUBE_UPGRADE_STATE_DOWNLOADING_IMAGES

    patch_kube_upgrade(cc, data)


def do_kube_pre_application_update(cc, args):
    """Update applications before Kubernetes is upgraded."""

    data = dict()
    data['state'] = KUBE_UPGRADE_STATE_PRE_UPDATING_APPS

    patch_kube_upgrade(cc, data)


@utils.arg('hostid', metavar='<hostname or id>',
           help="Name or ID of host")
def do_kube_host_cordon(cc, args):
    """Cordon to evict pods from host."""

    data = dict()
    ihost = ihost_utils._find_ihost(cc, args.hostid)
    data['hostname'] = ihost.hostname
    data['state'] = KUBE_UPGRADE_STATE_CORDON

    patch_kube_upgrade(cc, data)


@utils.arg('hostid', metavar='<hostname or id>',
           help="Name or ID of host")
def do_kube_host_uncordon(cc, args):
    """Cordon to evict pods from host."""

    data = dict()
    ihost = ihost_utils._find_ihost(cc, args.hostid)
    data['hostname'] = ihost.hostname
    data['state'] = KUBE_UPGRADE_STATE_UNCORDON

    patch_kube_upgrade(cc, data)


def do_kube_upgrade_networking(cc, args):
    """Upgrade kubernetes networking."""

    data = dict()
    data['state'] = KUBE_UPGRADE_STATE_UPGRADING_NETWORKING

    patch_kube_upgrade(cc, data)


def do_kube_upgrade_storage(cc, args):
    """Upgrade kubernetes storage."""

    data = dict()
    data['state'] = KUBE_UPGRADE_STATE_UPGRADING_STORAGE

    patch_kube_upgrade(cc, data)


def do_kube_post_application_update(cc, args):
    """Update applications after Kubernetes is upgraded."""

    data = dict()
    data['state'] = KUBE_UPGRADE_STATE_POST_UPDATING_APPS

    patch_kube_upgrade(cc, data)


def do_kube_upgrade_abort(cc, args):
    """Kubernetes upgrade aborting."""

    # Check if it is combined P&K upgrade or legacy k8s upgrade.
    if os.path.exists(SYSTEM_DEPLOY_JSON_FILE):
        print("This operation is not supported at this time. Kubernetes upgrade can only be "
              "aborted by running command 'software deploy abort' which aborts both platform "
              "upgrade and kubernetes upgrade together.")
        return

    data = dict()
    data['state'] = KUBE_UPGRADE_STATE_ABORTING

    patch_kube_upgrade(cc, data)


def do_kube_upgrade_complete(cc, args):
    """Complete a kubernetes upgrade."""

    data = dict()
    data['state'] = KUBE_UPGRADE_STATE_COMPLETE

    patch_kube_upgrade(cc, data)


def do_kube_upgrade_delete(cc, args):
    """Delete a kubernetes upgrade."""

    try:
        cc.kube_upgrade.delete()
    except exc.HTTPNotFound:
        raise exc.CommandError('Kubernetes upgrade not found')

    print("Kubernetes upgrade deleted")


def do_kube_upgrade_failed(cc, args):
    """Set kubernetes upgrade status to failed"""

    kube_upgrade_state_map = {
        KUBE_UPGRADE_STATE_DOWNLOADING_IMAGES: "downloading-images-failed",
        KUBE_UPGRADE_STATE_UPGRADING_NETWORKING: "upgrading-networking-failed",
        KUBE_UPGRADE_STATE_UPGRADING_FIRST_MASTER: "upgrading-first-master-failed",
        KUBE_UPGRADE_STATE_UPGRADING_SECOND_MASTER: "upgrading-second-master-failed"
    }

    kube_upgrades = cc.kube_upgrade.list()
    if kube_upgrades:
        current_state = getattr(kube_upgrades[0], 'state', '')
        if kube_upgrade_state_map.get(current_state):
            data = dict()
            data['state'] = kube_upgrade_state_map.get(current_state)
            patch = []
            for (k, v) in data.items():
                patch.append({'op': 'replace', 'path': '/' + k, 'value': v})

            try:
                kube_upgrade = cc.kube_upgrade.update(patch)
            except exc.HTTPNotFound:
                raise exc.CommandError('Kubernetes upgrade not found')
            _print_kube_upgrade_show(kube_upgrade)
        else:
            print('Kubernetes upgrade is in %s state, cannot be set to failed' % current_state)
    else:
        print('A kubernetes upgrade is not in progress')
