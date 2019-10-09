#
# Copyright (c) 2015-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# All Rights Reserved.
#

from cgtsclient.common import constants
from cgtsclient.common import utils
from cgtsclient import exc
from six.moves import input


def _print_upgrade_show(obj):
    fields = ['uuid', 'state', 'from_release', 'to_release']
    data = [(f, getattr(obj, f, '')) for f in fields]
    utils.print_tuple_list(data)


def do_upgrade_show(cc, args):
    """Show software upgrade details and attributes."""

    upgrades = cc.upgrade.list()
    if upgrades:
        _print_upgrade_show(upgrades[0])
    else:
        print('No upgrade in progress')


@utils.arg('-f', '--force',
           action='store_true',
           default=False,
           help="Ignore non management-affecting alarms")
def do_upgrade_start(cc, args):
    """Start a software upgrade. """

    upgrade = cc.upgrade.create(args.force)
    uuid = getattr(upgrade, 'uuid', '')
    try:
        upgrade = cc.upgrade.get(uuid)
    except exc.HTTPNotFound:
        raise exc.CommandError('Created upgrade UUID not found: %s' % uuid)
    _print_upgrade_show(upgrade)


def do_upgrade_activate(cc, args):
    """Activate a software upgrade."""

    data = dict()
    data['state'] = constants.UPGRADE_ACTIVATION_REQUESTED

    patch = []
    for (k, v) in data.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})
    try:
        upgrade = cc.upgrade.update(patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('Upgrade UUID not found')
    _print_upgrade_show(upgrade)


def do_upgrade_abort(cc, args):
    """Abort a software upgrade."""
    try:
        body = cc.upgrade.check_reinstall()
    except Exception:
        raise exc.CommandError('Error getting upgrade state')

    reinstall_necessary = body.get('reinstall_necessary', None)

    abort_required = False
    system_type, system_mode = utils._get_system_info(cc)

    is_cpe = system_type == constants.TS_AIO
    simplex = system_mode == constants.SYSTEM_MODE_SIMPLEX
    if simplex:
        if reinstall_necessary:
            warning_message = (
                '\n'
                'WARNING: THIS OPERATION WILL RESULT IN A COMPLETE SYSTEM '
                'OUTAGE.\n'
                'It will require this host to be reinstalled and the system '
                'restored with the previous version. '
                'The system will be restored to when the upgrade was started.'
                '\n\n'
                'Are you absolutely sure you want to continue? [yes/N]: ')
            abort_required = True
        else:
            warning_message = (
                '\n'
                'WARNING: This will stop the upgrade process. The system '
                'backup created during the upgrade-start will be removed.\n\n'
                'Continue [yes/N]: ')
    elif reinstall_necessary:
        warning_message = (
            '\n'
            'WARNING: THIS OPERATION WILL RESULT IN A COMPLETE SYSTEM '
            'OUTAGE.\n'
            'It will require every host in the system to be powered down and '
            'then reinstalled to recover. All instances will be lost, '
            'including their disks. You will only be able to recover '
            'instances if you have external backups for their data.\n'
            'This operation should be done as a last resort, if there is '
            'absolutely no other way to recover the system.\n\n'
            'Are you absolutely sure you want to continue? [yes/N]: ')
        abort_required = True
    else:
        if is_cpe:
            warning_message = (
                '\n'
                'WARNING: THIS OPERATION WILL IMPACT RUNNING INSTANCES.\n'
                'Any instances that have been migrated after the upgrade was '
                'started will be lost, including their disks. You will only '
                'be able to recover instances if you have external backups '
                'for their data.\n'
                'This operation should be done as a last resort, if there is '
                'absolutely no other way to recover the system.\n\n'
                'Are you absolutely sure you want to continue?  [yes/N]: ')
            abort_required = True
        else:
            warning_message = (
                '\n'
                'WARNING: By continuing this operation, you will be forced to '
                'downgrade any hosts that have been upgraded. The system will '
                'revert to the state when controller-0 was last active.\n\n'
                'Continue [yes/N]: ')

    confirm = input(warning_message)
    if confirm != 'yes':
        print("Operation cancelled.")
        return
    elif abort_required:
        confirm = input("Type 'abort' to confirm: ")
        if confirm != 'abort':
            print("Operation cancelled.")
            return

    data = dict()
    data['state'] = constants.UPGRADE_ABORTING

    patch = []
    for (k, v) in data.items():
        patch.append({'op': 'replace', 'path': '/' + k, 'value': v})
    try:
        upgrade = cc.upgrade.update(patch)
    except exc.HTTPNotFound:
        raise exc.CommandError('Upgrade UUID not found')
    _print_upgrade_show(upgrade)


def do_upgrade_complete(cc, args):
    """Complete a software upgrade."""

    try:
        upgrade = cc.upgrade.delete()
    except exc.HTTPNotFound:
        raise exc.CommandError('Upgrade not found')

    _print_upgrade_show(upgrade)


def do_upgrade_abort_complete(cc, args):
    """Complete a software upgrade."""

    try:
        upgrade = cc.upgrade.delete()
    except exc.HTTPNotFound:
        raise exc.CommandError('Upgrade not found')

    _print_upgrade_show(upgrade)
