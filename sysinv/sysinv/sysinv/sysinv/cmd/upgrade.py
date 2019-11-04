#!/usr/bin/env python
#
# Copyright (c) 2015-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Sysinv upgrade utilities.
"""

import sys

from oslo_config import cfg
from oslo_log import log
from sysinv._i18n import _
from sysinv.common import constants
from sysinv.common import service
from sysinv.common import utils
from sysinv.db import api as dbapi

from tsconfig.tsconfig import system_mode

CONF = cfg.CONF
LOG = log.getLogger(__name__)


def update_controller_state():
    mydbapi = dbapi.get_instance()

    LOG.info("Updating upgrades data in sysinv database")
    hostname = constants.CONTROLLER_1_HOSTNAME
    if system_mode == constants.SYSTEM_MODE_SIMPLEX:
        hostname = constants.CONTROLLER_0_HOSTNAME
    host = mydbapi.ihost_get_by_hostname(hostname)

    # Update the states for controller-1
    update_values = {'administrative': constants.ADMIN_UNLOCKED,
                     'operational': constants.OPERATIONAL_ENABLED,
                     'availability': constants.AVAILABILITY_AVAILABLE}
    mydbapi.ihost_update(host.uuid, update_values)

    # Update the from and to load for controller-1
    loads = mydbapi.load_get_list()
    target_load = utils.get_imported_load(loads)
    host_upgrade = mydbapi.host_upgrade_get_by_host(host.id)
    update_values = {'software_load': target_load.id,
                     'target_load': target_load.id}
    mydbapi.host_upgrade_update(host_upgrade.id, update_values)

    # Update the upgrade state
    upgrade = mydbapi.software_upgrade_get_one()
    upgrade_update = {'state': constants.UPGRADE_UPGRADING_CONTROLLERS}
    mydbapi.software_upgrade_update(upgrade.uuid, upgrade_update)


def add_action_parsers(subparsers):
    for action in ['update_controller_state']:
        parser = subparsers.add_parser(action)
        parser.set_defaults(func=globals()[action])


CONF.register_cli_opt(
    cfg.SubCommandOpt('action',
                      title='Action options',
                      help='Available upgrade options',
                      handler=add_action_parsers))


def main():
    # Parse config file and command line options, then start logging
    service.prepare_service(sys.argv)

    if CONF.action.name in ['update_controller_state']:
        msg = (_("Called '%(action)s'") %
               {"action": CONF.action.name})
        LOG.info(msg)
        CONF.action.func()
    else:
        LOG.error(_("Unknown action: %(action)") % {"action":
                                                    CONF.action.name})
