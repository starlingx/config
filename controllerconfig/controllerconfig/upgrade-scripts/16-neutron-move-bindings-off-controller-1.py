#!/usr/bin/python3
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will remove all neutron bindings from controller-1.
# This is necessary to match the behaviour on controller-1 after
# the host is locked.
# This should be removed once we support data migration upon a
# swact to controller-1 during an upgrade.
import psycopg2

import sys

from psycopg2.extras import RealDictCursor
from controllerconfig.common import log

LOG = log.get_logger(__name__)


def main():
    action = None
    from_release = None
    to_release = None  # noqa
    arg = 1
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]  # noqa
        elif arg == 3:
            action = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()

    if from_release == "18.03" and action == "migrate":
        try:
            move_routers_off_controller_1()
            move_networks_off_controller_1()
            move_port_bindings_off_controller_1()
            move_dhcp_port_device_id_off_controller_1()
            move_distributed_port_bindings_off_controller_1()
        except Exception as ex:
            LOG.exception(ex)
            print(ex)
            return 1


def run_cmd_postgres(cmd):
    """
    This executes the given command as user postgres.  This is necessary when
    this script is run as root, which is the case on an upgrade activation.
    """
    neutron_conn = psycopg2.connect("dbname=neutron user=postgres")
    with neutron_conn:
        with neutron_conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(cmd)
            LOG.info("Executing '%s'" % cmd)


def move_routers_off_controller_1():
    """
    This function moves all routers hosted on controller-1 to controller-0.
    This is required to match the DB state after controller-1 is locked as
    part of the upgrade, at which point they will be automatically reschduled.
    """
    cmd = ("UPDATE routerl3agentbindings SET l3_agent_id="
           "(SELECT id FROM agents WHERE agent_type='L3 agent'"
           " AND host='controller-0') WHERE l3_agent_id IN"
           " (SELECT id FROM agents WHERE agent_type='L3 agent'"
           " AND host='controller-1') AND (SELECT count(id)"
           " FROM agents WHERE agent_type='L3 agent'"
           " AND host='controller-0')=1;")
    run_cmd_postgres(cmd)


def move_networks_off_controller_1():
    """
    This function moves all dhcp bindings from controller-1 to controller-0.
    This is required to match the DB state after controller-1 is locked as
    part of the upgrade, at which point they will be automatically reschduled.
    """
    cmd = ("UPDATE networkdhcpagentbindings SET dhcp_agent_id="
           "(SELECT id FROM agents WHERE agent_type='DHCP agent'"
           " AND host='controller-0') WHERE dhcp_agent_id IN"
           " (SELECT id FROM agents WHERE agent_type='DHCP agent'"
           " AND host='controller-1') AND (SELECT count(id)"
           " FROM agents WHERE agent_type='DHCP agent'"
           " AND host='controller-0')=1;")
    run_cmd_postgres(cmd)


def move_dhcp_port_device_id_off_controller_1():
    """
    This function updates all dhcp ports' device IDs bound to controller-0
    over to controller-1.  Note that because the prefix is based on hostname,
    this prefix is constant for both controllers.
    controller-0: "dhcpaebe17f8-776d-5ab6-9a5f-e9bdeeaca66f"
    controller-1: "dhcpf42f2830-b2ec-5a2c-93f3-e3e3328e20a3"
    """
    cmd = ("UPDATE ports SET device_id ="
           " REPLACE(device_id,"
           " 'dhcpf42f2830-b2ec-5a2c-93f3-e3e3328e20a3',"
           " 'dhcpaebe17f8-776d-5ab6-9a5f-e9bdeeaca66f')"
           " WHERE device_owner = 'network:dhcp';")
    run_cmd_postgres(cmd)


def move_port_bindings_off_controller_1():
    """
    This function moves all port bindings from controller-1 to controller-0.
    """
    cmd = ("UPDATE ml2_port_bindings SET host='controller-0'"
           " WHERE host='controller-1';")
    run_cmd_postgres(cmd)


def move_distributed_port_bindings_off_controller_1():
    """
    This function deletes all ml2_distributed_port_bindings on contorller-1.
    """
    cmd = ("DELETE FROM ml2_distributed_port_bindings"
           " WHERE host='controller-1';")
    run_cmd_postgres(cmd)


if __name__ == "__main__":
    sys.exit(main())
