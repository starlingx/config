#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

import simplejson as json
import subprocess

from oslo_log import log as logging

from sysinv.agent.lldp.drivers.lldpd import driver as lldpd_driver
from sysinv.common import constants

LOG = logging.getLogger(__name__)


class SysinvOVSAgentDriver(lldpd_driver.SysinvLldpdAgentDriver):

    def run_cmd(self, cmd):
        p = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
        p.wait()
        output, error = p.communicate()
        if p.returncode != 0:
            LOG.error("Failed to run command %s: error: %s", cmd, error)
            return None
        return output

    def lldp_ovs_get_interface_port_map(self):
        interface_port_map = {}

        cmd = "ovs-vsctl --timeout 10 --format json "\
              "--columns name,_uuid,interfaces list Port"

        output = self.run_cmd(cmd)
        if not output:
            return

        ports = json.loads(output)
        ports = ports['data']

        for port in ports:
            port_uuid = port[1][1]
            interfaces = port[2][1]

            if isinstance(interfaces, list):
                for interface in interfaces:
                    interface_uuid = interface[1]
                    interface_port_map[interface_uuid] = port_uuid
            else:
                interface_uuid = interfaces
                interface_port_map[interface_uuid] = port_uuid

        return interface_port_map

    def lldp_ovs_get_port_bridge_map(self):
        port_bridge_map = {}

        cmd = "ovs-vsctl --timeout 10 --format json "\
              "--columns name,ports list Bridge"
        output = self.run_cmd(cmd)
        if not output:
            return

        bridges = json.loads(output)
        bridges = bridges['data']

        for bridge in bridges:
            bridge_name = bridge[0]
            port_set = bridge[1][1]
            for port in port_set:
                value = port[1]
                port_bridge_map[value] = bridge_name

        return port_bridge_map

    def lldp_ovs_lldp_flow_exists(self, brname, in_port):

        cmd = "ovs-ofctl dump-flows {} in_port={},dl_dst={},dl_type={}".format(
            brname, in_port, constants.LLDP_MULTICAST_ADDRESS,
            constants.LLDP_ETHER_TYPE)
        output = self.run_cmd(cmd)
        if not output:
            return None

        return (output.count("\n") > 1)

    def lldp_ovs_add_flows(self, brname, in_port, out_port):

        cmd = ("ovs-ofctl add-flow {} in_port={},dl_dst={},dl_type={},"
               "actions=output:{}".format(
                    brname, in_port, constants.LLDP_MULTICAST_ADDRESS,
                    constants.LLDP_ETHER_TYPE, out_port))
        output = self.run_cmd(cmd)
        if not output:
            return

        cmd = ("ovs-ofctl add-flow {} in_port={},dl_dst={},dl_type={},"
               "actions=output:{}".format(
                    brname, out_port, constants.LLDP_MULTICAST_ADDRESS,
                    constants.LLDP_ETHER_TYPE, in_port))
        output = self.run_cmd(cmd)
        if not output:
            return

    def lldp_ovs_update_flows(self):

        port_bridge_map = self.lldp_ovs_get_port_bridge_map()
        if not port_bridge_map:
            return

        interface_port_map = self.lldp_ovs_get_interface_port_map()
        if not interface_port_map:
            return

        cmd = "ovs-vsctl --timeout 10 --format json "\
              "--columns name,_uuid,type,other_config list Interface"

        output = self.run_cmd(cmd)
        if not output:
            return

        data = json.loads(output)
        data = data['data']

        for interface in data:
            name = interface[0]
            uuid = interface[1][1]
            type = interface[2]
            other_config = interface[3]

            if type != 'internal':
                continue

            config_map = other_config[1]
            for config in config_map:
                key = config[0]
                value = config[1]
                if key != 'lldp_phy_peer':
                    continue

                phy_peer = value
                brname = port_bridge_map[interface_port_map[uuid]]
                if not self.lldp_ovs_lldp_flow_exists(brname, name):
                    LOG.info("Adding missing LLDP flow from %s to %s",
                             name, phy_peer)
                    self.lldp_ovs_add_flows(brname, name, phy_peer)

                if not self.lldp_ovs_lldp_flow_exists(brname, value):
                    LOG.info("Adding missing LLDP flow from %s to %s",
                             phy_peer, name)
                    self.lldp_ovs_add_flows(brname, phy_peer, name)

    def lldp_agents_list(self):
        self.lldp_ovs_update_flows()
        return lldpd_driver.SysinvLldpdAgentDriver.lldp_agents_list(self)

    def lldp_neighbours_list(self):
        self.lldp_ovs_update_flows()
        return lldpd_driver.SysinvLldpdAgentDriver.lldp_neighbours_list(self)
