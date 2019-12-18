#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

from eventlet.green import subprocess
import simplejson as json

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
            try:
                port_uuid = port[1][1]
                interfaces = port[2][1]
            except IndexError:
                LOG.error("Unexpected port in LLDP port list: %r", port)
                continue

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
            try:
                bridge_name = bridge[0]
                ports = bridge[1][1]
            except IndexError:
                LOG.error("Unexpected bridge in LLDP bridge list: %r", bridge)
                continue

            if isinstance(ports, list):
                for port in ports:
                    try:
                        port_uuid = port[1]
                    except IndexError:
                        LOG.error("Unexpected port in LLDP bridge list: %r",
                                  port)
                        continue
                    port_bridge_map[port_uuid] = bridge_name
            else:
                port_uuid = ports
                port_bridge_map[port_uuid] = bridge_name

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
               "actions=output:{}".format(brname, in_port,
                                          constants.LLDP_MULTICAST_ADDRESS,
                                          constants.LLDP_ETHER_TYPE, out_port))
        output = self.run_cmd(cmd)
        if not output:
            return

        cmd = ("ovs-ofctl add-flow {} in_port={},dl_dst={},dl_type={},"
               "actions=output:{}".format(brname, out_port,
                                          constants.LLDP_MULTICAST_ADDRESS,
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
            try:
                name = interface[0]
                uuid = interface[1][1]
                type = interface[2]
                other_config = interface[3]
            except IndexError:
                LOG.error("Unexpected interface in LLDP interface list: %r",
                          interface)
                continue

            if type != 'internal':
                continue

            if uuid not in interface_port_map:
                continue

            if interface_port_map[uuid] not in port_bridge_map:
                continue

            brname = port_bridge_map[interface_port_map[uuid]]

            try:
                config_map = other_config[1]
            except IndexError:
                LOG.error("Unexpected config map in LLDP interface list: %r",
                          config_map)
                continue

            for config in config_map:
                try:
                    key = config[0]
                    value = config[1]
                except IndexError:
                    LOG.error("Unexpected config in LLDP interface list: %r",
                              config)
                    continue

                if key != 'lldp_phy_peer':
                    continue
                phy_peer = value

                if not self.lldp_ovs_lldp_flow_exists(brname, name):
                    LOG.info("Adding missing LLDP flow from %s to %s",
                             name, phy_peer)
                    self.lldp_ovs_add_flows(brname, name, phy_peer)

                if not self.lldp_ovs_lldp_flow_exists(brname, phy_peer):
                    LOG.info("Adding missing LLDP flow from %s to %s",
                             phy_peer, name)
                    self.lldp_ovs_add_flows(brname, phy_peer, name)

    def lldp_agents_list(self):
        self.lldp_ovs_update_flows()
        return lldpd_driver.SysinvLldpdAgentDriver.lldp_agents_list(self)

    def lldp_neighbours_list(self):
        self.lldp_ovs_update_flows()
        return lldpd_driver.SysinvLldpdAgentDriver.lldp_neighbours_list(self)
