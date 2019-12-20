#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

from eventlet.green import subprocess
from oslo_log import log as logging

import simplejson as json

from sysinv.agent.lldp.drivers import base
from sysinv.agent.lldp import plugin
from sysinv.common import constants

LOG = logging.getLogger(__name__)


class SysinvLldpdAgentDriver(base.SysinvLldpDriverBase):

    def __init__(self, **kwargs):
        self.client = ""
        self.agents = []
        self.neighbours = []
        self.current_neighbours = []
        self.previous_neighbours = []
        self.current_agents = []
        self.previous_agents = []
        self.agent_audit_count = 0
        self.neighbour_audit_count = 0

    def initialize(self):
        self.__init__()

    @staticmethod
    def _lldpd_get_agent_status():
        json_obj = json
        p = subprocess.Popen(["lldpcli", "-f", "json", "show",
                              "configuration"],
                             stdout=subprocess.PIPE)
        data = json_obj.loads(p.communicate()[0])

        configuration = data['configuration'][0]
        config = configuration['config'][0]
        rx_only = config['rx-only'][0]

        if rx_only.get("value") == "no":
            return "rx=enabled,tx=enabled"
        else:
            return "rx=enabled,tx=disabled"

    @staticmethod
    def _lldpd_get_attrs(iface):
        name_or_uuid = None
        chassis_id = None
        system_name = None
        system_desc = None
        capability = None
        management_address = None
        port_desc = None
        dot1_lag = None
        dot1_port_vid = None
        dot1_vid_digest = None
        dot1_mgmt_vid = None
        dot1_vlan_names = None
        dot1_proto_vids = None
        dot1_proto_ids = None
        dot3_mac_status = None
        dot3_max_frame = None
        dot3_power_mdi = None
        ttl = None
        attrs = {}

        # Note: dot1_vid_digest, dot1_mgmt_vid are not currently supported
        # by the lldpd daemon

        name_or_uuid = iface.get("name")
        chassis = iface.get("chassis")[0]
        port = iface.get("port")[0]

        if not chassis.get('id'):
            return attrs
        chassis_id = chassis['id'][0].get("value")

        if not port.get('id'):
            return attrs
        port_id = port["id"][0].get("value")

        if not port.get('ttl'):
            return attrs
        ttl = port['ttl'][0].get("value")

        if chassis.get("name"):
            system_name = chassis['name'][0].get("value")

        if chassis.get("descr"):
            system_desc = chassis['descr'][0].get("value")

        if chassis.get("capability"):
            capability = ""
            for cap in chassis["capability"]:
                if cap.get("enabled"):
                    if capability:
                        capability += ", "
                    capability += cap.get("type").lower()

        if chassis.get("mgmt-ip"):
            management_address = ""
            for addr in chassis["mgmt-ip"]:
                if management_address:
                    management_address += ", "
                management_address += addr.get("value").lower()

        if port.get("descr"):
            port_desc = port["descr"][0].get("value")

        if port.get("link-aggregation"):
            dot1_lag_supported = port["link-aggregation"][0].get("supported")
            dot1_lag_enabled = port["link-aggregation"][0].get("enabled")
            dot1_lag = "capable="
            if dot1_lag_supported:
                dot1_lag += "y,"
            else:
                dot1_lag += "n,"
            dot1_lag += "enabled="
            if dot1_lag_enabled:
                dot1_lag += "y"
            else:
                dot1_lag += "n"

        if port.get("auto-negotiation"):
            port_auto_neg_support = port["auto-negotiation"][0].get(
                "supported")
            port_auto_neg_enabled = port["auto-negotiation"][0].get("enabled")
            dot3_mac_status = "auto-negotiation-capable="
            if port_auto_neg_support:
                dot3_mac_status += "y,"
            else:
                dot3_mac_status += "n,"
            dot3_mac_status += "auto-negotiation-enabled="
            if port_auto_neg_enabled:
                dot3_mac_status += "y,"
            else:
                dot3_mac_status += "n,"
            advertised = ""
            if port.get("auto-negotiation")[0].get("advertised"):
                for adv in port["auto-negotiation"][0].get("advertised"):
                    if advertised:
                        advertised += ", "
                    type = adv.get("type").lower()
                    if adv.get("hd") and not adv.get("fd"):
                        type += "hd"
                    elif adv.get("fd"):
                        type += "fd"
                    advertised += type
                dot3_mac_status += advertised

        if port.get("mfs"):
            dot3_max_frame = port["mfs"][0].get("value")

        if port.get("power"):
            power_mdi_support = port["power"][0].get("supported")
            power_mdi_enabled = port["power"][0].get("enabled")
            power_mdi_devicetype = port["power"][0].get("device-type")[0].get(
                "value")
            power_mdi_pairs = port["power"][0].get("pairs")[0].get("value")
            power_mdi_class = port["power"][0].get("class")[0].get("value")
            dot3_power_mdi = "power-mdi-supported="
            if power_mdi_support:
                dot3_power_mdi += "y,"
            else:
                dot3_power_mdi += "n,"
            dot3_power_mdi += "power-mdi-enabled="
            if power_mdi_enabled:
                dot3_power_mdi += "y,"
            else:
                dot3_power_mdi += "n,"
            if power_mdi_support and power_mdi_enabled:
                dot3_power_mdi += "device-type=" + power_mdi_devicetype
                dot3_power_mdi += ",pairs=" + power_mdi_pairs
                dot3_power_mdi += ",class=" + power_mdi_class

        vlans = None
        if iface.get("vlan"):
            vlans = iface.get("vlan")

        if vlans:
            dot1_vlan_names = ""
            for vlan in vlans:
                if vlan.get("pvid"):
                    dot1_port_vid = vlan.get("vlan-id")
                    continue
                if dot1_vlan_names:
                    dot1_vlan_names += ", "
                dot1_vlan_names += vlan.get("value")

        ppvids = None
        if iface.get("ppvids"):
            ppvids = iface.get("ppvid")

        if ppvids:
            dot1_proto_vids = ""
            for ppvid in ppvids:
                if dot1_proto_vids:
                    dot1_proto_vids += ", "
                dot1_proto_vids += ppvid.get("value")

        pids = None
        if iface.get("pi"):
            pids = iface.get('pi')
            dot1_proto_ids = ""
            for id in pids:
                if dot1_proto_ids:
                    dot1_proto_ids += ", "
                dot1_proto_ids += id.get("value")

        msap = chassis_id + "," + port_id

        attrs = {"name_or_uuid": name_or_uuid,
                 constants.LLDP_TLV_TYPE_CHASSIS_ID: chassis_id,
                 constants.LLDP_TLV_TYPE_PORT_ID: port_id,
                 constants.LLDP_TLV_TYPE_TTL: ttl,
                 "msap": msap,
                 constants.LLDP_TLV_TYPE_SYSTEM_NAME: system_name,
                 constants.LLDP_TLV_TYPE_SYSTEM_DESC: system_desc,
                 constants.LLDP_TLV_TYPE_SYSTEM_CAP: capability,
                 constants.LLDP_TLV_TYPE_MGMT_ADDR: management_address,
                 constants.LLDP_TLV_TYPE_PORT_DESC: port_desc,
                 constants.LLDP_TLV_TYPE_DOT1_LAG: dot1_lag,
                 constants.LLDP_TLV_TYPE_DOT1_PORT_VID: dot1_port_vid,
                 constants.LLDP_TLV_TYPE_DOT1_VID_DIGEST: dot1_vid_digest,
                 constants.LLDP_TLV_TYPE_DOT1_MGMT_VID: dot1_mgmt_vid,
                 constants.LLDP_TLV_TYPE_DOT1_VLAN_NAMES: dot1_vlan_names,
                 constants.LLDP_TLV_TYPE_DOT1_PROTO_VIDS: dot1_proto_vids,
                 constants.LLDP_TLV_TYPE_DOT1_PROTO_IDS: dot1_proto_ids,
                 constants.LLDP_TLV_TYPE_DOT3_MAC_STATUS: dot3_mac_status,
                 constants.LLDP_TLV_TYPE_DOT3_MAX_FRAME: dot3_max_frame,
                 constants.LLDP_TLV_TYPE_DOT3_POWER_MDI: dot3_power_mdi}

        return attrs

    def lldp_has_neighbour(self, name):
        p = subprocess.check_output(["lldpcli", "-f", "keyvalue", "show",
                                     "neighbors", "summary", "ports", name])
        return len(p) > 0

    def lldp_update(self):
        subprocess.call(['lldpcli', 'update'])

    def lldp_agents_list(self):
        json_obj = json
        lldp_agents = []

        p = subprocess.Popen(["lldpcli", "-f", "json", "show", "interface",
                              "detail"], stdout=subprocess.PIPE)
        data = json_obj.loads(p.communicate()[0])

        lldp = data['lldp'][0]

        if not lldp.get('interface'):
            return lldp_agents

        for iface in lldp['interface']:
            agent_attrs = self._lldpd_get_attrs(iface)
            status = self._lldpd_get_agent_status()
            agent_attrs.update({"status": status})
            agent = plugin.Agent(**agent_attrs)
            lldp_agents.append(agent)

        return lldp_agents

    def lldp_agents_clear(self):
        self.current_agents = []
        self.previous_agents = []

    def lldp_neighbours_list(self):
        json_obj = json
        lldp_neighbours = []
        p = subprocess.Popen(["lldpcli", "-f", "json", "show", "neighbor",
                              "detail"], stdout=subprocess.PIPE)
        data = json_obj.loads(p.communicate()[0])

        lldp = data['lldp'][0]

        if not lldp.get('interface'):
            return lldp_neighbours

        for iface in lldp['interface']:
            neighbour_attrs = self._lldpd_get_attrs(iface)
            neighbour = plugin.Neighbour(**neighbour_attrs)
            lldp_neighbours.append(neighbour)

        return lldp_neighbours

    def lldp_neighbours_clear(self):
        self.current_neighbours = []
        self.previous_neighbours = []

    def lldp_update_systemname(self, systemname):
        p = subprocess.Popen(["lldpcli", "-f", "json", "show", "chassis"],
                             stdout=subprocess.PIPE)
        data = json.loads(p.communicate()[0])

        local_chassis = data['local-chassis'][0]
        chassis = local_chassis['chassis'][0]
        name = chassis.get('name', None)
        if name is None or not name[0].get("value"):
            return
        name = name[0]

        hostname = name.get("value").partition(':')[0]

        newname = hostname + ":" + systemname

        p = subprocess.Popen(["lldpcli", "configure", "system", "hostname",
                              newname], stdout=subprocess.PIPE)
