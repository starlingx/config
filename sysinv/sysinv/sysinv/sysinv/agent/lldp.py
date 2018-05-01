#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

""" inventory lldp Utilities and helper functions."""

import simplejson as json
import subprocess

import threading

from operator import attrgetter

from sysinv.common import constants
from sysinv.openstack.common import log as logging

LOG = logging.getLogger(__name__)


class Key(object):
    def __init__(self, chassisid, portid, portname):
        self.chassisid = chassisid
        self.portid = portid
        self.portname = portname

    def __hash__(self):
        return hash((self.chassisid, self.portid, self.portname))

    def __cmp__(self, rhs):
        return (cmp(self.chassisid, rhs.chassisid) or
                cmp(self.portid, rhs.portid) or
                cmp(self.portname, rhs.portname))

    def __eq__(self, rhs):
        return (self.chassisid == rhs.chassisid and
                self.portid == rhs.portid and
                self.portname == rhs.portname)

    def __ne__(self, rhs):
        return (self.chassisid != rhs.chassisid or
                self.portid != rhs.portid or
                self.portname != rhs.portname)

    def __str__(self):
        return "%s [%s] [%s]" % (self.portname, self.chassisid, self.portid)

    def __repr__(self):
        return "<Key '%s'>" % str(self)


class Agent(object):
    '''Class to encapsulate LLDP agent data for System Inventory'''

    def __init__(self, **kwargs):
        '''Construct an Agent object with the given values.'''
        self.key = Key(kwargs.get(constants.LLDP_TLV_TYPE_CHASSIS_ID),
                       kwargs.get(constants.LLDP_TLV_TYPE_PORT_ID),
                       kwargs.get("name_or_uuid"))
        self.status = kwargs.get('status')
        self.ttl = kwargs.get(constants.LLDP_TLV_TYPE_TTL)
        self.system_name = kwargs.get(constants.LLDP_TLV_TYPE_SYSTEM_NAME)
        self.system_desc = kwargs.get(constants.LLDP_TLV_TYPE_SYSTEM_DESC)
        self.port_desc = kwargs.get(constants.LLDP_TLV_TYPE_PORT_DESC)
        self.capabilities = kwargs.get(constants.LLDP_TLV_TYPE_SYSTEM_CAP)
        self.mgmt_addr = kwargs.get(constants.LLDP_TLV_TYPE_MGMT_ADDR)
        self.dot1_lag = kwargs.get(constants.LLDP_TLV_TYPE_DOT1_LAG)
        self.dot1_vlan_names = kwargs.get(
            constants.LLDP_TLV_TYPE_DOT1_VLAN_NAMES)
        self.dot3_max_frame = kwargs.get(
            constants.LLDP_TLV_TYPE_DOT3_MAX_FRAME)
        self.state = None

    def __hash__(self):
        return self.key.__hash__()

    def __eq__(self, rhs):
        return (self.key == rhs.key)

    def __ne__(self, rhs):
        return (self.key != rhs.key or
                self.status != rhs.status or
                self.ttl != rhs.ttl or
                self.system_name != rhs.system_name or
                self.system_desc != rhs.system_desc or
                self.port_desc != rhs.port_desc or
                self.capabilities != rhs.capabilities or
                self.mgmt_addr != rhs.mgmt_addr or
                self.dot1_lag != rhs.dot1_lag or
                self.dot1_vlan_names != rhs.dot1_vlan_names or
                self.dot3_max_frame != rhs.dot3_max_frame or
                self.state != rhs.state)

    def __str__(self):
        return "%s: [%s] [%s] [%s], [%s], [%s], [%s], [%s], [%s]" % (
            self.key, self.status, self.system_name, self.system_desc,
            self.port_desc, self.capabilities,
            self.mgmt_addr, self.dot1_lag,
            self.dot3_max_frame)

    def __repr__(self):
        return "<Agent '%s'>" % str(self)


class Neighbour(object):
    '''Class to encapsulate LLDP neighbour data for System Inventory'''

    def __init__(self, **kwargs):
        '''Construct an Neighbour object with the given values.'''
        self.key = Key(kwargs.get(constants.LLDP_TLV_TYPE_CHASSIS_ID),
                       kwargs.get(constants.LLDP_TLV_TYPE_PORT_ID),
                       kwargs.get("name_or_uuid"))
        self.msap = kwargs.get('msap')
        self.ttl = kwargs.get(constants.LLDP_TLV_TYPE_TTL)
        self.system_name = kwargs.get(constants.LLDP_TLV_TYPE_SYSTEM_NAME)
        self.system_desc = kwargs.get(constants.LLDP_TLV_TYPE_SYSTEM_DESC)
        self.port_desc = kwargs.get(constants.LLDP_TLV_TYPE_PORT_DESC)
        self.capabilities = kwargs.get(constants.LLDP_TLV_TYPE_SYSTEM_CAP)
        self.mgmt_addr = kwargs.get(constants.LLDP_TLV_TYPE_MGMT_ADDR)
        self.dot1_port_vid = kwargs.get(constants.LLDP_TLV_TYPE_DOT1_PORT_VID)
        self.dot1_vid_digest = kwargs.get(
            constants.LLDP_TLV_TYPE_DOT1_VID_DIGEST)
        self.dot1_mgmt_vid = kwargs.get(constants.LLDP_TLV_TYPE_DOT1_MGMT_VID)
        self.dot1_vid_digest = kwargs.get(
            constants.LLDP_TLV_TYPE_DOT1_VID_DIGEST)
        self.dot1_mgmt_vid = kwargs.get(constants.LLDP_TLV_TYPE_DOT1_MGMT_VID)
        self.dot1_lag = kwargs.get(constants.LLDP_TLV_TYPE_DOT1_LAG)
        self.dot1_vlan_names = kwargs.get(
            constants.LLDP_TLV_TYPE_DOT1_VLAN_NAMES)
        self.dot1_proto_vids = kwargs.get(
            constants.LLDP_TLV_TYPE_DOT1_PROTO_VIDS)
        self.dot1_proto_ids = kwargs.get(
            constants.LLDP_TLV_TYPE_DOT1_PROTO_IDS)
        self.dot3_mac_status = kwargs.get(
            constants.LLDP_TLV_TYPE_DOT3_MAC_STATUS)
        self.dot3_max_frame = kwargs.get(
            constants.LLDP_TLV_TYPE_DOT3_MAX_FRAME)
        self.dot3_power_mdi = kwargs.get(
            constants.LLDP_TLV_TYPE_DOT3_POWER_MDI)

        self.state = None

    def __hash__(self):
        return self.key.__hash__()

    def __eq__(self, rhs):
        return (self.key == rhs.key)

    def __ne__(self, rhs):
        return (self.key != rhs.key or
                self.msap != rhs.msap or
                self.system_name != rhs.system_name or
                self.system_desc != rhs.system_desc or
                self.port_desc != rhs.port_desc or
                self.capabilities != rhs.capabilities or
                self.mgmt_addr != rhs.mgmt_addr or
                self.dot1_port_vid != rhs.dot1_port_vid or
                self.dot1_vid_digest != rhs.dot1_vid_digest or
                self.dot1_mgmt_vid != rhs.dot1_mgmt_vid or
                self.dot1_vid_digest != rhs.dot1_vid_digest or
                self.dot1_mgmt_vid != rhs.dot1_mgmt_vid or
                self.dot1_lag != rhs.dot1_lag or
                self.dot1_vlan_names != rhs.dot1_vlan_names or
                self.dot1_proto_vids != rhs.dot1_proto_vids or
                self.dot1_proto_ids != rhs.dot1_proto_ids or
                self.dot3_mac_status != rhs.dot3_mac_status or
                self.dot3_max_frame != rhs.dot3_max_frame or
                self.dot3_power_mdi != rhs.dot3_power_mdi)

    def __str__(self):
        return "%s [%s] [%s] [%s], [%s]" % (
            self.key, self.system_name, self.system_desc,
            self.port_desc, self.capabilities)

    def __repr__(self):
        return "<Neighbour '%s'>" % str(self)


class LLDPOperator(object):
    '''Class to encapsulate LLDP operations for System Inventory'''

    def __init__(self, **kwargs):
        self._lock = threading.Lock()
        self.client = ""
        self.agents = []
        self.neighbours = []
        self.current_neighbours = []
        self.previous_neighbours = []
        self.current_agents = []
        self.previous_agents = []
        self.agent_audit_count = 0
        self.neighbour_audit_count = 0

    def lldpd_get_agent_status(self):
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

    def lldpd_get_attrs(self, iface):
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

    def lldpd_agent_list(self):
        json_obj = json
        lldp_agents = []

        p = subprocess.Popen(["lldpcli", "-f", "json", "show", "interface",
                              "detail"], stdout=subprocess.PIPE)
        data = json_obj.loads(p.communicate()[0])

        lldp = data['lldp'][0]

        if not lldp.get('interface'):
            return lldp_agents

        for iface in lldp['interface']:
            agent_attrs = self.lldpd_get_attrs(iface)
            status = self.lldpd_get_agent_status()
            agent_attrs.update({"status": status})
            agent = Agent(**agent_attrs)
            lldp_agents.append(agent)

        return lldp_agents

    def lldpd_neighbour_list(self):
        json_obj = json
        lldp_neighbours = []
        p = subprocess.Popen(["lldpcli", "-f", "json", "show", "neighbor",
                              "detail"], stdout=subprocess.PIPE)
        data = json_obj.loads(p.communicate()[0])

        lldp = data['lldp'][0]

        if not lldp.get('interface'):
            return lldp_neighbours

        for iface in lldp['interface']:
            neighbour_attrs = self.lldpd_get_attrs(iface)
            neighbour = Neighbour(**neighbour_attrs)
            lldp_neighbours.append(neighbour)

        return lldp_neighbours

    def _do_request(self, callable):
        """Thread safe wrapper for executing client requests.

        """

        with self._lock:
            return callable()

    def _execute_lldp_request(self, callable, snat=None):
        try:
            return self._do_request(callable)
        except Exception as e:
            LOG.error("Failed to execute LLDP request: %s", str(e))

    def vswitch_lldp_get_status(self, admin_status):
        if admin_status == "enabled":
            status = "rx=enabled,tx=enabled"
        elif admin_status == "tx-only":
            status = "rx=disabled,tx=enabled"
        elif admin_status == "rx-only":
            status = "rx=enabled,tx=disabled"
        else:
            status = "rx=disabled,tx=disabled"
        return status

    def vswitch_lldp_get_attrs(self, agent_neighbour_dict):
        attrs = {}

        vswitch_to_db_dict = {'local-chassis':
                              constants.LLDP_TLV_TYPE_CHASSIS_ID,
                              'local-port': constants.LLDP_TLV_TYPE_PORT_ID,
                              'remote-chassis':
                              constants.LLDP_TLV_TYPE_CHASSIS_ID,
                              'remote-port': constants.LLDP_TLV_TYPE_PORT_ID,
                              'tx-ttl': constants.LLDP_TLV_TYPE_TTL,
                              'rx-ttl': constants.LLDP_TLV_TYPE_TTL,
                              'system-name':
                              constants.LLDP_TLV_TYPE_SYSTEM_NAME,
                              'system-description':
                              constants.LLDP_TLV_TYPE_SYSTEM_DESC,
                              'port-description':
                              constants.LLDP_TLV_TYPE_PORT_DESC,
                              'system-capabilities':
                              constants.LLDP_TLV_TYPE_SYSTEM_CAP,
                              'management-address':
                              constants.LLDP_TLV_TYPE_MGMT_ADDR,
                              'dot1-lag': constants.LLDP_TLV_TYPE_DOT1_LAG,
                              'dot1-management-vid':
                              constants.LLDP_TLV_TYPE_DOT1_MGMT_VID,
                              'dot1-port-vid':
                              constants.LLDP_TLV_TYPE_DOT1_PORT_VID,
                              'dot1-proto-ids':
                              constants.LLDP_TLV_TYPE_DOT1_PROTO_IDS,
                              'dot1-proto-vids':
                              constants.LLDP_TLV_TYPE_DOT1_PROTO_VIDS,
                              'dot1-vid-digest':
                              constants.LLDP_TLV_TYPE_DOT1_VID_DIGEST,
                              'dot1-vlan-names':
                              constants.LLDP_TLV_TYPE_DOT1_VLAN_NAMES,
                              'dot3-lag':
                              constants.LLDP_TLV_TYPE_DOT1_LAG,
                              'dot3-mac-status':
                              constants.LLDP_TLV_TYPE_DOT3_MAC_STATUS,
                              'dot3-max-frame':
                              constants.LLDP_TLV_TYPE_DOT3_MAX_FRAME,
                              'dot3-power-mdi':
                              constants.LLDP_TLV_TYPE_DOT3_POWER_MDI}

        for k, v in vswitch_to_db_dict.iteritems():
            if k in agent_neighbour_dict:
                if agent_neighbour_dict[k]:
                    attr = {v: agent_neighbour_dict[k]}
                else:
                    attr = {v: None}
                attrs.update(attr)

        msap = attrs[constants.LLDP_TLV_TYPE_CHASSIS_ID] \
            + "," + attrs[constants.LLDP_TLV_TYPE_PORT_ID]

        attr = {"name_or_uuid": agent_neighbour_dict["port-uuid"],
                "msap": msap}
        attrs.update(attr)

        return attrs

    def vswitch_lldp_agent_list(self):
        """Sends a request to the vswitch requesting the full list of LLDP agent

        entries.
        """

        LOG.error("vswitch_lldp_agent_list is not implemented.")
        return []


    def vswitch_lldp_neighbour_list(self):
        """Sends a request to the vswitch requesting the full list of LLDP

        neighbour entries.
        """

        LOG.error("vswitch_lldp_neighbour_ist s not implemented.")
        return []


    def lldp_agents_list(self, do_compute=False):
        self.agent_audit_count += 1
        if self.agent_audit_count > constants.LLDP_FULL_AUDIT_COUNT:
            LOG.debug("LLDP agent audit: triggering full sync")
            self.agent_audit_count = 0
            self.lldp_agents_clear()

        self.previous_agents = self.current_agents
        self.current_agents = self.lldpd_agent_list()

        if do_compute:
            self.current_agents += self.vswitch_lldp_agent_list()

        current = set(self.current_agents)
        previous = set(self.previous_agents)
        removed = previous - current

        agent_array = []
        for a in self.current_agents:
            agent_array.append(a)

        if removed:
            for r in removed:
                LOG.debug("LLDP agent audit: detected removed agent")
                r.state = constants.LLDP_AGENT_STATE_REMOVED
                agent_array.append(r)
            return agent_array

        # Check that there is actual state changes and return an empty list if
        # nothing changed.
        if self.previous_agents:
            pairs = zip(sorted(current, key=attrgetter('key')),
                        sorted(previous, key=attrgetter('key')))
            if not any(x != y for x, y in pairs):
                LOG.debug("LLDP agent audit: No changes")
                return []

        return agent_array

    def lldp_agents_clear(self):
        self.current_agents = []
        self.previous_agents = []

    def lldp_neighbours_list(self, do_compute=False):
        self.neighbour_audit_count += 1
        if self.neighbour_audit_count > constants.LLDP_FULL_AUDIT_COUNT:
            LOG.debug("LLDP neighbour audit: triggering full sync")
            self.neighbour_audit_count = 0
            self.lldp_neighbours_clear()

        self.previous_neighbours = self.current_neighbours
        self.current_neighbours = self.lldpd_neighbour_list()

        if do_compute:
            self.current_neighbours += self.vswitch_lldp_neighbour_list()

        current = set(self.current_neighbours)
        previous = set(self.previous_neighbours)
        removed = previous - current

        neighbour_array = []
        for n in self.current_neighbours:
            neighbour_array.append(n)

        if removed:
            for r in removed:
                LOG.debug("LLDP neighbour audit: detected removed neighbour")
                r.state = constants.LLDP_NEIGHBOUR_STATE_REMOVED
                neighbour_array.append(r)
            return neighbour_array

        # Check that there is actual state changes and return an empty list if
        # nothing changed.
        if self.previous_neighbours:
            pairs = zip(sorted(current, key=attrgetter('key')),
                        sorted(previous, key=attrgetter('key')))
            if not any(x != y for x, y in pairs):
                LOG.debug("LLDP neighbour audit: No changes")
                return []

        return neighbour_array

    def lldp_neighbours_clear(self):
        self.current_neighbours = []
        self.previous_neighbours = []

    def lldp_update_systemname(self, context, systemname, do_compute=False):
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

        if do_compute:
            attrs = {"system-name": newname}
            LOG.error("lldp_update_systemname failed due to lack of vswitch")
