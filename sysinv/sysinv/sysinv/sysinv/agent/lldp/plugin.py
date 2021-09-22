#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4

# All Rights Reserved.
#

from oslo_log import log as logging
from oslo_utils import excutils

from sysinv.agent.lldp import manager
from sysinv.common import exception
from sysinv.common import constants

LOG = logging.getLogger(__name__)


class Key(object):
    def __init__(self, chassisid, portid, portname):
        self.chassisid = chassisid
        self.portid = portid
        self.portname = portname

    def __hash__(self):
        return hash((self.chassisid, self.portid, self.portname))

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


class SysinvLldpPlugin(object):

    """Implementation of the Plugin."""

    def __init__(self):
        self.manager = manager.SysinvLldpDriverManager()

    def lldp_has_neighbour(self, name):
        try:
            return self.manager.lldp_has_neighbour(name)
        except exception.LLDPDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("LLDP has neighbour failed")

    def lldp_update(self):
        try:
            self.manager.lldp_update()
        except exception.LLDPDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("LLDP update failed")

    def lldp_agents_list(self):
        try:
            agents = self.manager.lldp_agents_list()
        except exception.LLDPDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("LLDP agents list failed")

        return agents

    def lldp_agents_clear(self):
        try:
            self.manager.lldp_agents_clear()
        except exception.LLDPDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("LLDP agents clear failed")

    def lldp_neighbours_list(self):
        try:
            neighbours = self.manager.lldp_neighbours_list()
        except exception.LLDPDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("LLDP neighbours list failed")

        return neighbours

    def lldp_neighbours_clear(self):
        try:
            self.manager.lldp_neighbours_clear()
        except exception.LLDPDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("LLDP neighbours clear failed")

    def lldp_update_systemname(self, systemname):
        try:
            self.manager.lldp_update_systemname(systemname)
        except exception.LLDPDriverError as e:
            LOG.exception(e)
            with excutils.save_and_reraise_exception():
                LOG.error("LLDP update systemname failed")
