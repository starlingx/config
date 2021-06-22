# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 UnitedStack Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2016 Wind River Systems, Inc.
#

import jsonpatch
import pecan
from pecan import rest
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import lldp_tlv
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class LLDPAgentPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return []


class LLDPAgent(base.APIBase):
    """API representation of an LLDP Agent

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of an
    LLDP agent.
    """

    uuid = types.uuid
    "Unique UUID for this port"

    status = wtypes.text
    "Represent the status of the lldp agent"

    host_id = int
    "Represent the host_id the lldp agent belongs to"

    port_id = int
    "Represent the port_id the lldp agent belongs to"

    host_uuid = types.uuid
    "Represent the UUID of the host the lldp agent belongs to"

    port_uuid = types.uuid
    "Represent the UUID of the port the lldp agent belongs to"

    port_name = wtypes.text
    "Represent the name of the port the lldp neighbour belongs to"

    port_namedisplay = wtypes.text
    "Represent the display name of the port. Unique per host"

    links = [link.Link]
    "Represent a list containing a self link and associated lldp agent links"

    tlvs = [link.Link]
    "Links to the collection of LldpNeighbours on this ihost"

    chassis_id = wtypes.text
    "Represent the status of the lldp agent"

    port_identifier = wtypes.text
    "Represent the LLDP port id of the lldp agent"

    port_description = wtypes.text
    "Represent the port description of the lldp agent"

    system_description = wtypes.text
    "Represent the status of the lldp agent"

    system_name = wtypes.text
    "Represent the status of the lldp agent"

    system_capabilities = wtypes.text
    "Represent the status of the lldp agent"

    management_address = wtypes.text
    "Represent the status of the lldp agent"

    ttl = wtypes.text
    "Represent the time-to-live of the lldp agent"

    dot1_lag = wtypes.text
    "Represent the 802.1 link aggregation status of the lldp agent"

    dot1_vlan_names = wtypes.text
    "Represent the 802.1 vlan names of the lldp agent"

    dot3_mac_status = wtypes.text
    "Represent the 802.3 MAC/PHY status of the lldp agent"

    dot3_max_frame = wtypes.text
    "Represent the 802.3 maximum frame size of the lldp agent"

    def __init__(self, **kwargs):
        self.fields = list(objects.lldp_agent.fields.keys())
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_lldp_agent, expand=True):
        lldp_agent = LLDPAgent(**rpc_lldp_agent.as_dict())
        if not expand:
            lldp_agent.unset_fields_except([
                'uuid', 'host_id', 'port_id', 'status', 'host_uuid',
                'port_uuid', 'port_name', 'port_namedisplay',
                'created_at', 'updated_at',
                constants.LLDP_TLV_TYPE_CHASSIS_ID,
                constants.LLDP_TLV_TYPE_PORT_ID,
                constants.LLDP_TLV_TYPE_TTL,
                constants.LLDP_TLV_TYPE_SYSTEM_NAME,
                constants.LLDP_TLV_TYPE_SYSTEM_DESC,
                constants.LLDP_TLV_TYPE_SYSTEM_CAP,
                constants.LLDP_TLV_TYPE_MGMT_ADDR,
                constants.LLDP_TLV_TYPE_PORT_DESC,
                constants.LLDP_TLV_TYPE_DOT1_LAG,
                constants.LLDP_TLV_TYPE_DOT1_VLAN_NAMES,
                constants.LLDP_TLV_TYPE_DOT3_MAC_STATUS,
                constants.LLDP_TLV_TYPE_DOT3_MAX_FRAME])

        # never expose the id attribute
        lldp_agent.host_id = wtypes.Unset
        lldp_agent.port_id = wtypes.Unset

        lldp_agent.links = [
            link.Link.make_link('self', pecan.request.host_url,
                                'lldp_agents', lldp_agent.uuid),
            link.Link.make_link('bookmark', pecan.request.host_url,
                                'lldp_agents', lldp_agent.uuid,
                                bookmark=True)]

        if expand:
            lldp_agent.tlvs = [
                link.Link.make_link('self',
                                    pecan.request.host_url,
                                    'lldp_agents',
                                    lldp_agent.uuid + "/tlvs"),
                link.Link.make_link('bookmark',
                                    pecan.request.host_url,
                                    'lldp_agents',
                                    lldp_agent.uuid + "/tlvs",
                                    bookmark=True)]

        return lldp_agent


class LLDPAgentCollection(collection.Collection):
    """API representation of a collection of LldpAgent objects."""

    lldp_agents = [LLDPAgent]
    "A list containing LldpAgent objects"

    def __init__(self, **kwargs):
        self._type = 'lldp_agents'

    @classmethod
    def convert_with_links(cls, rpc_lldp_agents, limit, url=None,
                           expand=False, **kwargs):
        collection = LLDPAgentCollection()
        collection.lldp_agents = [LLDPAgent.convert_with_links(a, expand)
                                  for a in rpc_lldp_agents]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'LLDPAgentController'


class LLDPAgentController(rest.RestController):
    """REST controller for LldpAgents."""

    tlvs = lldp_tlv.LLDPTLVController(
        from_lldp_agents=True)
    "Expose tlvs as a sub-element of LldpAgents"

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_ihosts=False, from_ports=False):
        self._from_ihosts = from_ihosts
        self._from_ports = from_ports

    def _get_lldp_agents_collection(self, uuid,
                                    marker, limit, sort_key, sort_dir,
                                    expand=False, resource_url=None):

        if self._from_ihosts and not uuid:
            raise exception.InvalidParameterValue(_("Host id not specified."))

        if self._from_ports and not uuid:
            raise exception.InvalidParameterValue(_("Port id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.lldp_agent.get_by_uuid(pecan.request.context,
                                                        marker)

        if self._from_ihosts:
            agents = pecan.request.dbapi.lldp_agent_get_by_host(
                uuid, limit, marker_obj, sort_key=sort_key, sort_dir=sort_dir)

        elif self._from_ports:
            agents = []
            agent = pecan.request.dbapi.lldp_agent_get_by_port(uuid)
            agents.append(agent)
        else:
            agents = pecan.request.dbapi.lldp_agent_get_list(
                limit, marker_obj, sort_key=sort_key, sort_dir=sort_dir)

        return LLDPAgentCollection.convert_with_links(agents, limit,
                                                      url=resource_url,
                                                      expand=expand,
                                                      sort_key=sort_key,
                                                      sort_dir=sort_dir)

    @wsme_pecan.wsexpose(LLDPAgentCollection, types.uuid,
                         types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, uuid=None,
                marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of lldp agents."""
        return self._get_lldp_agents_collection(uuid, marker, limit, sort_key,
                                                sort_dir)

    @wsme_pecan.wsexpose(LLDPAgentCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of lldp_agents with detail."""

        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "lldp_agents":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['lldp_agents', 'detail'])
        return self._get_lldp_agents_collection(uuid, marker, limit, sort_key,
                                                sort_dir, expand, resource_url)

    @wsme_pecan.wsexpose(LLDPAgent, types.uuid)
    def get_one(self, port_uuid):
        """Retrieve information about the given lldp agent."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_lldp_agent = objects.lldp_agent.get_by_uuid(
            pecan.request.context, port_uuid)
        return LLDPAgent.convert_with_links(rpc_lldp_agent)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(LLDPAgent, body=LLDPAgent)
    def post(self, agent):
        """Create a new lldp agent."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        try:
            host_uuid = agent.host_uuid
            port_uuid = agent.port_uuid
            new_agent = pecan.request.dbapi.lldp_agent_create(port_uuid,
                                                              host_uuid,
                                                              agent.as_dict())
        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data"))
        return agent.convert_with_links(new_agent)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [LLDPAgentPatchType])
    @wsme_pecan.wsexpose(LLDPAgent, types.uuid,
                         body=[LLDPAgentPatchType])
    def patch(self, uuid, patch):
        """Update an existing lldp agent."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted
        if self._from_ports:
            raise exception.OperationNotPermitted

        rpc_agent = objects.lldp_agent.get_by_uuid(
            pecan.request.context, uuid)

        # replace ihost_uuid and port_uuid with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)
        for p in patch_obj:
            if p['path'] == '/host_uuid':
                p['path'] = '/host_id'
                host = objects.host.get_by_uuid(pecan.request.context,
                                                p['value'])
                p['value'] = host.id

            if p['path'] == '/port_uuid':
                p['path'] = '/port_id'
                try:
                    port = objects.port.get_by_uuid(
                        pecan.request.context, p['value'])
                    p['value'] = port.id
                except exception.SysinvException as e:
                    LOG.exception(e)
                    p['value'] = None

        try:
            agent = LLDPAgent(**jsonpatch.apply_patch(rpc_agent.as_dict(),
                                                      patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Update only the fields that have changed
        for field in objects.lldp_agent.fields:
            if rpc_agent[field] != getattr(agent, field):
                rpc_agent[field] = getattr(agent, field)

        rpc_agent.save()
        return LLDPAgent.convert_with_links(rpc_agent)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, uuid):
        """Delete an lldp agent."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted
        if self._from_ports:
            raise exception.OperationNotPermitted

        pecan.request.dbapi.lldp_agent_destroy(uuid)
