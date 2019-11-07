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
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class LLDPTLVPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return []


class LLDPTLV(base.APIBase):
    """API representation of an LldpTlv

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of an
    LLDP tlv.
    """

    type = wtypes.text
    "Represent the type of the lldp tlv"

    value = wtypes.text
    "Represent the value of the lldp tlv"

    agent_id = int
    "Represent the agent_id the lldp tlv belongs to"

    neighbour_id = int
    "Represent the neighbour the lldp tlv belongs to"

    agent_uuid = types.uuid
    "Represent the UUID of the agent the lldp tlv belongs to"

    neighbour_uuid = types.uuid
    "Represent the UUID of the neighbour the lldp tlv belongs to"

    links = [link.Link]
    "Represent a list containing a self link and associated lldp tlv links"

    def __init__(self, **kwargs):
        self.fields = objects.lldp_tlv.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_lldp_tlv, expand=True):
        lldp_tlv = LLDPTLV(**rpc_lldp_tlv.as_dict())
        if not expand:
            lldp_tlv.unset_fields_except(['type', 'value'])

        # never expose the id attribute
        lldp_tlv.agent_id = wtypes.Unset
        lldp_tlv.neighbour_id = wtypes.Unset

        lldp_tlv.links = [link.Link.make_link('self', pecan.request.host_url,
                                              'lldp_tlvs', lldp_tlv.type),
                          link.Link.make_link('bookmark',
                                              pecan.request.host_url,
                                              'lldp_tlvs', lldp_tlv.type,
                                              bookmark=True)]
        return lldp_tlv


class LLDPTLVCollection(collection.Collection):
    """API representation of a collection of LldpTlv objects."""

    lldp_tlvs = [LLDPTLV]
    "A list containing LldpTlv objects"

    def __init__(self, **kwargs):
        self._type = 'lldp_tlvs'

    @classmethod
    def convert_with_links(cls, rpc_lldp_tlvs, limit, url=None,
                           expand=False, **kwargs):
        collection = LLDPTLVCollection()
        collection.lldp_tlvs = [LLDPTLV.convert_with_links(a, expand)
                                for a in rpc_lldp_tlvs]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'LLDPTLVController'


class LLDPTLVController(rest.RestController):
    """REST controller for LldpTlvs."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_lldp_agents=False, from_lldp_neighbours=False):
        self._from_lldp_agents = from_lldp_agents
        self._from_lldp_neighbours = from_lldp_neighbours

    def _get_lldp_tlvs_collection(self, uuid,
                                  marker, limit, sort_key, sort_dir,
                                  expand=False, resource_url=None):

        if self._from_lldp_agents and not uuid:
            raise exception.InvalidParameterValue(
                _("LLDP agent id not specified."))

        if self._from_lldp_neighbours and not uuid:
            raise exception.InvalidParameterValue(
                _("LLDP neighbour id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.lldp_tlv.get_by_uuid(pecan.request.context,
                                                      marker)

        if self._from_lldp_agents:
            tlvs = pecan.request.dbapi.lldp_tlv_get_by_agent(uuid, limit,
                                                             marker_obj,
                                                             sort_key=sort_key,
                                                             sort_dir=sort_dir)

        elif self._from_lldp_neighbours:
            tlvs = pecan.request.dbapi.lldp_tlv_get_by_neighbour(
                uuid, limit, marker_obj, sort_key=sort_key, sort_dir=sort_dir)
        else:
            tlvs = pecan.request.dbapi.lldp_tlv_get_list(
                limit, marker_obj, sort_key=sort_key, sort_dir=sort_dir)

        return LLDPTLVCollection.convert_with_links(tlvs, limit,
                                                    url=resource_url,
                                                    expand=expand,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

    @wsme_pecan.wsexpose(LLDPTLVCollection, types.uuid,
                         types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, uuid=None,
                marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of lldp tlvs."""
        return self._get_lldp_tlvs_collection(uuid, marker, limit, sort_key,
                                              sort_dir)

    @wsme_pecan.wsexpose(LLDPTLVCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of lldp_tlvs with detail."""

        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "lldp_tlvs":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['lldp_tlvs', 'detail'])
        return self._get_lldp_tlvs_collection(uuid, marker, limit, sort_key,
                                              sort_dir, expand, resource_url)

    @wsme_pecan.wsexpose(LLDPTLV, int)
    def get_one(self, id):
        """Retrieve information about the given lldp tlv."""
        rpc_lldp_tlv = objects.lldp_tlv.get_by_id(
            pecan.request.context, id)
        return LLDPTLV.convert_with_links(rpc_lldp_tlv)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(LLDPTLV, body=LLDPTLV)
    def post(self, tlv):
        """Create a new lldp tlv."""
        if self._from_lldp_agents:
            raise exception.OperationNotPermitted

        if self._from_lldp_neighbours:
            raise exception.OperationNotPermitted

        try:
            agent_uuid = tlv.agent_uuid
            neighbour_uuid = tlv.neighbour_uuid
            new_tlv = pecan.request.dbapi.lldp_tlv_create(tlv.as_dict(),
                                                          agent_uuid,
                                                          neighbour_uuid)
        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data"))
        return tlv.convert_with_links(new_tlv)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [LLDPTLVPatchType])
    @wsme_pecan.wsexpose(LLDPTLV, int,
                         body=[LLDPTLVPatchType])
    def patch(self, id, patch):
        """Update an existing lldp tlv."""
        if self._from_lldp_agents:
            raise exception.OperationNotPermitted
        if self._from_lldp_neighbours:
            raise exception.OperationNotPermitted

        rpc_tlv = objects.lldp_tlv.get_by_id(
            pecan.request.context, id)

        # replace agent_uuid and neighbour_uuid with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)
        for p in patch_obj:
            if p['path'] == '/agent_uuid':
                p['path'] = '/agent_id'
                agent = objects.lldp_agent.get_by_uuid(pecan.request.context,
                                                       p['value'])
                p['value'] = agent.id

            if p['path'] == '/neighbour_uuid':
                p['path'] = '/neighbour_id'
                try:
                    neighbour = objects.lldp_neighbour.get_by_uuid(
                        pecan.request.context, p['value'])
                    p['value'] = neighbour.id
                except exception.SysinvException as e:
                    LOG.exception(e)
                    p['value'] = None

        try:
            tlv = LLDPTLV(
                **jsonpatch.apply_patch(rpc_tlv.as_dict(), patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Update only the fields that have changed
        for field in objects.lldp_tlv.fields:
            if rpc_tlv[field] != getattr(tlv, field):
                rpc_tlv[field] = getattr(tlv, field)

        rpc_tlv.save()
        return LLDPTLV.convert_with_links(rpc_tlv)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, int, status_code=204)
    def delete(self, id):
        """Delete an lldp tlv."""
        if self._from_lldp_agents:
            raise exception.OperationNotPermitted
        if self._from_lldp_neighbours:
            raise exception.OperationNotPermitted

        pecan.request.dbapi.lldp_tlv_destroy(id)
