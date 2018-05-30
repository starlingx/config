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
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log

LOG = log.getLogger(__name__)


class LLDPNeighbourPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return []


class LLDPNeighbour(base.APIBase):
    """API representation of an LLDP Neighbour

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of an
    LLDP neighbour.
    """

    uuid = types.uuid
    "Unique UUID for this port"

    msap = wtypes.text
    "Represent the MAC service access point of the lldp neighbour"

    host_id = int
    "Represent the host_id the lldp neighbour belongs to"

    port_id = int
    "Represent the port_id the lldp neighbour belongs to"

    host_uuid = types.uuid
    "Represent the UUID of the host the lldp neighbour belongs to"

    port_uuid = types.uuid
    "Represent the UUID of the port the lldp neighbour belongs to"

    port_name = wtypes.text
    "Represent the name of the port the lldp neighbour belongs to"

    port_namedisplay = wtypes.text
    "Represent the display name of the port. Unique per host"

    links = [link.Link]
    "Represent a list containing a self link and associated lldp neighbour"
    "links"

    tlvs = [link.Link]
    "Links to the collection of LldpNeighbours on this ihost"

    chassis_id = wtypes.text
    "Represent the status of the lldp neighbour"

    system_description = wtypes.text
    "Represent the status of the lldp neighbour"

    system_name = wtypes.text
    "Represent the status of the lldp neighbour"

    system_capabilities = wtypes.text
    "Represent the status of the lldp neighbour"

    management_address = wtypes.text
    "Represent the status of the lldp neighbour"

    port_identifier = wtypes.text
    "Represent the port identifier of the lldp neighbour"

    port_description = wtypes.text
    "Represent the port description of the lldp neighbour"

    dot1_lag = wtypes.text
    "Represent the 802.1 link aggregation status of the lldp neighbour"

    dot1_port_vid = wtypes.text
    "Represent the 802.1 port vlan id of the lldp neighbour"

    dot1_vid_digest = wtypes.text
    "Represent the 802.1 vlan id digest of the lldp neighbour"

    dot1_management_vid = wtypes.text
    "Represent the 802.1 management vlan id of the lldp neighbour"

    dot1_vlan_names = wtypes.text
    "Represent the 802.1 vlan names of the lldp neighbour"

    dot1_proto_vids = wtypes.text
    "Represent the 802.1 protocol vlan ids of the lldp neighbour"

    dot1_proto_ids = wtypes.text
    "Represent the 802.1 protocol ids of the lldp neighbour"

    dot3_mac_status = wtypes.text
    "Represent the 802.3 MAC/PHY status of the lldp neighbour"

    dot3_max_frame = wtypes.text
    "Represent the 802.3 maximum frame size of the lldp neighbour"

    dot3_power_mdi = wtypes.text
    "Represent the 802.3 power mdi status of the lldp neighbour"

    ttl = wtypes.text
    "Represent the neighbour time-to-live"

    def __init__(self, **kwargs):
        self.fields = objects.lldp_neighbour.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_lldp_neighbour, expand=True):
        lldp_neighbour = LLDPNeighbour(**rpc_lldp_neighbour.as_dict())

        if not expand:
            lldp_neighbour.unset_fields_except([
                'uuid', 'host_id', 'port_id', 'msap', 'host_uuid', 'port_uuid',
                'port_name', 'port_namedisplay', 'created_at', 'updated_at',
                constants.LLDP_TLV_TYPE_CHASSIS_ID,
                constants.LLDP_TLV_TYPE_PORT_ID,
                constants.LLDP_TLV_TYPE_TTL,
                constants.LLDP_TLV_TYPE_SYSTEM_NAME,
                constants.LLDP_TLV_TYPE_SYSTEM_DESC,
                constants.LLDP_TLV_TYPE_SYSTEM_CAP,
                constants.LLDP_TLV_TYPE_MGMT_ADDR,
                constants.LLDP_TLV_TYPE_PORT_DESC,
                constants.LLDP_TLV_TYPE_DOT1_LAG,
                constants.LLDP_TLV_TYPE_DOT1_PORT_VID,
                constants.LLDP_TLV_TYPE_DOT1_VID_DIGEST,
                constants.LLDP_TLV_TYPE_DOT1_MGMT_VID,
                constants.LLDP_TLV_TYPE_DOT1_PROTO_VIDS,
                constants.LLDP_TLV_TYPE_DOT1_PROTO_IDS,
                constants.LLDP_TLV_TYPE_DOT1_VLAN_NAMES,
                constants.LLDP_TLV_TYPE_DOT1_VID_DIGEST,
                constants.LLDP_TLV_TYPE_DOT3_MAC_STATUS,
                constants.LLDP_TLV_TYPE_DOT3_MAX_FRAME,
                constants.LLDP_TLV_TYPE_DOT3_POWER_MDI])

        # never expose the id attribute
        lldp_neighbour.host_id = wtypes.Unset
        lldp_neighbour.port_id = wtypes.Unset

        lldp_neighbour.links = [
            link.Link.make_link('self', pecan.request.host_url,
                                'lldp_neighbours', lldp_neighbour.uuid),
            link.Link.make_link('bookmark',
                                pecan.request.host_url,
                                'lldp_neighbours', lldp_neighbour.uuid,
                                bookmark=True)]

        if expand:
            lldp_neighbour.tlvs = [
                link.Link.make_link('self',
                                    pecan.request.host_url,
                                    'lldp_neighbours',
                                    lldp_neighbour.uuid + "/tlvs"),
                link.Link.make_link('bookmark',
                                    pecan.request.host_url,
                                    'lldp_neighbours',
                                    lldp_neighbour.uuid + "/tlvs",
                                    bookmark=True)]

        return lldp_neighbour


class LLDPNeighbourCollection(collection.Collection):
    """API representation of a collection of LldpNeighbour objects."""

    lldp_neighbours = [LLDPNeighbour]
    "A list containing LldpNeighbour objects"

    def __init__(self, **kwargs):
        self._type = 'lldp_neighbours'

    @classmethod
    def convert_with_links(cls, rpc_lldp_neighbours, limit, url=None,
                           expand=False, **kwargs):
        collection = LLDPNeighbourCollection()

        collection.lldp_neighbours = [LLDPNeighbour.convert_with_links(a,
                                                                       expand)
                                      for a in rpc_lldp_neighbours]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'LLDPNeighbourController'


class LLDPNeighbourController(rest.RestController):
    """REST controller for LldpNeighbours."""

    tlvs = lldp_tlv.LLDPTLVController(
        from_lldp_neighbours=True)
    "Expose tlvs as a sub-element of LldpNeighbours"

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_ihosts=False, from_ports=False):
        self._from_ihosts = from_ihosts
        self._from_ports = from_ports

    def _get_lldp_neighbours_collection(self, uuid, marker, limit, sort_key,
                                        sort_dir, expand=False,
                                        resource_url=None):

        if self._from_ihosts and not uuid:
            raise exception.InvalidParameterValue(_("Host id not specified."))

        if self._from_ports and not uuid:
            raise exception.InvalidParameterValue(_("Port id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.lldp_neighbour.get_by_uuid(
                pecan.request.context, marker)

        if self._from_ihosts:
            neighbours = pecan.request.dbapi.lldp_neighbour_get_by_host(
                uuid, limit, marker_obj, sort_key=sort_key, sort_dir=sort_dir)

        elif self._from_ports:
            neighbours = pecan.request.dbapi.lldp_neighbour_get_by_port(
                uuid, limit, marker_obj, sort_key=sort_key, sort_dir=sort_dir)
        else:
            neighbours = pecan.request.dbapi.lldp_neighbour_get_list(
                limit, marker_obj, sort_key=sort_key, sort_dir=sort_dir)

        return LLDPNeighbourCollection.convert_with_links(neighbours, limit,
                                                          url=resource_url,
                                                          expand=expand,
                                                          sort_key=sort_key,
                                                          sort_dir=sort_dir)

    @wsme_pecan.wsexpose(LLDPNeighbourCollection, types.uuid,
                         types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, uuid=None,
                marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of lldp neighbours."""

        return self._get_lldp_neighbours_collection(uuid, marker, limit,
                                                    sort_key, sort_dir)

    @wsme_pecan.wsexpose(LLDPNeighbourCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of lldp_neighbours with detail."""

        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "lldp_neighbours":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['lldp_neighbours', 'detail'])
        return self._get_lldp_neighbours_collection(uuid, marker, limit,
                                                    sort_key, sort_dir, expand,
                                                    resource_url)

    @wsme_pecan.wsexpose(LLDPNeighbour, types.uuid)
    def get_one(self, port_uuid):
        """Retrieve information about the given lldp neighbour."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_lldp_neighbour = objects.lldp_neighbour.get_by_uuid(
            pecan.request.context, port_uuid)
        return LLDPNeighbour.convert_with_links(rpc_lldp_neighbour)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(LLDPNeighbour, body=LLDPNeighbour)
    def post(self, neighbour):
        """Create a new lldp neighbour."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        try:
            host_uuid = neighbour.host_uuid
            port_uuid = neighbour.port_uuid
            new_neighbour = pecan.request.dbapi.lldp_neighbour_create(
                port_uuid, host_uuid, neighbour.as_dict())
        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data"))
        return neighbour.convert_with_links(new_neighbour)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [LLDPNeighbourPatchType])
    @wsme_pecan.wsexpose(LLDPNeighbour, types.uuid,
                         body=[LLDPNeighbourPatchType])
    def patch(self, uuid, patch):
        """Update an existing lldp neighbour."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted
        if self._from_ports:
            raise exception.OperationNotPermitted

        rpc_neighbour = objects.lldp_neighbour.get_by_uuid(
            pecan.request.context, uuid)

        # replace host_uuid and port_uuid with corresponding
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
            neighbour = LLDPNeighbour(
                **jsonpatch.apply_patch(rpc_neighbour.as_dict(), patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Update only the fields that have changed
        for field in objects.lldp_neighbour.fields:
            if rpc_neighbour[field] != getattr(neighbour, field):
                rpc_neighbour[field] = getattr(neighbour, field)

        rpc_neighbour.save()
        return LLDPNeighbour.convert_with_links(rpc_neighbour)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, uuid):
        """Delete an lldp neighbour."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted
        if self._from_ports:
            raise exception.OperationNotPermitted

        pecan.request.dbapi.lldp_neighbour_destroy(uuid)
