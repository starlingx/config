#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan
from pecan import rest
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import types
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class PtpInterfaceMapPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class PtpInterfaceMap(base.APIBase):
    """API representation of a PTP interface map to interface.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a PTP interface association to interface.
    """

    created_at = wtypes.datetime.datetime
    "Timestamp of creation of this PTP interface mapping"

    id = int
    "Unique ID for this PTP interface mapping"

    uuid = types.uuid
    "Unique UUID for this PTP interface mapping"

    interface_id = int
    "ID of the associated interface"

    ifname = wtypes.text
    "Name of the associated interface"

    iftype = wtypes.text
    "Type of the associated interface"

    hostname = wtypes.text
    "Name of the host for the associated interface"

    ptp_interface_id = int
    "ID of the associated PTP interface"

    name = wtypes.text
    "Name of the PTP instance for the associated PTP interface"

    service = wtypes.text
    "Service type of the PTP instance for the associated PTP interface"

    def __init__(self, **kwargs):
        self.fields = list(objects.ptp_interface_map.fields.keys())
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_ptp_interface_map, expand=True):
        ptp_interface_map = PtpInterfaceMap(**rpc_ptp_interface_map.as_dict())
        if not expand:
            ptp_interface_map.unset_fields_except(
                ['uuid', 'interface_id', 'ifname', 'iftype', 'hostname',
                 'ptp_interface_id', 'name', 'service', 'created_at'])

        LOG.debug("PtpInterfaceMap.convert_with_links: converted %s" %
                  ptp_interface_map.as_dict())
        return ptp_interface_map


class PtpInterfaceMapCollection(collection.Collection):
    """API representation of a collection of PTP interface maps."""

    ptp_interface_maps = [PtpInterfaceMap]
    "A list containing PTP interface map objects"

    def __init__(self, **kwargs):
        self._type = 'ptp_interface_maps'

    @classmethod
    def convert_with_links(cls, rpc_ptp_interface_maps, limit, url=None,
                           expand=False, **kwargs):
        collection = PtpInterfaceMapCollection()
        collection.ptp_interface_maps = \
            [PtpInterfaceMap.convert_with_links(p, expand)
                for p in rpc_ptp_interface_maps]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'PtpInterfaceMapController'


class PtpInterfaceMapController(rest.RestController):
    """REST controller for PTP interface map."""

    @wsme_pecan.wsexpose(PtpInterfaceMap, types.uuid)
    def get_one(self, ptp_interface_map_uuid):
        """Retrieve a single PTP interface."""
        LOG.debug("PtpInterfaceMapController.get_one: uuid=%s" %
                  ptp_interface_map_uuid)
        try:
            ptp_interface_map = objects.ptp_interface_map.get_by_uuid(
                pecan.request.context,
                ptp_interface_map_uuid)
        except exception.InvalidParameterValue:
            raise wsme.exc.ClientSideError(
                _("No PTP interface mapping found for %s"
                  % ptp_interface_map_uuid))

        return PtpInterfaceMap.convert_with_links(ptp_interface_map)

    def _check_interface_exists(self, id):
        LOG.debug("PtpInterfaceMapController._check_interface_exists: "
                  "id %d" % id)
        try:
            pecan.request.dbapi.iinterface_get(id)
        except exception.InvalidParameterValue:
            raise wsme.exc.ClientSideError(
                _("No interface found with id %d" % id))

    def _check_ptp_interface_exists(self, id):
        LOG.debug("PtpInterfaceMapController._check_ptp_interface_exists: "
                  "id %d" % id)
        try:
            pecan.request.dbapi.ptp_interface_get(id)
        except exception.PtpInterfaceNotFound:
            raise wsme.exc.ClientSideError(
                _("No PTP interface found with id %d" % id))

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(PtpInterfaceMap, body=PtpInterfaceMap)
    def post(self, ptp_interface_map):
        """Create a new PTP interface mapping."""
        ptp_interface_map_dict = ptp_interface_map.as_dict()
        LOG.debug("PtpInterfaceMapController.post: %s"
                  % ptp_interface_map_dict)

        self._check_interface_exists(ptp_interface_map_dict['interface_id'])
        self._check_ptp_interface_exists(
            ptp_interface_map_dict['ptp_interface_id'])

        result = pecan.request.dbapi.ptp_interface_set_interface(
            ptp_interface_map_dict)
        return PtpInterfaceMap.convert_with_links(result)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, ptp_interface_map_uuid):
        """Delete a PTP interface mapping."""
        LOG.debug("PtpInterfaceMapController.delete: %s"
                  % ptp_interface_map_uuid)
        ptp_interface_map = objects.ptp_interface_map.get_by_uuid(
            pecan.request.context, ptp_interface_map_uuid)
        pecan.request.dbapi.ptp_parameter_unset_interface(
            ptp_interface_map.as_dict())
