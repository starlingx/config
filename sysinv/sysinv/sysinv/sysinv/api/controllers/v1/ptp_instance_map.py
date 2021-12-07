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


class PtpInstanceMapPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class PtpInstanceMap(base.APIBase):
    """API representation of a PTP instance map to host.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a PTP instance association to host.
    """

    created_at = wtypes.datetime.datetime
    "Timestamp of creation of this PTP instance mapping"

    id = int
    "Unique ID for this PTP instance mapping"

    uuid = types.uuid
    "Unique UUID for this PTP instance mapping"

    host_id = int
    "ID of the associated host"

    hostname = wtypes.text
    "Name of the associated host"

    ptp_instance_id = int
    "ID of the associated PTP instance"

    name = wtypes.text
    "Name of the associated PTP instance"

    service = wtypes.text
    "Service type of the associated PTP instance"

    def __init__(self, **kwargs):
        self.fields = list(objects.ptp_instance_map.fields.keys())
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_ptp_instance_map, expand=True):
        ptp_instance_map = PtpInstanceMap(**rpc_ptp_instance_map.as_dict())
        if not expand:
            ptp_instance_map.unset_fields_except(
                ['uuid', 'host_id', 'hostname', 'ptp_instance_id',
                 'name', 'service', 'created_at'])

        LOG.debug("PtpInstanceMap.convert_with_links: converted %s" %
                  ptp_instance_map.as_dict())
        return ptp_instance_map


class PtpInstanceMapCollection(collection.Collection):
    """API representation of a collection of PTP instance maps."""

    ptp_instance_maps = [PtpInstanceMap]
    "A list containing PTP instance mapping objects"

    def __init__(self, **kwargs):
        self._type = 'ptp_instance_maps'

    @classmethod
    def convert_with_links(cls, rpc_ptp_instance_maps, limit, url=None,
                           expand=False, **kwargs):
        collection = PtpInstanceMapCollection()
        collection.ptp_instance_maps = \
            [PtpInstanceMap.convert_with_links(p, expand)
                for p in rpc_ptp_instance_maps]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'PtpInstanceMapController'


class PtpInstanceMapController(rest.RestController):
    """REST controller for PTP instance map."""

    @wsme_pecan.wsexpose(PtpInstanceMap, types.uuid)
    def get_one(self, ptp_instance_map_uuid):
        """Retrieve a single PTP instance."""
        LOG.debug("PtpInstanceMapController.get_one: uuid=%s" %
                  ptp_instance_map_uuid)
        try:
            ptp_instance_map = objects.ptp_instance_map.get_by_uuid(
                pecan.request.context,
                ptp_instance_map_uuid)
        except exception.InvalidParameterValue:
            raise wsme.exc.ClientSideError(
                _("No PTP instance mapping found for %s"
                  % ptp_instance_map_uuid))

        return PtpInstanceMap.convert_with_links(ptp_instance_map)

    def _check_instance_exists(self, id):
        LOG.debug("PtpInstanceMapController._check_instance_exists: "
                  "id %d" % id)
        try:
            pecan.request.dbapi.ptp_instance_get(id)
        except exception.PtpInstanceNotFound:
            raise wsme.exc.ClientSideError(
                _("No PTP parameter object found with id %d" % id))

    def _check_host_exists(self, id):
        LOG.debug("PtpInstanceMapController._check_host_exists: "
                  "id %d" % id)
        try:
            pecan.request.dbapi.ihost_get(id)
        except exception.ServerNotFound:
            raise wsme.exc.ClientSideError(
                _("No host found with id %d" % id))

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(PtpInstanceMap, body=PtpInstanceMap)
    def post(self, ptp_instance_map):
        """Create a new PTP instance mapping."""
        ptp_instance_map_dict = ptp_instance_map.as_dict()
        LOG.debug("PtpInstanceMapController.post: %s"
                  % ptp_instance_map_dict)

        self._check_instance_exists(ptp_instance_map_dict['ptp_instance_id'])
        self._check_host_exists(ptp_instance_map_dict['host_id'])

        result = pecan.request.dbapi.ptp_instance_set_host(
            ptp_instance_map_dict)
        return PtpInstanceMap.convert_with_links(result)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, ptp_instance_map_uuid):
        """Delete a PTP instance mapping."""
        LOG.debug("PtpInstanceMapController.delete: %s"
                  % ptp_instance_map_uuid)
        ptp_instance_map = objects.ptp_instance_map.get_by_uuid(
            pecan.request.context, ptp_instance_map_uuid)
        pecan.request.dbapi.ptp_parameter_unset_host(
            ptp_instance_map.as_dict())
