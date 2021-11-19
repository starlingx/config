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


class PtpParameterOwnershipPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class PtpParameterOwnership(base.APIBase):
    """API representation of a PTP parameter ownership.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a PTP parameter ownership.
    """

    created_at = wtypes.datetime.datetime
    "Timestamp of creation of this PTP parameter ownership"

    id = int
    "Unique ID for this PTP parameter ownership"

    uuid = types.uuid
    "Unique UUID for this PTP parameter ownership"

    parameter_uuid = types.uuid
    "UUID of the PTP parameter (name/value)"

    owner_uuid = types.uuid
    "UUID of the entity associated to PTP parameter (instance or interface)"

    def __init__(self, **kwargs):
        self.fields = list(objects.ptp_paramownership.fields.keys())
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_ptp_paramownership, expand=True):
        ptp_parameter_ownership = PtpParameterOwnership(
            **rpc_ptp_paramownership.as_dict())
        if not expand:
            ptp_parameter_ownership.unset_fields_except(
                ['uuid', 'parameter_uuid', 'owner_uuid', 'created_at'])

        LOG.debug("PtpParameterOwnership.convert_with_links: converted %s" %
                  ptp_parameter_ownership.as_dict())
        return ptp_parameter_ownership


class PtpParameterOwnershipCollection(collection.Collection):
    """API representation of a collection of PTP owners."""

    ptp_parameter_ownerships = [PtpParameterOwnership]
    "A list containing PTP ownership objects"

    def __init__(self, **kwargs):
        self._type = 'ptp_parameter_ownerships'

    @classmethod
    def convert_with_links(cls, rpc_ptp_paramownerships, limit, url=None,
                           expand=False, **kwargs):
        collection = PtpParameterOwnershipCollection()
        collection.ptp_paramownerships = \
            [PtpParameterOwnership.convert_with_links(p, expand)
                for p in rpc_ptp_paramownerships]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'PtpParameterOwnershipController'


class PtpParameterOwnershipController(rest.RestController):
    """REST controller for PTP parameter ownership."""

    @wsme_pecan.wsexpose(PtpParameterOwnership, types.uuid)
    def get_one(self, ptp_paramownership_uuid):
        """Retrieve a single PTP parameter."""
        LOG.debug("PtpParameterOwnershipController.get_one: uuid=%s" %
                  ptp_paramownership_uuid)
        try:
            ptp_paramownership = objects.ptp_paramownership.get_by_uuid(
                pecan.request.context,
                ptp_paramownership_uuid)
        except exception.InvalidParameterValue:
            raise wsme.exc.ClientSideError(
                _("No PTP parameter ownership found for %s"
                  % ptp_paramownership_uuid))

        return PtpParameterOwnership.convert_with_links(ptp_paramownership)

    def _check_parameter_exists(self, uuid):
        LOG.debug("PtpParameterOwnershipController._check_parameter_exists: "
                  "uuid %s" % uuid)
        try:
            pecan.request.dbapi.ptp_parameter_get(uuid)
        except exception.PtpParameterNotFound:
            raise wsme.exc.ClientSideError(
                _("No PTP parameter object found with id %s" % uuid))

    def _check_owner_exists(self, uuid):
        LOG.debug("PtpParameterOwnershipController._check_owner_exists: "
                  "uuid %s" % uuid)
        try:
            pecan.request.dbapi.ptp_paramowner_get(uuid)
        except exception.NotFound:
            raise wsme.exc.ClientSideError(
                _("No PTP parameter owner found with id %s" % uuid))

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(PtpParameterOwnership, body=PtpParameterOwnership)
    def post(self, ptp_paramownership):
        """Create a new PTP parameter ownership."""
        ptp_paramownership_dict = ptp_paramownership.as_dict()
        LOG.debug("PtpParameterOwnershipController.post: %s"
                  % ptp_paramownership_dict)

        self._check_parameter_exists(ptp_paramownership_dict['parameter_uuid'])
        self._check_owner_exists(ptp_paramownership_dict['owner_uuid'])

        result = pecan.request.dbapi.ptp_parameter_set_owner(
            ptp_paramownership_dict)
        return PtpParameterOwnership.convert_with_links(result)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, ptp_paramownership_uuid):
        """Delete a PTP parameter ownership."""
        LOG.debug("PtpParameterController.delete: %s"
                  % ptp_paramownership_uuid)
        ptp_paramownership = objects.ptp_paramownership.get_by_uuid(
            pecan.request.context, ptp_paramownership_uuid)
        pecan.request.dbapi.ptp_parameter_unset_owner(
            ptp_paramownership.as_dict())
