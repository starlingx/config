#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
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
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class PtpParameterPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return []


class PtpParameter(base.APIBase):
    """API representation of a PTP parameter.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a PTP parameter.
    """

    created_at = wtypes.datetime.datetime
    "Timestamp of creation of this PTP parameter"

    updated_at = wtypes.datetime.datetime
    "Timestamp of update of this PTP parameter"

    id = int
    "Unique ID for this PTP parameter"

    uuid = types.uuid
    "Unique UUID for this PTP parameter"

    name = wtypes.text
    "Name of PTP parameter"

    value = wtypes.text
    "Value of PTP parameter"

    owners = types.MultiType([list])
    "List of owners (UUIDs)"

    def __init__(self, **kwargs):
        self.fields = list(objects.ptp_parameter.fields.keys())
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_ptp_parameter, expand=True):
        ptp_parameter = PtpParameter(**rpc_ptp_parameter.as_dict())
        if not expand:
            ptp_parameter.unset_fields_except(['uuid',
                                               'name',
                                               'value',
                                               'owners',
                                               'created_at',
                                               'updated_at'])

        LOG.debug("PtpParameter.convert_with_links: converted %s" %
                  ptp_parameter.as_dict())
        return ptp_parameter


class PtpParameterCollection(collection.Collection):
    """API representation of a collection of PTP parameters."""

    ptp_parameters = [PtpParameter]
    "A list containing PTP parameter objects"

    def __init__(self, **kwargs):
        self._type = 'ptp_parameters'

    @classmethod
    def convert_with_links(cls, rpc_ptp_parameters, limit, url=None,
                           expand=False, **kwargs):
        collection = PtpParameterCollection()
        collection.ptp_parameters = [PtpParameter.convert_with_links(p, expand)
                                     for p in rpc_ptp_parameters]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'PtpParameterController'


class PtpParameterController(rest.RestController):
    """REST controller for PTP parameter."""

    def __init__(self, parent=None):
        self._parent = parent

    @wsme_pecan.wsexpose(PtpParameterCollection, types.uuid, wtypes.text,
                         types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, parent_uuid=None, type=None, marker=None, limit=None,
                sort_key='name', sort_dir='asc'):
        """Retrieve a list of PTP parameters."""
        LOG.debug("PtpParameterController.get_all: parent %s uuid %s type %s" %
                  (self._parent, parent_uuid, type))
        if self._parent and not parent_uuid:
            raise exception.InvalidParameterValue(_(
                  "Parent id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.ptp_parameter.get_by_uuid(
                pecan.request.context, marker)

        if parent_uuid:
            if self._parent == 'ptp_instance':
                ptp_parameters = \
                    pecan.request.dbapi.ptp_parameters_get_list(
                        ptp_instance=parent_uuid, limit=limit,
                        marker=marker_obj, sort_key=sort_key,
                        sort_dir=sort_dir)
            elif self._parent == 'ptp_interface':
                ptp_parameters = \
                    pecan.request.dbapi.ptp_parameters_get_list(
                        ptp_interface=parent_uuid, limit=limit,
                        marker=marker_obj, sort_key=sort_key,
                        sort_dir=sort_dir)
        elif type is not None:
            ptp_parameters = \
                pecan.request.dbapi.ptp_parameters_get_list_by_type(
                    type, limit, marker_obj, sort_key=sort_key,
                    sort_dir=sort_dir)
        else:
            ptp_parameters = pecan.request.dbapi.ptp_parameters_get_list(
                limit=limit, marker=marker_obj, sort_key=sort_key,
                sort_dir=sort_dir)

        return PtpParameterCollection.convert_with_links(
            ptp_parameters, limit, sort_key=sort_key, sort_dir=sort_dir)

    @wsme_pecan.wsexpose(PtpParameter, types.uuid)
    def get_one(self, ptp_parameter_uuid):
        """Retrieve a single PTP parameter."""
        LOG.debug("PtpParameterController.get_one: uuid=%s" %
                  ptp_parameter_uuid)
        try:
            ptp_parameter = objects.ptp_parameter.get_by_uuid(
                pecan.request.context, ptp_parameter_uuid)
        except exception.InvalidParameterValue:
            raise wsme.exc.ClientSideError(
                _("No PTP parameter found for %s" % ptp_parameter_uuid))

        return PtpParameter.convert_with_links(ptp_parameter)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(PtpParameter, body=PtpParameter)
    def post(self, ptp_parameter):
        """Create a new PTP parameter."""
        ptp_parameter_dict = ptp_parameter.as_dict()
        LOG.debug("PtpParameterController.post: %s" % ptp_parameter_dict)

        # Get rid of owner list to create the PTP parameter
        try:
            ptp_parameter_dict.pop('owners')
        except KeyError:
            LOG.debug("PtpParameterController.post: no owner list in %s" %
                      ptp_parameter_dict)

        result = pecan.request.dbapi.ptp_parameter_create(ptp_parameter_dict)
        return PtpParameter.convert_with_links(result)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [PtpParameterPatchType])
    @wsme_pecan.wsexpose(PtpParameter, types.uuid,
                         body=[PtpParameterPatchType])
    def patch(self, uuid, patch):
        """Update the value of an existing PTP parameter."""
        if self._parent:
            raise exception.OperationNotPermitted

        utils.validate_patch(patch)
        ptp_parameter = objects.ptp_parameter.get_by_uuid(
            pecan.request.context, uuid)

        patch_obj = jsonpatch.JsonPatch(patch)
        try:
            patched_parameter = PtpParameter(
                **jsonpatch.apply_patch(ptp_parameter.as_dict(), patch_obj))
        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Update only the fields that have changed
        for field in objects.ptp_parameter.fields:
            if ptp_parameter[field] != getattr(patched_parameter, field):
                ptp_parameter[field] = getattr(patched_parameter, field)

        ptp_parameter.save()
        return PtpParameter.convert_with_links(ptp_parameter)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, ptp_parameter_uuid):
        """Delete a PTP parameter."""
        LOG.debug("PtpParameterController.delete: %s" % ptp_parameter_uuid)
        if self._parent:
            raise exception.OperationNotPermitted

        # Only allow delete if there are no associated PTP instances and
        # interfaces
        owners = pecan.request.dbapi.ptp_parameter_get_owners(
            ptp_parameter_uuid)
        if owners:
            raise wsme.exc.ClientSideError("PTP parameter %s still in use"
                                           % ptp_parameter_uuid)

        pecan.request.dbapi.ptp_parameter_destroy(ptp_parameter_uuid)
