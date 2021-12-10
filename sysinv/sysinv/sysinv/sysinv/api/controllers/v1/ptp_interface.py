########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

import jsonpatch
import pecan
from pecan import rest
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import ptp_parameter
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class PtpInterfacePatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return []


class PtpInterface(base.APIBase):
    """API representation of a PTP interface.

    This class enforces type checking and value constraints, and converts
    between the interna object model and the API representation of a PTP
    interface.
    """

    created_at = wtypes.datetime.datetime
    "Timestamp of creation of this PTP interface"

    updated_at = wtypes.datetime.datetime
    "Timestamp of update of this PTP interface"

    # Inherited from PtpParameterOwner

    id = int
    "ID (primary key) of this PTP interface"

    uuid = types.uuid
    "Unique UUID for this PTP interface"

    type = wtypes.Enum(str,
                       constants.PTP_PARAMETER_OWNER_INSTANCE,
                       constants.PTP_PARAMETER_OWNER_INTERFACE)
    "Type of parameter owner (PTP_PARAMETER_OWNER_INTERFACE)"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                    six.integer_types)}
    "Capabilities (metadata) of this PTP interface"

    # Fields of PtpInterface

    name = wtypes.text
    "Name given to the PTP interface"

    ptp_instance_id = int
    "ID for the PTP instance this interface is associated with"

    ptp_instance_uuid = types.uuid
    "The UUID of the host this PTP interface belongs to"

    ptp_instance_name = wtypes.text
    "The name of the associated PTP instance"

    hostnames = types.MultiType([list])
    "Name(s) of host(s) associated to this PTP interface"

    interface_names = types.MultiType([list])
    "Interface(s) associated to this PTP interface"

    parameters = types.MultiType([list])
    "List of parameters referred by this PTP interface"

    def __init__(self, **kwargs):
        self.fields = list(objects.ptp_interface.fields.keys())
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    @classmethod
    def convert_with_links(cls, rpc_ptp_interface, expand=True):
        ptp_interface = PtpInterface(**rpc_ptp_interface.as_dict())
        if not expand:
            ptp_interface.unset_fields_except(['id',
                                               'uuid',
                                               'type',
                                               'capabilities',
                                               'name',
                                               'ptp_instance_id',
                                               'ptp_instance_uuid',
                                               'ptp_instance_name',
                                               'hostnames',
                                               'interface_names',
                                               'parameters',
                                               'created_at',
                                               'updated_at'])

        LOG.debug("PtpInterface.convert_with_links: converted %s" %
                  ptp_interface.as_dict())
        return ptp_interface


class PtpInterfaceCollection(collection.Collection):
    """API representation of a collection of PTP interfaces."""

    ptp_interfaces = [PtpInterface]
    "A list containing PtpInterface objects"

    def __init__(self, **kwargs):
        self._type = 'ptp_interfaces'

    @classmethod
    def convert_with_links(cls, rpc_ptp_interfaces, limit, url=None,
                           expand=False, **kwargs):
        collection = PtpInterfaceCollection()
        collection.ptp_interfaces = [PtpInterface.convert_with_links(p, expand)
                                     for p in rpc_ptp_interfaces]
        collection.next = collection.get_next(limit, url=url, **kwargs)

        return collection


LOCK_NAME = 'PtpInterfaceController'


class PtpInterfaceController(rest.RestController):
    """REST controller for ptp interfaces."""

    ptp_parameters = ptp_parameter.PtpParameterController(
        parent="ptp_interface")
    "Expose PTP parameters as a sub-element of PTP interfaces"

    def __init__(self, parent=None):
        self._parent = parent

    @wsme_pecan.wsexpose(PtpInterfaceCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, parent_uuid=None, marker=None, limit=None, sort_key='id',
                sort_dir='asc'):
        """Retrieve a list of PTP interfaces."""
        LOG.debug("PtpInterfaceController.get_all: parent %s uuid %s type %s" %
                  (self._parent, parent_uuid, type))
        if self._parent and not parent_uuid:
            raise exception.InvalidParameterValue(_(
                "Parent id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.ptp_interface.get_by_uuid(
                pecan.request.context, marker)

        if self._parent == 'iinterface':
            ptp_interfaces = \
                pecan.request.dbapi.ptp_interfaces_get_list(
                    interface=parent_uuid, limit=limit, marker=marker_obj,
                    sort_key=sort_key, sort_dir=sort_dir)
        elif self._parent == 'ihosts':
            ptp_interfaces = \
                pecan.request.dbapi.ptp_interfaces_get_list(
                    host=parent_uuid, limit=limit, marker=marker_obj,
                    sort_key=sort_key, sort_dir=sort_dir)
        else:
            ptp_interfaces = \
                pecan.request.dbapi.ptp_interfaces_get_list(
                    limit=limit, marker=marker_obj, sort_key=sort_key,
                    sort_dir=sort_dir)

        return PtpInterfaceCollection.convert_with_links(
            ptp_interfaces, limit, sort_key=sort_key, sort_dir=sort_dir)

    @wsme_pecan.wsexpose(PtpInterface, types.uuid)
    def get_one(self, ptp_interface_uuid):
        """Retrieve information about the given PTP interface"""
        LOG.debug("PtpInterfaceController.get_one: uuid=%s"
                  % ptp_interface_uuid)
        ptp_interface = objects.ptp_interface.get_by_uuid(
            pecan.request.context, ptp_interface_uuid)
        return PtpInterface.convert_with_links(ptp_interface)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(PtpInterface, body=PtpInterface)
    def post(self, ptp_interface):
        """Create a new PTP interface"""
        ptp_interface_dict = ptp_interface.as_dict()
        LOG.debug("PtpInterfaceController.post: %s" % ptp_interface_dict)

        """
        TODO: enforce "name" as required field here
        """

        ptp_instance_uuid = ptp_interface_dict.pop('ptp_instance_uuid', None)
        ptp_instance = objects.ptp_instance.get_by_uuid(pecan.request.context,
                                                        ptp_instance_uuid)
        ptp_interface_dict['ptp_instance_id'] = ptp_instance['id']

        return PtpInterface.convert_with_links(
            pecan.request.dbapi.ptp_interface_create(ptp_interface_dict))

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [PtpInterfacePatchType])
    @wsme_pecan.wsexpose(PtpInterface, types.uuid,
                         body=[PtpInterfacePatchType])
    def patch(self, uuid, patch):
        """Update the association between PTP interface and PTP parameters."""
        if self._parent:
            raise exception.OperationNotPermitted

        LOG.debug("PtpInterfaceController.patch: uuid %s params %s" %
                  (uuid, patch))
        utils.validate_patch(patch)

        try:
            # Check PTP interface exists
            objects.ptp_interface.get_by_uuid(pecan.request.context, uuid)
        except exception.InvalidParameterValue:
            raise wsme.exc.ClientSideError(
                _("No PTP interface found for %s" % uuid))

        # Currently patch is used to add/remove PTP parameters
        # (but not having both operations in same patch)
        patch_list = list(jsonpatch.JsonPatch(patch))
        for p in patch_list:
            param_uuid = p['value']
            try:
                # Check PTP parameter exists
                pecan.request.dbapi.ptp_parameter_get(param_uuid)
            except exception.PtpParameterNotFound:
                raise wsme.exc.ClientSideError(
                    _("No PTP parameter object found for %s" % param_uuid))

            if p['op'] == 'add':
                pecan.request.dbapi.ptp_interface_parameter_add(uuid,
                                                                param_uuid)
            else:
                pecan.request.dbapi.ptp_interface_parameter_remove(uuid,
                                                                   param_uuid)

        return PtpInterface.convert_with_links(
            objects.ptp_interface.get_by_uuid(pecan.request.context, uuid))

    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, ptp_interface_uuid):
        """Delete a PTP interface."""
        LOG.debug("PtpInterfaceController.delete: %s" % ptp_interface_uuid)
        if self._parent:
            raise exception.OperationNotPermitted

        try:
            ptp_interface_obj = objects.ptp_interface.get_by_uuid(
                pecan.request.context, ptp_interface_uuid)
        except exception.PtpInterfaceNotFound:
            raise

        # Only allow delete if there are no associated hosts/interfaces and
        # parameters
        parameters = pecan.request.dbapi.ptp_parameters_get_list(
            ptp_interface=ptp_interface_uuid)
        if parameters:
            raise wsme.exc.ClientSideError(
                "PTP interface %s is still associated with PTP parameter(s)"
                % ptp_interface_uuid)

        interfaces = pecan.request.dbapi.ptp_interface_get_assignees(
            ptp_interface_obj.id)
        if interfaces:
            raise wsme.exc.ClientSideError(
                "PTP interface %s is still associated with host interface(s)"
                % ptp_interface_uuid)

        LOG.debug("PtpInterfaceController.delete: all clear for %s" %
                  ptp_interface_uuid)
        pecan.request.dbapi.ptp_interface_destroy(ptp_interface_uuid)
