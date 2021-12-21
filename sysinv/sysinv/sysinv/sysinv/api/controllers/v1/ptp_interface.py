########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

import pecan
from pecan import rest
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
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

    # Inherited from PtpParameterOwner

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

    links = [link.Link]
    "A list containing a self link and associated ptp interface links"

    ptp_instance_uuid = types.uuid
    "The UUID of the host this PTP interface belongs to"

    ptp_instance_name = wtypes.text
    "The name of the associated PTP instance"

    created_at = wtypes.datetime.datetime

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
            ptp_interface.unset_fields_except(['uuid',
                                               'type',
                                               'capabilities',
                                               'name',
                                               'ptp_instance_id',
                                               'ptp_instance_uuid',
                                               'ptp_instance_name',
                                               'created_at'])

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

    def __init__(self, from_ihosts=False):
        self._from_ihosts = from_ihosts

    @wsme_pecan.wsexpose(PtpInterfaceCollection, types.uuid, int, wtypes.text,
                         wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of PTP interfaces."""
        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        """ TODO
        marker_obj = None
        if marker:
            marker_obj = objects.ptp_interface.get_by_uuid(
                pecan.request.context, marker)

        if self._from_ihosts or host_uuid is not None:
            if interface_uuid is not None:
                ptp_interfaces = \
                    pecan.request.dbapi.ptp_interfaces_get_by_interface(
                        interface_uuid, limit, marker_obj, sort_key, sort_dir)
            else:
                ptp_interfaces = \
                    pecan.request.dbapi.ptp_interfaces_get_by_host(
                        host_uuid, limit, marker_obj, sort_key, sort_dir)
        else:
            ptp_interfaces = pecan.request.dbapi.ptp_interfaces_get_list()
        """
        ptp_interfaces = pecan.request.dbapi.ptp_interfaces_get_list()
        return PtpInterfaceCollection.convert_with_links(ptp_interfaces,
                                                         limit,
                                                         sort_key=sort_key,
                                                         sort_dir=sort_dir)

    @wsme_pecan.wsexpose(PtpInterface, types.uuid)
    def get_one(self, ptp_interface_uuid):
        """Retrieve information about the given PTP interface"""
        rpc_ptp_interface = objects.ptp_interface.get_by_uuid(
            pecan.request.context, ptp_interface_uuid)
        return PtpInterface.convert_with_links(rpc_ptp_interface)

    @wsme_pecan.wsexpose(PtpInterface, body=PtpInterface)
    def post(self, ptp_interface):
        """Create a new PTP interface"""
        return self._create_ptp_interface(ptp_interface)

    def _create_ptp_interface(self, ptp_interface):
        # Create a new PTP interface
        ptp_interface_dict = ptp_interface.as_dict()

        """
        TODO: enforce "name" as required field here
        """

        instance_uuid = ptp_interface_dict.pop('ptp_instance_uuid', None)
        instance = objects.ptp_instance.get_by_uuid(pecan.request.context,
                                                    instance_uuid)
        ptp_interface_dict['ptp_instance_id'] = instance['id']

        """ TODO
        check = \
            pecan.request.dbapi.ptp_interfaces_get_by_instance_and_interface(
                ptp_interface_dict["ptp_instance_id"],
                ptp_interface_dict["interface_id"])
        if len(check) != 0:
            raise exception.PtpInterfaceAlreadyExists()
        """

        result = pecan.request.dbapi.ptp_interface_create(ptp_interface_dict)
        return PtpInterface.convert_with_links(result)

    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, ptp_interface_uuid):
        """Delete a PTP interface."""
        try:
            ptp_interface = objects.ptp_interface.get_by_uuid(
                pecan.request.context, ptp_interface_uuid)
        except exception.PtpInterfaceNotFound:
            raise

        # Only allow delete if there are no associated parameters
        parameters = pecan.request.dbapi.ptp_parameters_get_by_owner_uuid(
            ptp_interface_uuid)
        if parameters:
            names = [str(p['name']) for p in parameters]
            raise wsme.exc.ClientSideError(
                "PTP interface %s has PTP parameter(s): %s"
                % (ptp_interface_uuid, names))

        LOG.debug("PtpInterfaceController.delete: all clear for %s" %
                  ptp_interface_uuid)
        pecan.request.dbapi.ptp_interface_destroy(ptp_interface.uuid)
