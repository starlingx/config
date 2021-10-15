########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

import pecan
from pecan import rest
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
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

    uuid = types.uuid
    "Unique UUID for this PTP interface"

    interface_uuid = types.uuid
    "ID for the interface associated with the PTP interface"

    ptp_instance_id = int
    "ID for the PTP instance this interface is associated with"

    links = [link.Link]
    "A list containing a self link and associated ptp interface links"

    ptp_instance_uuid = types.uuid
    "The UUID of the host this PTP interface belongs to"

    ifname = wtypes.text
    "The name of the underlying interface"

    forihostid = int
    "The foreign key host id"

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
                                                'ptp_instance_id',
                                                'forihostid',
                                                'ptp_instance_name',
                                                'ifname',
                                                'interface_uuid',
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

    def _get_ptp_interfaces_collection(self, host_uuid=None, marker=None,
                                       limit=None, sort_key=None,
                                       sort_dir=None, expand=False,
                                       resource_url=None, interface_uuid=None):

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        marker_obj = None

        if marker:
            marker_obj = objects.ptp_interface.get_by_uuid(pecan.request.context,
                                                            marker)
        if self._from_ihosts or host_uuid is not None:
            if interface_uuid is not None:
                ptp_interfaces = pecan.request.dbapi.ptp_interfaces_get_by_interface(
                                                                interface_uuid, limit,
                                                                marker_obj,
                                                                sort_key,
                                                                sort_dir)
            else:
                ptp_interfaces = pecan.request.dbapi.ptp_interfaces_get_by_host(
                                                                host_uuid, limit,
                                                                marker_obj,
                                                                sort_key,
                                                                sort_dir)
        else:
            ptp_interfaces = pecan.request.dbapi.ptp_interfaces_get_list()
        return PtpInterfaceCollection.convert_with_links(ptp_interfaces,
                                                            limit,
                                                            url=resource_url,
                                                            expand=expand,
                                                            sort_key=sort_key,
                                                            sort_dir=sort_dir)

    @wsme_pecan.wsexpose(PtpInterfaceCollection, types.uuid, types.uuid, int,
                            wtypes.text, wtypes.text, types.uuid)
    def get_all(self, host_uuid, marker=None, limit=None,
                sort_key='id', sort_dir='asc', interface_uuid=None):
        """Retrieve a list of PTP interfaces."""
        return self._get_ptp_interfaces_collection(host_uuid, marker, limit,
                                                   sort_key=sort_key,
                                                   sort_dir=sort_dir,
                                                   expand=False,
                                                   interface_uuid=interface_uuid)

    @wsme_pecan.wsexpose(PtpInterface, types.uuid)
    def get_one(self, ptp_interface_uuid):
        """Retrieve information about the given PTP interface"""
        rpc_ptp_interface = objects.ptp_interface.get_by_uuid(pecan.request.context,
                                                              ptp_interface_uuid)
        return PtpInterface.convert_with_links(rpc_ptp_interface)

    @wsme_pecan.wsexpose(PtpInterface, body=PtpInterface)
    def post(self, ptp_interface):
        """Create a new PTP interface"""
        return self._create_ptp_interface(ptp_interface)

    def _create_ptp_interface(self, ptp_interface):
        # Create a new PTP interface
        ptp_interface_dict = ptp_interface.as_dict()

        instance_uuid = ptp_interface_dict.pop('ptp_instance_uuid', None)
        instance = objects.ptp_instance.get_by_uuid(pecan.request.context,
                                                    instance_uuid)

        interface_uuid = ptp_interface_dict.pop('interface_uuid', None)
        interface = pecan.request.dbapi.iinterface_get(interface_uuid)

        ptp_interface_dict['interface_id'] = interface['id']
        ptp_interface_dict['ptp_instance_id'] = instance['id']

        check = pecan.request.dbapi.ptp_interfaces_get_by_instance_and_interface(
                                            ptp_interface_dict["ptp_instance_id"],
                                            ptp_interface_dict["interface_id"])
        if len(check) != 0:
            raise exception.PtpInterfaceAlreadyExists()

        result = pecan.request.dbapi.ptp_interface_create(ptp_interface_dict)
        return PtpInterface.convert_with_links(result)

    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, ptp_interface_uuid):
        """Delete a PTP interface."""
        try:
            ptp_interface = objects.ptp_interface.get_by_uuid(pecan.request.context,
                                                              ptp_interface_uuid)
        except exception.PtpInterfaceNotFound:
            raise
        pecan.request.dbapi.ptp_interface_destroy(ptp_interface.uuid)
