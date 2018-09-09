# vim: tabstop=4 shiftwidth=4 softtabstop=4

#
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
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#

import uuid
import wsme
import pecan
from pecan import rest
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import utils as cutils
from sysinv.common import constants
from sysinv.common import exception
from sysinv import objects
from oslo_log import log


LOG = log.getLogger(__name__)


# Cannot assign any of the following network types
NONASSIGNABLE_NETWORK_TYPES = (constants.NETWORK_TYPE_DATA,
                               constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                               constants.NETWORK_TYPE_PCI_SRIOV)

# Once assigned, cannot remove any of the following network types
NONDUPLICATE_NETWORK_TYPES = (constants.NETWORK_TYPE_MGMT,
                              constants.NETWORK_TYPE_OAM,
                              constants.NETWORK_TYPE_INFRA)


class InterfaceNetwork(base.APIBase):

    id = int
    "Unique ID for this interface network"

    uuid = types.uuid
    "Unique UUID for this interface network"

    forihostid = int
    "The ID of the host the interface belongs to"

    interface_uuid = types.uuid
    "Unique UUID of the parent interface"

    ifname = wtypes.text
    "User defined name of the interface"

    network_id = int
    "Unique ID of the parent network"

    network_uuid = types.uuid
    "Unique UUID of the parent network"

    network_name = wtypes.text
    "User defined name of the network"

    network_type = wtypes.text
    "Represents the type for the network"

    def __init__(self, **kwargs):
        self.fields = objects.interface_network.fields.keys()
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    @classmethod
    def convert_with_links(cls, rpc_interface_network, expand=True):
        interface_network = InterfaceNetwork(**rpc_interface_network.as_dict())
        if not expand:
            interface_network.unset_fields_except([
                'forihostid', 'id', 'uuid', 'interface_uuid', 'ifname',
                'network_id', 'network_uuid', 'network_name', 'network_type'
            ])
        return interface_network


class InterfaceNetworkCollection(collection.Collection):
    """API representation of a collection of IP addresses."""

    interface_networks = [InterfaceNetwork]
    "A list containing IP Interface Network objects"

    def __init__(self, **kwargs):
        self._type = 'interface_networks'

    @classmethod
    def convert_with_links(cls, rpc_interface_network, limit, url=None,
                           expand=False, **kwargs):
        collection = InterfaceNetworkCollection()
        collection.interface_networks = [InterfaceNetwork.convert_with_links(p, expand)
                                         for p in rpc_interface_network]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'InterfaceNetworkController'


class InterfaceNetworkController(rest.RestController):

    def __init__(self, parent=None):
        self._parent = parent

    def _create_interface_network(self, interface_network):
        interface_network_dict = interface_network.as_dict()
        interface_network_dict['uuid'] = str(uuid.uuid4())

        # Remove UUIDs from dict to be replaced with IDs
        interface_uuid = interface_network_dict.pop('interface_uuid')
        network_uuid = interface_network_dict.pop('network_uuid')

        interface_id = self._get_interface_id(interface_uuid)
        network_id, network_type = self._get_network_id_and_type(network_uuid)

        interface_network_dict['interface_id'] = interface_id
        interface_network_dict['network_id'] = network_id

        self._check_interface_class(interface_uuid)
        self._check_assigned_network_type(network_type)
        self._check_duplicate_interface_network(interface_network_dict)
        self._check_duplicate_type(interface_id, network_type)
        self._check_pxeboot_network(interface_id, network_type)
        self._check_oam_network(interface_id, network_type)

        result = pecan.request.dbapi.interface_network_create(interface_network_dict)

        interface = pecan.request.dbapi.iinterface_get(interface_uuid)
        if not interface.networktype:
            values = {'networktype': network_type}
            pecan.request.dbapi.iinterface_update(interface_uuid, values)

        return InterfaceNetwork.convert_with_links(result)

    def _get_interface_network_collection(
            self, parent_uuid=None, marker=None, limit=None, sort_key=None,
            sort_dir=None, expand=False, resource_url=None):
        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        marker_obj = None

        if marker:
            marker_obj = objects.interface_network.get_by_uuid(
                pecan.request.context, marker)

        if self._parent == "ihosts":
            interface_networks = pecan.request.dbapi.interface_network_get_by_host(
                parent_uuid, limit=limit, marker=marker_obj,
                sort_key=sort_key, sort_dir=sort_dir)
        elif self._parent == "iinterfaces":
            interface_networks = pecan.request.dbapi.interface_network_get_by_interface(
                parent_uuid, limit=limit, marker=marker_obj,
                sort_key=sort_key, sort_dir=sort_dir)
        else:
            interface_networks = pecan.request.dbapi.interface_network_get_all(
                limit=limit, marker=marker_obj,
                sort_key=sort_key, sort_dir=sort_dir)

        return InterfaceNetworkCollection.convert_with_links(
            interface_networks, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    def _get_one(self, interface_network_uuid):
        rpc_interface_network = objects.interface_network.get_by_uuid(
            pecan.request.context, interface_network_uuid)
        return InterfaceNetwork.convert_with_links(rpc_interface_network)

    def _check_interface_class(self, interface_uuid):
        interface = pecan.request.dbapi.iinterface_get(interface_uuid)
        if not interface.ifclass or interface.ifclass == constants.INTERFACE_CLASS_NONE:
            values = {'ifclass': constants.INTERFACE_CLASS_PLATFORM}
            pecan.request.dbapi.iinterface_update(interface_uuid, values)
            return
        elif interface.ifclass == constants.INTERFACE_CLASS_PLATFORM:
            return
        else:
            msg = _("An interface with interface class '%s' "
                    "cannot assign platform networks." % interface.ifclass)
            raise wsme.exc.ClientSideError(msg)

    def _query_interface_network(self, interface_network):
        try:
            result = pecan.request.dbapi.interface_network_query(interface_network)
        except exception.InterfaceNetworkNotFoundByHostInterfaceNetwork:
            return None
        return result

    def _check_duplicate_interface_network(self, interface_network):
        result = self._query_interface_network(interface_network)
        if not result:
            return
        raise exception.InterfaceNetworkAlreadyExists(
            interface_id=interface_network['interface_id'],
            network_id=interface_network['network_id'])

    def _check_duplicate_type(self, interface_id, network_type):
        if network_type in NONDUPLICATE_NETWORK_TYPES:
            interface_networks = pecan.request.dbapi.interface_network_get_all()
            for i in interface_networks:
                if i.interface_id == interface_id and i.network_type == network_type:
                    msg = _("An interface with network type '%s' is "
                            "already provisioned on this node." % network_type)
                    raise wsme.exc.ClientSideError(msg)
            else:
                return

    def _check_assigned_network_type(self, network_type):
        if network_type not in NONASSIGNABLE_NETWORK_TYPES:
            return
        raise exception.UnsupportedAssignedInterfaceNetworkType(network_type=network_type)

    def _check_pxeboot_network(self, interface_id, network_type):
        interface_networks = pecan.request.dbapi.interface_network_get_all()
        for i in interface_networks:
            # if attempting to assign a pxeboot network to an interface which
            # already has a different network assigned
            if i.interface_id == interface_id and \
                    network_type == constants.NETWORK_TYPE_PXEBOOT:
                msg = _("You cannot assign a network of type '%s' to an interface "
                        "which is already assigned with a different network."
                        % network_type)
                raise wsme.exc.ClientSideError(msg)
            # if attempting to assign a different network to an interface
            # already assigned with a pxeboot network
            elif i.interface_id == interface_id and \
                    i.network_type == constants.NETWORK_TYPE_PXEBOOT:
                msg = _("An interface assigned with a network of type '%s' "
                        "cannot contain additional networks."
                        % i.network_type)
                raise wsme.exc.ClientSideError(msg)

    def _check_oam_network(self, interface_id, network_type):
        NONASSIGNABLE_WITH_OAM = [constants.NETWORK_TYPE_MGMT,
                                  constants.NETWORK_TYPE_PXEBOOT,
                                  constants.NETWORK_TYPE_INFRA]
        interface_networks = pecan.request.dbapi.interface_network_get_all()
        for i in interface_networks:
            if i.interface_id == interface_id and \
                network_type == constants.NETWORK_TYPE_OAM and \
                    i.network_type in NONASSIGNABLE_WITH_OAM:
                msg = _("You cannot assign a network of type '%s' to an interface "
                        "which is already assigned with a network of type '%s'."
                        % (network_type, i.network_type))
                raise wsme.exc.ClientSideError(msg)
            elif i.interface_id == interface_id and \
                i.network_type == constants.NETWORK_TYPE_OAM and \
                    network_type in NONASSIGNABLE_WITH_OAM:
                msg = _("An interface assigned with a network of type '%s' "
                        "cannot assign a network of type '%s'."
                        % (i.network_type, network_type))
                raise wsme.exc.ClientSideError(msg)

    def _get_interface_id(self, interface_uuid):
        interface = pecan.request.dbapi.iinterface_get(interface_uuid)
        return interface['id']

    def _get_network_id_and_type(self, network_uuid):
        network = pecan.request.dbapi.network_get(network_uuid)
        return network['id'], network['type']

    @wsme_pecan.wsexpose(InterfaceNetwork, types.uuid)
    def get_one(self, interface_network_uuid):
        return self._get_one(interface_network_uuid)

    @wsme_pecan.wsexpose(InterfaceNetworkCollection,
                         wtypes.text, types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, parent_uuid=None, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        return self._get_interface_network_collection(
            parent_uuid, marker, limit, sort_key, sort_dir)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(InterfaceNetwork, body=InterfaceNetwork)
    def post(self, interface_network):
        return self._create_interface_network(interface_network)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, interface_network_uuid):
        interface_network = self._get_one(interface_network_uuid)
        pecan.request.dbapi.interface_network_destroy(interface_network_uuid)
        interface_networks = pecan.request.dbapi.interface_network_get_by_interface(
            interface_network.interface_uuid)
        if not interface_networks:
            values = {'ifclass': None}
            pecan.request.dbapi.iinterface_update(interface_network.interface_uuid, values)
