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
# Copyright (c) 2015-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import collections
import pecan
from pecan import rest
import uuid
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import address_pool
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


ALLOWED_NETWORK_TYPES = [constants.NETWORK_TYPE_MGMT,
                         constants.NETWORK_TYPE_PXEBOOT,
                         constants.NETWORK_TYPE_OAM,
                         constants.NETWORK_TYPE_MULTICAST,
                         constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
                         constants.NETWORK_TYPE_CLUSTER_HOST,
                         constants.NETWORK_TYPE_CLUSTER_POD,
                         constants.NETWORK_TYPE_CLUSTER_SERVICE,
                         constants.NETWORK_TYPE_IRONIC,
                         constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM,
                         constants.NETWORK_TYPE_STORAGE,
                         constants.NETWORK_TYPE_ADMIN]


class Network(base.APIBase):
    """API representation of an IP network.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of an IP
    network.
    """

    id = int
    "Unique ID for this network"

    uuid = types.uuid
    "Unique UUID for this network"

    type = wtypes.text
    "Represent the type for the network"

    name = wtypes.text
    "Unique name for this network"

    dynamic = bool
    "Enables or disables dynamic address allocation for network"

    pool_uuid = wtypes.text
    "The UUID of the address pool associated with the network"

    def __init__(self, **kwargs):
        self.fields = list(objects.network.fields.keys())
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    @classmethod
    def convert_with_links(cls, rpc_network, expand=True):
        network = Network(**rpc_network.as_dict())
        if not expand:
            network.unset_fields_except(['id', 'uuid', 'type', 'name',
                                         'dynamic', 'pool_uuid'])
        return network

    def _validate_network_type(self):
        if self.type not in ALLOWED_NETWORK_TYPES:
            raise ValueError(_("Network type %s not supported") %
                             self.type)

    def validate_syntax(self):
        """
        Validates the syntax of each field.
        """
        self._validate_network_type()


class NetworkCollection(collection.Collection):
    """API representation of a collection of IP networks."""

    networks = [Network]
    "A list containing IP Network objects"

    def __init__(self, **kwargs):
        self._type = 'networks'

    @classmethod
    def convert_with_links(cls, rpc_networks, limit, url=None,
                           expand=False, **kwargs):
        collection = NetworkCollection()
        collection.networks = [Network.convert_with_links(n, expand)
                               for n in rpc_networks]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'NetworkController'


class NetworkController(rest.RestController):
    """REST controller for Networks."""

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    def _get_network_collection(self, marker=None, limit=None, sort_key=None,
                                sort_dir=None, expand=False,
                                resource_url=None):
        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        marker_obj = None

        if marker:
            marker_obj = objects.network.get_by_uuid(
                pecan.request.context, marker)

        networks = pecan.request.dbapi.networks_get_all(
            limit, marker_obj, sort_key=sort_key, sort_dir=sort_dir)

        return NetworkCollection.convert_with_links(
            networks, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    def _get_one(self, network_uuid):
        rpc_network = objects.network.get_by_uuid(
            pecan.request.context, network_uuid)
        return Network.convert_with_links(rpc_network)

    def _check_network_type(self, networktype):
        networks = pecan.request.dbapi.networks_get_by_type(networktype)
        if networks:
            raise exception.NetworkAlreadyExists(type=networktype)
        if (networktype == constants.NETWORK_TYPE_ADMIN and
            utils.get_distributed_cloud_role() !=
                constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
            msg = _("Network of type {} restricted to distributed cloud "
                    "role of {}."
                    .format(networktype, constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD))
            raise wsme.exc.ClientSideError(msg)

    def _check_network_pool(self, pool):
        # ensure address pool exists and is not already inuse
        addresses = pecan.request.dbapi.addresses_get_by_pool(pool.id)
        if addresses:
            raise exception.NetworkAddressPoolInUse()

    def _create_network_addresses(self, pool, network):
        if network['type'] == constants.NETWORK_TYPE_MGMT:
            addresses = self._create_mgmt_network_address(pool)
        elif network['type'] == constants.NETWORK_TYPE_ADMIN:
            addresses = self._create_admin_network_address(pool)
        elif network['type'] == constants.NETWORK_TYPE_PXEBOOT:
            addresses = self._create_pxeboot_network_address()
        elif network['type'] == constants.NETWORK_TYPE_CLUSTER_HOST:
            addresses = self._create_cluster_host_network_address()
        elif network['type'] == constants.NETWORK_TYPE_OAM:
            addresses = self._create_oam_network_address(pool)
        elif network['type'] == constants.NETWORK_TYPE_MULTICAST:
            addresses = self._create_multicast_network_address()
        elif network['type'] == constants.NETWORK_TYPE_IRONIC:
            addresses = self._create_ironic_network_address()
        elif network['type'] == constants.NETWORK_TYPE_SYSTEM_CONTROLLER:
            addresses = self._create_system_controller_network_address(pool)
        elif network['type'] == constants.NETWORK_TYPE_STORAGE:
            addresses = self._create_storage_network_address()
        else:
            return
        self._populate_network_addresses(pool, network, addresses)

    def _create_mgmt_network_address(self, pool):
        addresses = collections.OrderedDict()
        addresses[constants.CONTROLLER_HOSTNAME] = None
        addresses[constants.CONTROLLER_0_HOSTNAME] = None
        addresses[constants.CONTROLLER_1_HOSTNAME] = None

        if pool.gateway_address is not None:
            if utils.get_distributed_cloud_role() == \
                    constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
                # In subcloud configurations, the management gateway is used
                # to communicate with the central cloud.
                addresses[constants.SYSTEM_CONTROLLER_GATEWAY_IP_NAME] =\
                    pool.gateway_address
            else:
                addresses[constants.CONTROLLER_GATEWAY] =\
                    pool.gateway_address
        return addresses

    def _create_admin_network_address(self, pool):
        addresses = {}
        if pool.floating_address:
            addresses.update(
                {constants.CONTROLLER_HOSTNAME: pool.floating_address})
        else:
            addresses.update({constants.CONTROLLER_HOSTNAME: None})

        if pool.controller0_address:
            addresses.update(
                {constants.CONTROLLER_0_HOSTNAME: pool.controller0_address})
        else:
            addresses.update({constants.CONTROLLER_0_HOSTNAME: None})

        if pool.controller1_address:
            addresses.update(
                {constants.CONTROLLER_1_HOSTNAME: pool.controller1_address})
        else:
            addresses.update({constants.CONTROLLER_1_HOSTNAME: None})

        if pool.gateway_address is not None:
            if utils.get_distributed_cloud_role() == \
                    constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
                # In subcloud configurations, the admin gateway is used
                # to communicate with the central cloud.
                addresses[constants.SYSTEM_CONTROLLER_GATEWAY_IP_NAME] =\
                    pool.gateway_address
            else:
                addresses[constants.CONTROLLER_GATEWAY] =\
                    pool.gateway_address
        return addresses

    def _create_pxeboot_network_address(self):
        addresses = collections.OrderedDict()
        addresses[constants.CONTROLLER_HOSTNAME] = None
        addresses[constants.CONTROLLER_0_HOSTNAME] = None
        addresses[constants.CONTROLLER_1_HOSTNAME] = None
        return addresses

    def _create_cluster_host_network_address(self):
        addresses = collections.OrderedDict()
        addresses[constants.CONTROLLER_HOSTNAME] = None
        addresses[constants.CONTROLLER_0_HOSTNAME] = None
        addresses[constants.CONTROLLER_1_HOSTNAME] = None
        return addresses

    def _create_oam_network_address(self, pool):
        addresses = {}
        if pool.floating_address:
            addresses.update(
                {constants.CONTROLLER_HOSTNAME: pool.floating_address})

        if utils.get_system_mode() != constants.SYSTEM_MODE_SIMPLEX:
            if pool.controller0_address:
                addresses.update(
                    {constants.CONTROLLER_0_HOSTNAME: pool.controller0_address})

            if pool.controller1_address:
                addresses.update(
                    {constants.CONTROLLER_1_HOSTNAME: pool.controller1_address})

        if pool.gateway_address:
            addresses.update(
                {constants.CONTROLLER_GATEWAY: pool.gateway_address})
        return addresses

    def _create_multicast_network_address(self):
        addresses = collections.OrderedDict()
        addresses[constants.SM_MULTICAST_MGMT_IP_NAME] = None
        addresses[constants.MTCE_MULTICAST_MGMT_IP_NAME] = None
        addresses[constants.PATCH_CONTROLLER_MULTICAST_MGMT_IP_NAME] = None
        addresses[constants.PATCH_AGENT_MULTICAST_MGMT_IP_NAME] = None
        return addresses

    def _create_system_controller_network_address(self, pool):
        addresses = {}
        return addresses

    def _create_ironic_network_address(self):
        addresses = collections.OrderedDict()
        addresses[constants.CONTROLLER_HOSTNAME] = None
        addresses[constants.CONTROLLER_0_HOSTNAME] = None
        addresses[constants.CONTROLLER_1_HOSTNAME] = None
        return addresses

    def _create_storage_network_address(self):
        addresses = collections.OrderedDict()
        addresses[constants.CONTROLLER_HOSTNAME] = None
        addresses[constants.CONTROLLER_0_HOSTNAME] = None
        addresses[constants.CONTROLLER_1_HOSTNAME] = None
        return addresses

    def _populate_network_addresses(self, pool, network, addresses):
        opt_fields = {}
        for name, address in addresses.items():
            address_name = cutils.format_address_name(name, network['type'])
            if not address:
                address = address_pool.AddressPoolController.allocate_address(
                    pool, order=address_pool.SEQUENTIAL_ALLOCATION)
            LOG.debug("address_name={} address={}".format(address_name, address))
            values = {
                'address_pool_id': pool.id,
                'address': str(address),
                'prefix': pool['prefix'],
                'family': pool['family'],
                'enable_dad': constants.IP_DAD_STATES[pool['family']],
                'name': address_name,
            }

            # Check for address existent before creation
            try:
                address_obj = pecan.request.dbapi.address_get_by_address(
                    str(address))
                pecan.request.dbapi.address_update(address_obj.uuid,
                                                   {'name': address_name})
            except exception.AddressNotFoundByAddress:
                address_obj = pecan.request.dbapi.address_create(values)

            # Update address pool with associated address
            if name == constants.CONTROLLER_0_HOSTNAME:
                opt_fields.update({
                    address_pool.ADDRPOOL_CONTROLLER0_ADDRESS_ID:
                        address_obj.id})
            elif name == constants.CONTROLLER_1_HOSTNAME:
                opt_fields.update({
                    address_pool.ADDRPOOL_CONTROLLER1_ADDRESS_ID:
                        address_obj.id})
            elif name == constants.CONTROLLER_HOSTNAME:
                opt_fields.update({
                    address_pool.ADDRPOOL_FLOATING_ADDRESS_ID: address_obj.id})
            elif name == constants.CONTROLLER_GATEWAY:
                opt_fields.update({
                    address_pool.ADDRPOOL_GATEWAY_ADDRESS_ID: address_obj.id})
        if opt_fields:
            pecan.request.dbapi.address_pool_update(pool.uuid, opt_fields)

    def _create_network(self, network):
        # Perform syntactic validation
        network.validate_syntax()
        network = network.as_dict()
        network['uuid'] = str(uuid.uuid4())

        # Perform semantic validation
        self._check_network_type(network['type'])

        pool_uuid = network.pop('pool_uuid', None)
        if pool_uuid:
            pool = pecan.request.dbapi.address_pool_get(pool_uuid)
            network.update({'address_pool_id': pool.id})

        # Attempt to create the new network record
        result = pecan.request.dbapi.network_create(network)

        self._create_network_addresses(pool, network)

        # If the host has already been created, make an RPC request
        # reconfigure the service endpoints. As oam network is processed
        # after management network, check only for NETWORK_TYPE_OAM to
        # avoid potentially making two reconfigure_service_endpoints
        # rpc requests in succession.
        chosts = pecan.request.dbapi.ihost_get_by_personality(
            constants.CONTROLLER)
        if (len(chosts) == 1 and
                network['type'] == constants.NETWORK_TYPE_OAM):
            pecan.request.rpcapi.reconfigure_service_endpoints(
                pecan.request.context, chosts[0])

        # After the initial configration completed, we can still delete/add
        # the system controller networks in a subcloud's controller to
        # re-home a subcloud to a new central cloud. In this case, we want
        # to update the related services configurations in runtime.
        if cutils.is_initial_config_complete() and \
            network['type'] in [constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
                                constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM]:
            self._update_system_controller_network_config(network['type'])
        return Network.convert_with_links(result)

    def _update_system_controller_network_config(self, type):
        """ Update related services configurations after updating system
            controller networks"""
        if type == constants.NETWORK_TYPE_SYSTEM_CONTROLLER:
            pecan.request.rpcapi.update_ldap_client_config(
                pecan.request.context)
        elif type == constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM:
            pecan.request.rpcapi.update_dnsmasq_config(
                pecan.request.context)

    @wsme_pecan.wsexpose(NetworkCollection,
                         types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of IP Networks."""
        return self._get_network_collection(marker, limit,
                                            sort_key=sort_key,
                                            sort_dir=sort_dir)

    @wsme_pecan.wsexpose(Network, types.uuid)
    def get_one(self, network_uuid):
        """Retrieve a single IP Network."""
        return self._get_one(network_uuid)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Network, body=Network)
    def post(self, network):
        """Create a new IP network."""
        return self._create_network(network)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, network_uuid):
        """Delete a network."""
        network = pecan.request.dbapi.network_get(network_uuid)
        if cutils.is_initial_config_complete() and \
            network['type'] in [constants.NETWORK_TYPE_MGMT,
                                constants.NETWORK_TYPE_OAM,
                                constants.NETWORK_TYPE_CLUSTER_HOST,
                                constants.NETWORK_TYPE_PXEBOOT,
                                constants.NETWORK_TYPE_CLUSTER_POD,
                                constants.NETWORK_TYPE_CLUSTER_SERVICE,
                                constants.NETWORK_TYPE_STORAGE,
                                constants.NETWORK_TYPE_ADMIN]:
            msg = _("Cannot delete type {} network {} after initial "
                    "configuration completion"
                    .format(network['type'], network_uuid))
            raise wsme.exc.ClientSideError(msg)
        pecan.request.dbapi.network_destroy(network_uuid)
