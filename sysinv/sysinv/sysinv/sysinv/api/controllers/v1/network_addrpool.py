# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_log import log
import wsme
from wsme import types as wtypes
import pecan
from pecan import rest
import uuid

import wsmeext.pecan as wsme_pecan
from sysinv.api.controllers.v1 import address_pool
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class NetworkAddresspool(base.APIBase):
    """API representation of an IP network.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of an IP
    network.
    """

    id = int
    "Unique ID for this network"

    uuid = types.uuid
    "Unique UUID for this network"

    address_pool_id = int
    "Unique ID of the associated network"

    address_pool_uuid = types.uuid
    "Unique UUID of the associated network"

    address_pool_name = wtypes.text
    "User defined name of the associated network"

    network_id = int
    "Unique ID of the associated network"

    network_uuid = types.uuid
    "Unique UUID of the associated network"

    network_name = wtypes.text
    "User defined name of the associated network"

    def __init__(self, **kwargs):
        self.fields = list(objects.network_addrpool.fields.keys())
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    @classmethod
    def convert_with_links(cls, rpc_network_addrpool, expand=True):
        network_addrpool = NetworkAddresspool(**rpc_network_addrpool.as_dict())
        if not expand:
            network_addrpool.unset_fields_except(['id', 'uuid',
                                                  'address_pool_id',
                                                  'address_pool_uuid',
                                                  'address_pool_name',
                                                  'network_id',
                                                  'network_uuid',
                                                  'network_name'])
        return network_addrpool

    def validate_syntax(self):
        """
        Validates the syntax of each field.
        """
        pass


class NetworkAddresspoolCollection(collection.Collection):
    """API representation of a collection of IP networks."""

    network_addresspools = [NetworkAddresspool]
    "A list containing Network Addresspool objects"

    def __init__(self, **kwargs):
        self._type = 'network_addresspools'

    @classmethod
    def convert_with_links(cls, rpc_network_addresspolls, limit, url=None,
                           expand=False, **kwargs):
        collection = NetworkAddresspoolCollection()
        collection.network_addresspools = [NetworkAddresspool.convert_with_links(n, expand)
                                           for n in rpc_network_addresspolls]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'NetworkController'


class NetworkAddresspoolController(rest.RestController):
    """REST controller for NetworkAddresspool."""

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    def _get_one(self, network_addrpool_uuid):
        rpc_network_addrpool = objects.network_addrpool.get_by_uuid(
            pecan.request.context, network_addrpool_uuid)
        return NetworkAddresspool.convert_with_links(rpc_network_addrpool)

    def _get_network_addrpool_collection(self, marker=None, limit=None, sort_key=None,
                                sort_dir=None, expand=False,
                                resource_url=None):
        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        marker_obj = None

        if marker:
            marker_obj = objects.network_addrpool.get_by_uuid(
                pecan.request.context, marker)

        networks = pecan.request.dbapi.network_addrpool_get_all(
            limit, marker_obj, sort_key=sort_key, sort_dir=sort_dir)

        return NetworkAddresspoolCollection.convert_with_links(
            networks, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    def _populate_network_addresses(self, pool, network, addresses, net_pool):

        if_net_list = pecan.request.dbapi.interface_network_get_by_network_id(net_pool.network_id)
        hostname_dict = dict()
        for if_net in if_net_list:
            host = pecan.request.dbapi.ihost_get(if_net.forihostid)
            hostname_dict.update({host.hostname: if_net})

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

            addr_intf = dict()
            for hostname in hostname_dict:
                if address_name == f"{hostname}-{net_pool.network_type}":
                    addr_intf.update({'interface_id':
                                    hostname_dict[hostname].interface_id})
                    break

            if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX \
                    and net_pool.network_type == constants.NETWORK_TYPE_OAM:
                if address_name == f"{constants.CONTROLLER}-{net_pool.network_type}":
                    addr_intf.update({'interface_id':
                                    hostname_dict[hostname].interface_id})

            # Check for address existent before creation
            try:
                address_obj = pecan.request.dbapi.address_get_by_address(
                    str(address))
                upd_values = {'name': address_name}
                upd_values.update(addr_intf)
                pecan.request.dbapi.address_update(address_obj.uuid, upd_values)
            except exception.AddressNotFoundByAddress:
                values.update(addr_intf)
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

        # update pool with addresses IDs
        if opt_fields:
            pecan.request.dbapi.address_pool_update(pool.uuid, opt_fields)

    def _create_network_addrpool(self, network_addrpool):
        # Perform syntactic validation
        network_addrpool.validate_syntax()
        network_addrpool = network_addrpool.as_dict()
        network_addrpool['uuid'] = str(uuid.uuid4())

        network = pecan.request.dbapi.network_get(network_addrpool['network_uuid'])
        pool = pecan.request.dbapi.address_pool_get(network_addrpool['address_pool_uuid'])
        pool_family = constants.IP_FAMILIES[pool.family]

        net_pool_list = pecan.request.dbapi.network_addrpool_get_by_network_id(network.id)
        if len(net_pool_list) == 2:
            # each network can have a max of 2 address-pools
            attached_pools = list()
            for netpool in net_pool_list:
                this_pool = pecan.request.dbapi.address_pool_get(netpool.address_pool_uuid)
                attached_pools.append(this_pool.name)
            msg = (f"Network of type {network.type} already have "
                   f"maximum of 2 pools attached: {attached_pools}")
            raise wsme.exc.ClientSideError(msg)
        elif len(net_pool_list) == 1:
            # each network can have only 1 address-pool per protocol
            this_pool = pecan.request.dbapi.address_pool_get(net_pool_list[0].address_pool_uuid)
            if this_pool.family == pool.family:
                msg = (f"Network of type {network.type} already have "
                       f"pool {this_pool.name} for family {pool_family}")
                raise wsme.exc.ClientSideError(msg)
        elif len(net_pool_list) == 0:
            # if the network have primary_pool_family set, check address family
            if not network.pool_uuid and network.primary_pool_family:
                if pool_family != network.primary_pool_family:
                    msg = (f"Network of type {network.type} requires "
                           f"primary pool of family {network.primary_pool_family}")
                    raise wsme.exc.ClientSideError(msg)

        if network.type == constants.NETWORK_TYPE_PXEBOOT \
                and pool.family != constants.IPV4_FAMILY:
            msg = (f"Network of type {network.type} only supports "
                    f"pool of family {network.primary_pool_family}")
            raise wsme.exc.ClientSideError(msg)

        net_pool_list = pecan.request.dbapi.network_addrpool_get_by_pool_id(pool.id)
        if len(net_pool_list):
            msg = ("Address pool already in use by another network")
            raise wsme.exc.ClientSideError(msg)

        result = pecan.request.dbapi.network_addrpool_create({'address_pool_id': pool.id,
                                                              'network_id': network.id})

        values = {}
        if not network.pool_uuid and not network.primary_pool_family:
            values = {'address_pool_id': pool.id, 'primary_pool_family': pool_family}
        elif not network.pool_uuid and network.primary_pool_family:
            values = {'address_pool_id': pool.id}

        if values:
            pecan.request.dbapi.network_update(network.uuid, values)

        # add the addresses
        addresses = utils.PopulateAddresses.create_network_addresses(pool, network)
        self._populate_network_addresses(pool, network, addresses, result)

        return NetworkAddresspool.convert_with_links(result)

    @wsme_pecan.wsexpose(NetworkAddresspool, types.uuid)
    def get_one(self, network_addrpool_uuid):
        """Retrieve a single Network-Addresspool object."""
        return self._get_one(network_addrpool_uuid)

    @wsme_pecan.wsexpose(NetworkAddresspoolCollection,
                         types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of Network-Addresspool objects."""
        return self._get_network_addrpool_collection(marker, limit,
                                            sort_key=sort_key,
                                            sort_dir=sort_dir)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(NetworkAddresspool, body=NetworkAddresspool)
    def post(self, network_addrpool):
        """Create a new Network-Addresspool object."""
        new_net_pool = self._create_network_addrpool(network_addrpool)
        return new_net_pool

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, network_addrpool_uuid):
        """Delete a Network-Addresspool object."""
        to_delete = pecan.request.dbapi.network_addrpool_get(network_addrpool_uuid)

        network = pecan.request.dbapi.network_get(to_delete['network_uuid'])
        pool = pecan.request.dbapi.address_pool_get(to_delete['address_pool_uuid'])

        if cutils.is_initial_config_complete():
            if (network['type'] in [constants.NETWORK_TYPE_OAM,
                                constants.NETWORK_TYPE_CLUSTER_HOST,
                                constants.NETWORK_TYPE_PXEBOOT,
                                constants.NETWORK_TYPE_CLUSTER_POD,
                                constants.NETWORK_TYPE_CLUSTER_SERVICE,
                                constants.NETWORK_TYPE_STORAGE]):
                msg = (f"Cannot delete relation for network {network.uuid}"
                       f" with type {network['type']} after initial configuration completion")
                raise wsme.exc.ClientSideError(msg)
            elif (network['type'] in [constants.NETWORK_TYPE_MGMT] and
                 utils.get_system_mode() != constants.SYSTEM_MODE_SIMPLEX):
                msg = (f"Cannot delete relation for network {network.uuid}"
                       f" with type {network['type']} after initial configuration completion")
                raise wsme.exc.ClientSideError(msg)

        if network.pool_uuid == pool.uuid:
            # this operation is blocked for now
            msg = (f"Cannot remove primary pool '{pool.name}' from '{network.name}'"
                   f" with type {network['type']}")
            raise wsme.exc.ClientSideError(msg)

        # since the association with the pool is removed, remove the interface id from the address
        pool_addresses = pecan.request.dbapi.addresses_get_by_pool(pool.id)
        for addr in pool_addresses:
            if addr.interface_id:
                pecan.request.dbapi.address_update(addr.uuid, {'interface_id': None})

        pecan.request.dbapi.network_addrpool_destroy(to_delete.uuid)
