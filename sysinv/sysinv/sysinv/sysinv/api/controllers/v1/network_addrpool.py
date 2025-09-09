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
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import utils as cutils
from sysinv.common import address_pool as caddress_pool
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

    def _check_modification_allowed(self, operation, network, pool):
        if network.type in [constants.NETWORK_TYPE_OAM,
                            constants.NETWORK_TYPE_CLUSTER_HOST,
                            constants.NETWORK_TYPE_CLUSTER_POD,
                            constants.NETWORK_TYPE_CLUSTER_SERVICE,
                            constants.NETWORK_TYPE_STORAGE]:
            return
        if network.type == constants.NETWORK_TYPE_MGMT:
            if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
                chosts = pecan.request.dbapi.ihost_get_by_personality(constants.CONTROLLER)
                for host in chosts:
                    if utils.is_aio_simplex_host_unlocked(host):
                        msg = ("Cannot complete the action because Host {} "
                               "is in administrative state = unlocked"
                               .format(host['hostname']))
                        raise wsme.exc.ClientSideError(msg)
                return
            else:
                if network.pool_uuid != pool.uuid:
                    # it is possible to add the secondary pool for management during runtime
                    # A "config out-of-date" will be generated for the affected nodes.
                    return
        if network.type in [constants.NETWORK_TYPE_MULTICAST]:
            if network.pool_uuid != pool.uuid:
                # it is possible to add the secondary pool for multicast during runtime
                # A "config out-of-date" will be generated for the affected nodes.
                return
        if network.type not in [constants.NETWORK_TYPE_PXEBOOT,
                                constants.NETWORK_TYPE_MULTICAST]:
            return
        if cutils.is_initial_config_complete():
            oper_text = 'create' if operation == constants.API_POST else 'delete'
            msg = (f"Cannot {oper_text} relation for network {{{network.uuid}}} "
                   f"with type {network.type} after initial configuration completion")
            raise wsme.exc.ClientSideError(msg)

    def _check_address_pool_overlap(self, network, pool):
        caddress_pool.check_address_pools_overlaps(pecan.request.dbapi, [pool], {network.type})

    def _check_cluster_dual_stack_config(self, operation, network):

        cpod_pools = list()
        cpod = pecan.request.dbapi.networks_get_by_type(constants.NETWORK_TYPE_CLUSTER_POD)
        if cpod:
            cpod_pools = pecan.request.dbapi.address_pools_get_by_network(cpod[0].id)

        csvc_pools = list()
        csvc = pecan.request.dbapi.networks_get_by_type(constants.NETWORK_TYPE_CLUSTER_SERVICE)
        if csvc:
            csvc_pools = pecan.request.dbapi.address_pools_get_by_network(csvc[0].id)

        chost_pools = list()
        chost = pecan.request.dbapi.networks_get_by_type(constants.NETWORK_TYPE_CLUSTER_HOST)
        if chost:
            chost_pools = pecan.request.dbapi.address_pools_get_by_network(chost[0].id)

        if (operation == constants.API_POST) and (len(cpod_pools) > 1) \
                and (len(csvc_pools) > 1) and (len(chost_pools) > 1):
            return True

        elif (operation == constants.API_DELETE) and (len(cpod_pools) == 1) \
                and (len(chost_pools) == 1) and (len(csvc_pools) == 1):
            return True

        return False

    def _network_addresspool_operation_complete(self, operation, network, addrpool, hosts):
        if_net_list = pecan.request.dbapi.interface_network_get_by_network_id(network.id)
        if network.type == constants.NETWORK_TYPE_OAM and len(if_net_list) > 0:
            pecan.request.rpcapi.update_oam_config(pecan.request.context)

        elif network.type == constants.NETWORK_TYPE_MGMT:
            if cutils.is_initial_config_complete():
                if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
                    pecan.request.rpcapi.set_mgmt_network_reconfig_flag(pecan.request.context)
                    if utils.is_network_associated_to_interface(constants.NETWORK_TYPE_MGMT):
                        if operation == constants.API_POST:
                            caddress_pool.add_management_addresses_to_no_proxy_list([addrpool])
                        else:
                            caddress_pool.remove_management_addresses_from_no_proxy_list([addrpool])
                        cutils.update_routes_to_system_controller(pecan.request.dbapi)
                else:
                    # is the management secondary pool?
                    if network.pool_uuid != addrpool.uuid:
                        # if yes send the rpc request
                        disable = True if operation == constants.API_DELETE else False
                        pecan.request.rpcapi.update_mgmt_secondary_pool_config(
                            pecan.request.context, addrpool.family, disable)

        elif network.type == constants.NETWORK_TYPE_ADMIN:
            if hosts:
                cutils.update_routes_to_system_controller(pecan.request.dbapi, hosts)
                disable = operation == constants.API_DELETE and network.pool_uuid == addrpool.uuid
                for host in hosts:
                    pecan.request.rpcapi.update_admin_config(pecan.request.context, host,
                                                             disable=disable)

        elif network.type == constants.NETWORK_TYPE_STORAGE:
            if cutils.is_initial_config_complete():
                pecan.request.rpcapi.update_storage_net_config(pecan.request.context)

        elif network.type in [constants.NETWORK_TYPE_CLUSTER_HOST,
                            constants.NETWORK_TYPE_CLUSTER_POD,
                            constants.NETWORK_TYPE_CLUSTER_SERVICE] \
                and self._check_cluster_dual_stack_config(operation, network) \
                and cutils.is_initial_config_complete():
            disable = True if operation == constants.API_DELETE else False
            LOG.info(f"kubernetes dual_stack config( family{addrpool.family} disable={disable})")
            pecan.request.rpcapi.update_kubernetes_dual_stack_config(pecan.request.context,
                                                                     addrpool.family, disable)

    def _address_pools_get_by_network_type(self, network_type):
        network_pools = list()
        network = pecan.request.dbapi.networks_get_by_type(network_type)
        if network:
            network_pools = pecan.request.dbapi.address_pools_get_by_network(
                network[0].id
            )
        return network_pools

    def _update_interface_address_mode(self, network, pool):
        """ After a pool is assigned to a platform network, update the affected
            interface's address mode to static, in a similar way done by the
            interface-network API
        """
        if network.type in [constants.NETWORK_TYPE_MGMT,
                            constants.NETWORK_TYPE_OAM,
                            constants.NETWORK_TYPE_CLUSTER_HOST,
                            constants.NETWORK_TYPE_ADMIN]:
            addr_alloc_mode = constants.IPV4_STATIC
            if pool.family == constants.IPV6_FAMILY:
                addr_alloc_mode = constants.IPV6_STATIC
            if_net_list = pecan.request.dbapi.interface_network_get_by_network_id(network.id)
            for if_net_obj in if_net_list:
                utils.update_address_mode(if_net_obj.interface_id, pool.family,
                                          addr_alloc_mode, None)

    def _create_network_addrpool(self, network_addrpool):
        # Perform syntactic validation
        network_addrpool.validate_syntax()
        network_addrpool = network_addrpool.as_dict()
        network_addrpool['uuid'] = str(uuid.uuid4())

        network = pecan.request.dbapi.network_get(network_addrpool['network_uuid'])
        pool = pecan.request.dbapi.address_pool_get(network_addrpool['address_pool_uuid'])
        pool_family = constants.IP_FAMILIES[pool.family]

        self._check_modification_allowed(constants.API_POST, network, pool)
        self._check_address_pool_overlap(network, pool)

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

        # Make sure cluster-pod address-pool is not added before OAM
        # address-pool of same IP family.
        if network.type == constants.NETWORK_TYPE_CLUSTER_POD \
                and pool.family not in [
                oam_pool.family for oam_pool in
                self._address_pools_get_by_network_type(
                    constants.NETWORK_TYPE_OAM
                )]:
            msg = ("Cluster-pod address-pool can not be added before OAM "
                   "address-pool of same IP family")
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

        caddress_pool.populate_network_pool_addresses(pool, network.type, pecan.request.dbapi)
        caddress_pool.assign_pool_addresses_to_interfaces(pool, network, pecan.request.dbapi)
        self._update_interface_address_mode(network, pool)

        hosts = None
        if network.type == constants.NETWORK_TYPE_ADMIN:
            hosts = pecan.request.dbapi.ihosts_get_by_addrpool(pool.id)

        self._network_addresspool_operation_complete(constants.API_POST, network, pool, hosts)

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

        self._check_modification_allowed(constants.API_DELETE, network, pool)

        if network.pool_uuid == pool.uuid:
            # this operation is blocked for now
            msg = (f"Cannot remove primary pool '{pool.name}' from '{network.name}'"
                   f" with type {network['type']}")
            raise wsme.exc.ClientSideError(msg)

        # Make sure OAM pool is not deleted before deleting cluster-pod
        # address-pool of same IP family.
        if network.type == constants.NETWORK_TYPE_OAM and pool.family in [
            cluster_pod_pool.family for cluster_pod_pool in
            self._address_pools_get_by_network_type(
                constants.NETWORK_TYPE_CLUSTER_POD
            )
        ]:
            msg = ("oam address-pool can not be deleted before cluster-pod "
                   "address-pool of same IP family")
            raise wsme.exc.ClientSideError(msg)

        hosts = None
        if network.type == constants.NETWORK_TYPE_ADMIN:
            hosts = pecan.request.dbapi.ihosts_get_by_addrpool(pool.id)

        # since the association with the pool is removed, remove the interface id from the address
        pool_addresses = pecan.request.dbapi.addresses_get_by_pool(pool.id)
        for addr in pool_addresses:
            if addr.interface_id:
                pecan.request.dbapi.address_update(addr.uuid, {'interface_id': None})

        pecan.request.dbapi.network_addrpool_destroy(to_delete.uuid)

        self._network_addresspool_operation_complete(constants.API_DELETE, network, pool, hosts)
