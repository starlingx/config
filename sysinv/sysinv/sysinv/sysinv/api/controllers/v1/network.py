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
# Copyright (c) 2015-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import pecan
from pecan import rest
import uuid
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.common import address_pool as caddress_pool
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

    primary_pool_family = wtypes.text
    "The primary pool address family (IPv4 or IPv6)"

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
                                         'dynamic', 'pool_uuid',
                                         'primary_pool_family'])
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

    def _check_address_pool_overlap(self, pool, networktype):
        caddress_pool.check_address_pools_overlaps(pecan.request.dbapi, [pool], {networktype})

    def _check_network_pool(self, pool):
        # ensure address pool exists and is not already inuse
        addresses = pecan.request.dbapi.addresses_get_by_pool(pool.id)
        if addresses:
            raise exception.NetworkAddressPoolInUse()

    def _get_addrpool(self, network):
        pool_uuid = network.pop('pool_uuid', None)
        if not pool_uuid:
            msg = _("Address pool UUID has to be specified")
            raise wsme.exc.ClientSideError(msg)
        return pecan.request.dbapi.address_pool_get(pool_uuid)

    def _create_network(self, network):
        # Perform syntactic validation
        network.validate_syntax()
        network = network.as_dict()
        network['uuid'] = str(uuid.uuid4())
        networktype = network['type']

        pool = self._get_addrpool(network)

        # Perform semantic validation
        self._check_network_type(networktype)
        self._check_address_pool_overlap(pool, networktype)

        if pool:
            network.update({'address_pool_id': pool.id})
            network.update({'primary_pool_family': constants.IP_FAMILIES[pool.family]})

        # Attempt to create the new network record
        result = pecan.request.dbapi.network_create(network)

        if pool:
            # create here the network-addrpool object
            net_pool = pecan.request.dbapi.network_addrpool_create({"address_pool_id": pool.id,
                                                                    "network_id": result.id})
            LOG.info(f"added network-addrpool {net_pool.uuid}")

            caddress_pool.populate_network_pool_addresses(pool, networktype, pecan.request.dbapi)

        # If the host has already been created, make an RPC request
        # reconfigure the service endpoints. As oam network is processed
        # after management network, check only for NETWORK_TYPE_OAM to
        # avoid potentially making two reconfigure_service_endpoints
        # rpc requests in succession.
        chosts = pecan.request.dbapi.ihost_get_by_personality(
            constants.CONTROLLER)
        if (len(chosts) == 1 and
                networktype == constants.NETWORK_TYPE_OAM):
            pecan.request.rpcapi.reconfigure_service_endpoints(
                pecan.request.context, chosts[0])

        # After the initial configration completed, we can still delete/add
        # the system controller networks in a subcloud's controller to
        # re-home a subcloud to a new central cloud. In this case, we want
        # to update the related services configurations in runtime.
        if cutils.is_initial_config_complete() and \
            networktype in [constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
                                constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM]:
            self._update_system_controller_network_config(networktype)

        return Network.convert_with_links(result)

    def _update_system_controller_network_config(self, type):
        """ Update related services configurations after updating system
            controller networks"""
        if type == constants.NETWORK_TYPE_SYSTEM_CONTROLLER:
            pecan.request.rpcapi.update_ldap_client_config(
                pecan.request.context)
            pecan.request.rpcapi.update_ldap_nat_config(
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
        if cutils.is_initial_config_complete():
            if (network['type'] in [constants.NETWORK_TYPE_OAM,
                                constants.NETWORK_TYPE_CLUSTER_HOST,
                                constants.NETWORK_TYPE_PXEBOOT,
                                constants.NETWORK_TYPE_CLUSTER_POD,
                                constants.NETWORK_TYPE_CLUSTER_SERVICE,
                                constants.NETWORK_TYPE_STORAGE] or
                (network['type'] in [constants.NETWORK_TYPE_MGMT] and
                 utils.get_system_mode() != constants.SYSTEM_MODE_SIMPLEX)):
                    msg = _("Cannot delete type {} network {} after initial "
                        "configuration completion"
                        .format(network['type'], network_uuid))
                    raise wsme.exc.ClientSideError(msg)

            elif (network['type'] in [constants.NETWORK_TYPE_MGMT] and
                  utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX):

                # For AIO-SX the mgmt network can be be reconfigured if host is locked
                chosts = pecan.request.dbapi.ihost_get_by_personality(
                    constants.CONTROLLER)
                for host in chosts:
                    if utils.is_aio_simplex_host_unlocked(host):
                        msg = _("Cannot delete type {} network {} because Host {} "
                                "is in administrative state = unlocked"
                                .format(network['type'], network_uuid, host['hostname']))
                        raise wsme.exc.ClientSideError(msg)

        # InterfaceNetwork objects are automatically removed from the database when the network is
        # destroyed. However, addresses have to be explicitly unassigned from the interfaces.
        addrpools = pecan.request.dbapi.address_pools_get_by_network(network.id)
        for addrpool in addrpools:
            addresses = pecan.request.dbapi.addresses_get_by_pool(addrpool.id)
            for address in addresses:
                if address.interface_id:
                    pecan.request.dbapi.address_update(address.id, {'interface_id': None})

        pecan.request.dbapi.network_destroy(network_uuid)

        if network.type == constants.NETWORK_TYPE_ADMIN:
            hosts = pecan.request.dbapi.ihost_get_by_personality(constants.CONTROLLER)
            if hosts:
                if (utils.get_distributed_cloud_role() ==
                        constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD):
                    cutils.update_subcloud_routes(pecan.request.dbapi, hosts)
                for host in hosts:
                    pecan.request.rpcapi.update_admin_config(pecan.request.context, host, True)
