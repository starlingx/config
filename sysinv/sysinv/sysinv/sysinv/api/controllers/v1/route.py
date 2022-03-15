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
# Copyright (c) 2015-2022 Wind River Systems, Inc.
#

import netaddr
import pecan
from pecan import rest
import uuid
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import exception
from sysinv.common import constants
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)

# Maximum number of equal cost paths for a destination subnet
SYSINV_ROUTE_MAX_PATHS = 4

# Defines the list of interface network types that support routes
ALLOWED_NETWORK_TYPES = [constants.NETWORK_TYPE_DATA,
                         constants.NETWORK_TYPE_MGMT,
                         constants.NETWORK_TYPE_CLUSTER_HOST,
                         constants.NETWORK_TYPE_STORAGE,
                         constants.NETWORK_TYPE_OAM]


class Route(base.APIBase):
    """API representation of an IP route.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of an IP
    route.
    """

    id = int
    "Unique ID for this route"

    uuid = types.uuid
    "Unique UUID for this route"

    interface_uuid = types.uuid
    "Unique UUID of the parent interface"

    ifname = wtypes.text
    "User defined name of the interface"

    network = types.ipaddress
    "IP route network address"

    prefix = int
    "IP route prefix length"

    gateway = types.ipaddress
    "IP route nexthop gateway address"

    metric = int
    "IP route metric"

    forihostid = int
    "The ID of the host this interface belongs to"

    def __init__(self, **kwargs):
        self.fields = list(objects.route.fields.keys())
        for k in self.fields:
            if not hasattr(self, k):
                # Skip fields that we choose to hide
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    def _get_family(self):
        value = netaddr.IPAddress(self.network)
        return value.version

    def as_dict(self):
        """
        Sets additional DB only attributes when converting from an API object
        type to a dictionary that will be used to populate the DB.
        """
        data = super(Route, self).as_dict()
        data['family'] = self._get_family()
        return data

    @classmethod
    def convert_with_links(cls, rpc_route, expand=True):
        route = Route(**rpc_route.as_dict())
        if not expand:
            route.unset_fields_except(['uuid', 'network', 'prefix', 'gateway',
                                       'metric',
                                       'inteface_uuid', 'ifname',
                                       'forihostid'])
        return route

    def _validate_network_prefix(self):
        """
        Validates that the prefix is valid for the IP address family and that
        there are no host bits set.
        """
        try:
            cidr = netaddr.IPNetwork(self.network + "/" + str(self.prefix))
        except netaddr.core.AddrFormatError:
            raise ValueError(_("Invalid IP address and prefix"))
        address = netaddr.IPAddress(self.network)
        if address != cidr.network:
            raise ValueError(_("Invalid IP network %(address)s/%(prefix)s "
                               "expecting %(network)s/%(prefix)s") %
                             {'address': self.network,
                              'prefix': self.prefix,
                              'network': cidr.network})

    def _validate_zero_network(self):
        data = netaddr.IPNetwork(self.network + "/" + str(self.prefix))
        network = data.network
        if self.prefix != 0 and network.value == 0:
            raise ValueError(_("Network must not be null when prefix is non zero"))

    def _validate_metric(self):
        if self.metric < 0:
            raise ValueError(_("Route metric must be greater than zero"))

    @classmethod
    def address_in_subnet(self, gateway, address, prefix):
        subnet = netaddr.IPNetwork(address + "/" + str(prefix))
        ipaddr = netaddr.IPAddress(gateway)
        if subnet.network == (ipaddr & subnet.netmask):
            return True
        return False

    def _validate_gateway(self):
        gateway = netaddr.IPAddress(self.gateway)
        if gateway.value == 0:
            raise ValueError(_("Gateway address must not be null"))
        if self.prefix and Route.address_in_subnet(
                self.gateway, self.network, self.prefix):

            raise ValueError(_("Gateway address must not be within "
                               "destination subnet"))

    def _validate_addresses(self):
        network = netaddr.IPAddress(self.network)
        gateway = netaddr.IPAddress(self.gateway)
        if network == gateway:
            raise ValueError(_("Network and gateway IP addresses "
                               "must be different"))

    def _validate_families(self):
        network = netaddr.IPAddress(self.network)
        gateway = netaddr.IPAddress(self.gateway)
        if network.version != gateway.version:
            raise ValueError(_("Network and gateway IP versions must match"))

    def _validate_unicast_addresses(self):
        network = netaddr.IPAddress(self.network)
        gateway = netaddr.IPAddress(self.gateway)
        if not network.is_unicast():
            raise ValueError(_("Network address must be a unicast address"))
        if not gateway.is_unicast():
            raise ValueError(_("Gateway address must be a unicast address"))

    def validate_syntax(self):
        """
        Validates the syntax of each field.
        """
        self._validate_network_prefix()
        self._validate_zero_network()
        self._validate_families()
        self._validate_unicast_addresses()
        self._validate_addresses()
        self._validate_gateway()
        self._validate_metric()


class RouteCollection(collection.Collection):
    """API representation of a collection of IP routes."""

    routes = [Route]
    "A list containing IP Route objects"

    def __init__(self, **kwargs):
        self._type = 'routes'

    @classmethod
    def convert_with_links(cls, rpc_routes, limit, url=None,
                           expand=False, **kwargs):
        collection = RouteCollection()
        collection.routes = [Route.convert_with_links(a, expand)
                                for a in rpc_routes]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'RouteController'


class RouteController(rest.RestController):
    """REST controller for Routes."""

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    def _get_route_collection(self, parent_uuid=None,
                              marker=None, limit=None, sort_key=None,
                              sort_dir=None, expand=False,
                              resource_url=None):
        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        marker_obj = None

        if marker:
            marker_obj = objects.route.get_by_uuid(
                pecan.request.context, marker)

        if self._parent == "ihosts":
            routes = pecan.request.dbapi.routes_get_by_host(
                parent_uuid,
                limit, marker_obj, sort_key=sort_key, sort_dir=sort_dir)
        elif self._parent == "iinterfaces":
            routes = pecan.request.dbapi.routes_get_by_interface(
                parent_uuid,
                limit, marker_obj, sort_key=sort_key, sort_dir=sort_dir)
        else:
            routes = pecan.request.dbapi.routes_get_all(
                limit, marker_obj, sort_key=sort_key, sort_dir=sort_dir)

        return RouteCollection.convert_with_links(
            routes, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    def _query_route(self, host_id, route):
        try:
            result = pecan.request.dbapi.route_query(host_id, route)
        except exception.RouteNotFoundByName:
            return None
        return result

    def _get_parent_id(self, interface_uuid):
        interface = pecan.request.dbapi.iinterface_get(interface_uuid)
        return (interface['forihostid'], interface['id'])

    def _check_interface_type(self, interface_id):
        interface = pecan.request.dbapi.iinterface_get(interface_id)
        if (interface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM and
                interface['networktypelist'] is None):
            raise exception.InterfaceNetworkNotSet()
        for nt in interface['networktypelist']:
            if nt not in ALLOWED_NETWORK_TYPES:
                raise exception.RoutesNotSupportedOnInterfaces(type=nt)
        return

    def _check_duplicate_route(self, host_id, route):
        result = self._query_route(host_id, route)
        if not result:
            return
        raise exception.RouteAlreadyExists(network=route['network'],
                                           prefix=route['prefix'],
                                           gateway=route['gateway'])

    def _is_same_subnet(self, a, b):
        if a['prefix'] != b['prefix']:
            return False
        if a['metric'] != b['metric']:
            return False
        _a = netaddr.IPNetwork(a['network'] + "/" + str(a['prefix']))
        _b = netaddr.IPNetwork(b['network'] + "/" + str(b['prefix']))
        if _a.network == _b.network:
            return True
        return False

    def _check_duplicate_subnet(self, host_id, route):
        result = pecan.request.dbapi.routes_get_by_host(host_id)
        count = 0
        for entry in result:
            if self._is_same_subnet(entry, route):
                count += 1
        if count >= SYSINV_ROUTE_MAX_PATHS:
            raise exception.RouteMaxPathsForSubnet(
                count=SYSINV_ROUTE_MAX_PATHS,
                network=entry['network'],
                prefix=entry['prefix'])

    def _check_reachable_gateway(self, interface_id, route):
        result = pecan.request.dbapi.addresses_get_by_interface(interface_id)
        for address in result:
            if Route.address_in_subnet(route['gateway'],
                                       address['address'],
                                       address['prefix']):
                return
        result = pecan.request.dbapi.address_pools_get_by_interface(
            interface_id)
        for pool in result:
            if Route.address_in_subnet(route['gateway'],
                                       pool['network'],
                                       pool['prefix']):
                return
        raise exception.RouteGatewayNotReachable(gateway=route['gateway'])

    def _check_local_gateway(self, host_id, route):
        address = {'address': route['gateway']}
        try:
            result = pecan.request.dbapi.address_query(address)
            # It is OK to set up a route to a gateway. Gateways are not
            # local addresses.
            if 'gateway' not in result.name:
                raise exception.RouteGatewayCannotBeLocal(
                    gateway=route['gateway'])
        except exception.AddressNotFoundByAddress:
            pass
        return

    def _check_route_conflicts(self, host_id, route):
        self._check_duplicate_route(host_id, route)
        self._check_duplicate_subnet(host_id, route)

    @cutils.synchronized(LOCK_NAME)
    def _create_route_atomic(self, host_id, interface_id, route):
        self._check_route_conflicts(host_id, route)
        # Attempt to create the new route record
        result = pecan.request.dbapi.route_create(interface_id, route)
        pecan.request.rpcapi.update_route_config(pecan.request.context,
                                                 result.forihostid)
        return result

    def _create_route(self, route):
        route.validate_syntax()
        route = route.as_dict()
        route['uuid'] = str(uuid.uuid4())
        interface_uuid = route.pop('interface_uuid')
        # Query parent object references
        host_id, interface_id = self._get_parent_id(interface_uuid)
        # Check for semantic conflicts
        self._check_interface_type(interface_id)
        self._check_local_gateway(host_id, route)
        self._check_reachable_gateway(interface_id, route)

        result = self._create_route_atomic(host_id, interface_id, route)

        return Route.convert_with_links(result)

    def _get_one(self, route_uuid):
        rpc_route = objects.route.get_by_uuid(
            pecan.request.context, route_uuid)
        return Route.convert_with_links(rpc_route)

    @wsme_pecan.wsexpose(RouteCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, parent_uuid=None,
                marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of IP Routes."""
        return self._get_route_collection(parent_uuid, marker, limit,
                                          sort_key=sort_key, sort_dir=sort_dir)

    @wsme_pecan.wsexpose(Route, types.uuid)
    def get_one(self, route_uuid):
        return self._get_one(route_uuid)

    @wsme_pecan.wsexpose(Route, body=Route)
    def post(self, route):
        """Create a new IP route."""
        return self._create_route(route)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, route_uuid):
        """Delete an IP route."""
        try:
            route = objects.route.get_by_uuid(pecan.request.context, route_uuid)
        except exception.RouteNotFound:
            raise
        pecan.request.dbapi.route_destroy(route_uuid)
        pecan.request.rpcapi.update_route_config(pecan.request.context, route.forihostid)
