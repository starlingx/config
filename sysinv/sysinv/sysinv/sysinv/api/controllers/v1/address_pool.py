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
# Copyright (c) 2015-2017 Wind River Systems, Inc.
#


import netaddr
import uuid

import pecan
from pecan import rest
import random

import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_utils._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common import log

LOG = log.getLogger(__name__)

# Defines the list of network address allocation schemes
SEQUENTIAL_ALLOCATION = 'sequential'
RANDOM_ALLOCATION = 'random'
VALID_ALLOCATION_ORDER = [SEQUENTIAL_ALLOCATION, RANDOM_ALLOCATION]

# Defines the default allocation order if not specified
DEFAULT_ALLOCATION_ORDER = RANDOM_ALLOCATION

# Address Pool optional field names
ADDRPOOL_CONTROLLER0_ADDRESS_ID = 'controller0_address_id'
ADDRPOOL_CONTROLLER1_ADDRESS_ID = 'controller1_address_id'
ADDRPOOL_FLOATING_ADDRESS_ID = 'floating_address_id'
ADDRPOOL_GATEWAY_ADDRESS_ID = 'gateway_address_id'


class AddressPoolPatchType(types.JsonPatchType):
    """A complex type that represents a single json-patch operation."""

    value = types.MultiType([wtypes.text, [list]])

    @staticmethod
    def mandatory_attrs():
        """These attributes cannot be removed."""
        result = (super(AddressPoolPatchType, AddressPoolPatchType).
                mandatory_attrs())
        result.append(['/name', '/network', '/prefix', '/order', '/ranges'])
        return result

    @staticmethod
    def readonly_attrs():
        """These attributes cannot be updated."""
        return ['/network', '/prefix']

    @staticmethod
    def validate(patch):
        result = (super(AddressPoolPatchType, AddressPoolPatchType).
                  validate(patch))
        if patch.op in ['add', 'remove']:
            msg = _("Attributes cannot be added or removed")
            raise wsme.exc.ClientSideError(msg % patch.path)
        if patch.path in patch.readonly_attrs():
            msg = _("'%s' is a read-only attribute and can not be updated")
            raise wsme.exc.ClientSideError(msg % patch.path)
        return result


class AddressPool(base.APIBase):
    """API representation of an IP address pool.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of an IP
    address pool.
    """

    id = int
    "Unique ID for this address"

    uuid = types.uuid
    "Unique UUID for this address"

    name = wtypes.text
    "User defined name of the address pool"

    network = types.ipaddress
    "Network IP address"

    prefix = int
    "Network IP prefix length"

    order = wtypes.text
    "Address allocation scheme order"

    controller0_address = types.ipaddress
    "Controller-0 IP address"

    controller0_address_id = int
    "Represent the ID of the controller-0 IP address."

    controller1_address = types.ipaddress
    "Controller-1 IP address"

    controller1_address_id = int
    "Represent the ID of the controller-1 IP address."

    floating_address = types.ipaddress
    "Represent the floating IP address."

    floating_address_id = int
    "Represent the ID of the floating IP address."

    gateway_address = types.ipaddress
    "Represent the ID of the gateway IP address."

    gateway_address_id = int
    "Represent the ID of the gateway IP address."

    ranges = types.MultiType([[list]])
    "List of start-end pairs of IP address"

    def __init__(self, **kwargs):
        self.fields = objects.address_pool.fields.keys()
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
        data = super(AddressPool, self).as_dict()
        data['family'] = self._get_family()
        return data

    @classmethod
    def convert_with_links(cls, rpc_addrpool, expand=True):
        pool = AddressPool(**rpc_addrpool.as_dict())
        if not expand:
            pool.unset_fields_except(['uuid', 'name',
                                      'network', 'prefix', 'order', 'ranges',
                                      'controller0_address',
                                      'controller0_address_id',
                                      'controller1_address',
                                      'controller1_address_id',
                                      'floating_address',
                                      'floating_address_id',
                                      'gateway_address',
                                      'gateway_address_id'
                                      ])
        return pool

    @classmethod
    def _validate_name(cls, name):
        if len(name) < 1:
            raise ValueError(_("Name must not be an empty string"))

    @classmethod
    def _validate_prefix(cls, prefix):
        if prefix < 1:
            raise ValueError(_("Address prefix must be greater than 1"))

    @classmethod
    def _validate_zero_network(cls, network, prefix):
        data = netaddr.IPNetwork(network + "/" + str(prefix))
        network = data.network
        if network.value == 0:
            raise ValueError(_("Network must not be null"))

    @classmethod
    def _validate_network(cls, network, prefix):
        """
        Validates that the prefix is valid for the IP address family.
        """
        try:
            value = netaddr.IPNetwork(network + "/" + str(prefix))
        except netaddr.core.AddrFormatError:
            raise ValueError(_("Invalid IP address and prefix"))
        mask = value.hostmask
        host = value.ip & mask
        if host.value != 0:
            raise ValueError(_("Host bits must be zero"))

    @classmethod
    def _validate_network_type(cls, network):
        address = netaddr.IPAddress(network)
        if not address.is_unicast() and not address.is_multicast():
            raise ValueError(_("Network address must be a unicast address or"
                               "a multicast address"))

    @classmethod
    def _validate_allocation_order(cls, order):
        if order and order not in VALID_ALLOCATION_ORDER:
            raise ValueError(_("Network address allocation order must be one "
                               "of: %s") % ', '.join(VALID_ALLOCATION_ORDER))

    def validate_syntax(self):
        """
        Validates the syntax of each field.
        """
        self._validate_name(self.name)
        self._validate_prefix(self.prefix)
        self._validate_zero_network(self.network, self.prefix)
        self._validate_network(self.network, self.prefix)
        self._validate_network_type(self.network)
        self._validate_allocation_order(self.order)


class AddressPoolCollection(collection.Collection):
    """API representation of a collection of IP addresses."""

    addrpools = [AddressPool]
    "A list containing IP Address Pool objects"

    def __init__(self, **kwargs):
        self._type = 'addrpools'

    @classmethod
    def convert_with_links(cls, rpc_addrpool, limit, url=None,
                           expand=False, **kwargs):
        collection = AddressPoolCollection()
        collection.addrpools = [AddressPool.convert_with_links(p, expand)
                                for p in rpc_addrpool]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'AddressPoolController'


class AddressPoolController(rest.RestController):
    """REST controller for Address Pools."""

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    def _get_address_pool_collection(self, parent_uuid,
                                     marker=None, limit=None, sort_key=None,
                                     sort_dir=None, expand=False,
                                     resource_url=None):
        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        marker_obj = None

        if marker:
            marker_obj = objects.address_pool.get_by_uuid(
                pecan.request.context, marker)

        addrpools = pecan.request.dbapi.address_pools_get_all(
                limit=limit, marker=marker_obj,
                sort_key=sort_key, sort_dir=sort_dir)

        return AddressPoolCollection.convert_with_links(
            addrpools, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    def _query_address_pool(self, addrpool):
        try:
            result = pecan.request.dbapi.address_pool_query(addrpool)
        except exception.AddressPoolNotFoundByName:
            return None
        return result

    def _check_name_conflict(self, addrpool):
        try:
            pool = pecan.request.dbapi.address_pool_get(addrpool['name'])
            raise exception.AddressPoolAlreadyExists(name=addrpool['name'])
        except exception.AddressPoolNotFound:
            pass

    def _check_valid_range(self, network, start, end, ipset):
        start_address = netaddr.IPAddress(start)
        end_address = netaddr.IPAddress(end)
        if (start_address.version != end_address.version or
              start_address.version != network.version):
            raise exception.AddressPoolRangeVersionMismatch()
        if start_address not in network:
            raise exception.AddressPoolRangeValueNotInNetwork(
                address=start, network=str(network))
        if end_address not in network:
            raise exception.AddressPoolRangeValueNotInNetwork(
                address=end, network=str(network))
        if start_address > end_address:
            raise exception.AddressPoolRangeTransposed()
        if start_address == network.network:
            raise exception.AddressPoolRangeCannotIncludeNetwork()
        if end_address == network.broadcast:
            raise exception.AddressPoolRangeCannotIncludeBroadcast()
        intersection = ipset & netaddr.IPSet(netaddr.IPRange(start, end))
        if intersection.size:
            raise exception.AddressPoolRangeContainsDuplicates(
                start=start, end=end)

    def _check_valid_ranges(self, addrpool):
        ipset = netaddr.IPSet()
        prefix = addrpool['prefix']
        network = netaddr.IPNetwork(addrpool['network'] + "/" + str(prefix))
        for start, end in addrpool['ranges']:
            self._check_valid_range(network, start, end, ipset)
            ipset.update(netaddr.IPRange(start, end))

    def _check_allocated_addresses(self, address_pool_id):
        addresses = pecan.request.dbapi.addresses_get_by_pool(
            address_pool_id)
        if addresses:
            raise exception.AddressPoolInUseByAddresses()

    def _check_pool_readonly(self, address_pool_id):
        networks = pecan.request.dbapi.networks_get_by_pool(address_pool_id)
        if networks:
            # network managed address pool, no changes permitted
            raise exception.AddressPoolReadonly()

    def _make_default_range(self, addrpool):
        ipset = netaddr.IPSet([addrpool['network'] + "/" + str(addrpool['prefix'])])
        if ipset.size < 4:
            raise exception.AddressPoolRangeTooSmall()
        return [(str(ipset.iprange()[1]), str(ipset.iprange()[-2]))]

    def _set_defaults(self, addrpool):
        addrpool['uuid'] = str(uuid.uuid4())
        if 'order' not in addrpool:
            addrpool['order'] = DEFAULT_ALLOCATION_ORDER
        if 'ranges' not in addrpool or not addrpool['ranges']:
            addrpool['ranges'] = self._make_default_range(addrpool)

    def _sort_ranges(self, addrpool):
        current = addrpool['ranges']
        addrpool['ranges'] = sorted(current, key=lambda x: netaddr.IPAddress(x[0]))

    @classmethod
    def _select_address(cls, available, order):
        """
        Chooses a new IP address from the set of available addresses according
        to the allocation order directive.
        """
        if order == SEQUENTIAL_ALLOCATION:
            return str(next(available.iter_ipranges())[0])
        elif order == RANDOM_ALLOCATION:
            index = random.randint(0, available.size - 1)
            for r in available.iter_ipranges():
                if index < r.size:
                    return str(r[index])
                index = index - r.size
        else:
            raise exception.AddressPoolInvalidAllocationOrder(order=order)

    @classmethod
    def allocate_address(cls, pool, dbapi=None, order=None):
        """
        Allocates the next available IP address from a pool.
        """
        if not dbapi:
            dbapi = pecan.request.dbapi
        # Build a set of defined ranges
        defined = netaddr.IPSet()
        for (start, end) in pool.ranges:
            defined.update(netaddr.IPRange(start, end))
        # Determine which addresses are already in use
        addresses = dbapi.addresses_get_by_pool(pool.id)
        inuse = netaddr.IPSet()
        for a in addresses:
            inuse.add(a.address)
        # Calculate which addresses are still available
        available = defined - inuse
        if available.size == 0:
            raise exception.AddressPoolExhausted(name=pool.name)
        if order is None:
            order = pool.order
        # Select an address according to the allocation scheme
        return cls._select_address(available, order)

    # @cutils.synchronized("address-pool-allocation", external=True)
    @classmethod
    def assign_address(cls, interface_id, pool_uuid, address_name=None,
                       dbapi=None):
        """
        Allocates the next available IP address from a pool and assigns it to
        an interface object.
        """
        if not dbapi:
            dbapi = pecan.request.dbapi
        pool = dbapi.address_pool_get(pool_uuid)
        ip_address = cls.allocate_address(pool, dbapi)
        address = {'address': ip_address,
                   'prefix': pool['prefix'],
                   'family': pool['family'],
                   'enable_dad': constants.IP_DAD_STATES[pool['family']],
                   'address_pool_id': pool['id'],
                   'interface_id': interface_id}
        if address_name:
            address['name'] = address_name
        return dbapi.address_create(address)

    def _validate_range_updates(self, addrpool, updates):
        addresses = pecan.request.dbapi.addresses_get_by_pool(addrpool.id)
        if not addresses:
            return
        current_ranges = netaddr.IPSet()
        for r in addrpool.ranges:
            current_ranges.add(netaddr.IPRange(*r))
        new_ranges = netaddr.IPSet()
        for r in updates['ranges']:
            new_ranges.add(netaddr.IPRange(*r))
        removed_ranges = current_ranges - new_ranges
        for a in addresses:
            if a['address'] in removed_ranges:
                raise exception.AddressPoolRangesExcludeExistingAddress()

    def _validate_updates(self, addrpool, updates):
        if 'name' in updates:
            AddressPool._validate_name(updates['name'])
        if 'order' in updates:
            AddressPool._validate_allocation_order(updates['order'])
        if 'ranges' in updates:
            self._validate_range_updates(addrpool, updates)
        return

    def _address_create(self, addrpool_dict, address):
        values = {
            'address': str(address),
            'prefix': addrpool_dict['prefix'],
            'family': addrpool_dict['family'],
            'enable_dad': constants.IP_DAD_STATES[addrpool_dict['family']],
        }
        # Check for address existent before creation
        try:
            address_obj = pecan.request.dbapi.address_get_by_address(address)
        except exception.NotFound:
            address_obj = pecan.request.dbapi.address_create(values)

        return address_obj

    def _create_address_pool(self, addrpool):
        addrpool.validate_syntax()
        addrpool_dict = addrpool.as_dict()
        self._set_defaults(addrpool_dict)
        self._sort_ranges(addrpool_dict)

        # Check for semantic conflicts
        self._check_name_conflict(addrpool_dict)
        self._check_valid_ranges(addrpool_dict)

        floating_address = addrpool_dict.pop('floating_address', None)
        controller0_address = addrpool_dict.pop('controller0_address', None)
        controller1_address = addrpool_dict.pop('controller1_address', None)
        gateway_address = addrpool_dict.pop('gateway_address', None)

        # Create addresses if specified
        if floating_address:
            f_addr = self._address_create(addrpool_dict, floating_address)
            addrpool_dict[ADDRPOOL_FLOATING_ADDRESS_ID] = f_addr.id

        if controller0_address:
            c0_addr = self._address_create(addrpool_dict, controller0_address)
            addrpool_dict[ADDRPOOL_CONTROLLER0_ADDRESS_ID] = c0_addr.id

        if controller1_address:
            c1_addr = self._address_create(addrpool_dict, controller1_address)
            addrpool_dict[ADDRPOOL_CONTROLLER1_ADDRESS_ID] = c1_addr.id

        if gateway_address:
            g_addr = self._address_create(addrpool_dict, gateway_address)
            addrpool_dict[ADDRPOOL_GATEWAY_ADDRESS_ID] = g_addr.id

        # Attempt to create the new address pool record
        new_pool = pecan.request.dbapi.address_pool_create(addrpool_dict)

        # Update the address_pool_id field in each of the addresses
        values = {'address_pool_id': new_pool.id}
        if new_pool.floating_address:
            pecan.request.dbapi.address_update(f_addr.uuid, values)

        if new_pool.controller0_address:
            pecan.request.dbapi.address_update(c0_addr.uuid, values)

        if new_pool.controller1_address:
            pecan.request.dbapi.address_update(c1_addr.uuid, values)

        if new_pool.gateway_address:
            pecan.request.dbapi.address_update(g_addr.uuid, values)

        return new_pool

    def _get_updates(self, patch):
        """Retrieve the updated attributes from the patch request."""
        updates = {}
        for p in patch:
            attribute = p['path'] if p['path'][0] != '/' else p['path'][1:]
            updates[attribute] = p['value']
        return updates

    def _get_one(self, address_pool_uuid):
        rpc_addrpool = objects.address_pool.get_by_uuid(
            pecan.request.context, address_pool_uuid)
        return AddressPool.convert_with_links(rpc_addrpool)

    @wsme_pecan.wsexpose(AddressPoolCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, parent_uuid=None,
                marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of IP Address Pools."""
        return self._get_address_pool_collection(parent_uuid, marker, limit,
                                                 sort_key, sort_dir)

    @wsme_pecan.wsexpose(AddressPool, types.uuid)
    def get_one(self, address_pool_uuid):
        return self._get_one(address_pool_uuid)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(AddressPool, body=AddressPool)
    def post(self, addrpool):
        """Create a new IP address pool."""
        return self._create_address_pool(addrpool)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [AddressPoolPatchType])
    @wsme_pecan.wsexpose(AddressPool, types.uuid, body=[AddressPoolPatchType])
    def patch(self, address_pool_uuid, patch):
        """Updates attributes of an IP address pool."""
        addrpool = self._get_one(address_pool_uuid)
        updates = self._get_updates(patch)
        self._check_pool_readonly(addrpool.id)
        self._validate_updates(addrpool, updates)
        return pecan.request.dbapi.address_pool_update(
            address_pool_uuid, updates)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, address_pool_uuid):
        """Delete an IP address pool."""
        addrpool = self._get_one(address_pool_uuid)
        self._check_pool_readonly(addrpool.id)
        self._check_allocated_addresses(addrpool.id)
        pecan.request.dbapi.address_pool_destroy(address_pool_uuid)
