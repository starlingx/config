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


import netaddr
import pecan
from pecan import rest
import random
import uuid
import wsme
import copy
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

ADDRESS_FIELDS = {'gateway_address': 'gateway_address_id',
                  'floating_address': 'floating_address_id',
                  'controller0_address': 'controller0_address_id',
                  'controller1_address': 'controller1_address_id'}

CONTROLLER_ADDRESS_FIELDS = {
    constants.CONTROLLER_GATEWAY: ('gateway_address', 'gateway_address_id'),
    constants.CONTROLLER_HOSTNAME: ('floating_address', 'floating_address_id'),
    constants.CONTROLLER_0_HOSTNAME: ('controller0_address', 'controller0_address_id'),
    constants.CONTROLLER_1_HOSTNAME: ('controller1_address', 'controller1_address_id')}

# Address pools for the admin and system controller networks in the subcloud
# are allowed to be deleted/modified post install.
SUBCLOUD_WRITABLE_NETWORK_TYPES = [constants.NETWORK_TYPE_ADMIN,
                                   constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
                                   constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM]

# Address pool for the management network in an AIO-SX installation
# is allowed to be deleted/modified post install
AIOSX_WRITABLE_NETWORK_TYPES = [constants.NETWORK_TYPE_MGMT]


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
        return ['/id', '/uuid', '/controller0_address_id', '/controller1_address_id',
                '/floating_address_id', '/gateway_address_id']

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

    family = int
    "Network address family"

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
        self.fields = list(objects.address_pool.fields.keys())
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
                                      'network', 'prefix', 'family', 'order', 'ranges',
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
            pecan.request.dbapi.address_pool_get(addrpool['name'])
            raise exception.AddressPoolAlreadyExists(name=addrpool['name'])
        except exception.AddressPoolNotFound:
            pass

    def _check_pool_overlap(self, addrpool, network_types):
        caddress_pool.check_address_pools_overlaps(pecan.request.dbapi, [addrpool],
                                                   network_types, False)

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

    def _get_addrpool_subnet(self, addrpool):
        return netaddr.IPNetwork(addrpool['network'] + "/" + str(addrpool['prefix']))

    def _check_valid_subnet(self, subnet, family=None):
        utils.is_valid_subnet(subnet, family)

    def _check_valid_ranges(self, addrpool, subnet):
        ipset = netaddr.IPSet()
        for start, end in addrpool['ranges']:
            self._check_valid_range(subnet, start, end, ipset)
            ipset.update(netaddr.IPRange(start, end))

    def _check_valid_address(self, subnet, address):
        addr = netaddr.IPAddress(address)
        utils.is_valid_address_within_subnet(addr, subnet)

    def _validate_name(self, addrpool):
        AddressPool._validate_name(addrpool['name'])
        self._check_name_conflict(addrpool)

    def _check_modification_allowed(self, network_types):
        # No restrictions during initial config
        if not cutils.is_initial_config_complete():
            return

        for nw_type in network_types:
            # OAM address pools are writable, except during upgrades.
            if nw_type == constants.NETWORK_TYPE_OAM:
                utils.check_disallow_during_upgrades()
                continue

            # The admin and system controller address pools which exist on the
            # subcloud are expected for re-home a subcloud to new system controllers.
            if nw_type in SUBCLOUD_WRITABLE_NETWORK_TYPES:
                continue

            # The management address pool can be changed for AIO-SX, if the host is locked.
            if nw_type in AIOSX_WRITABLE_NETWORK_TYPES:
                if self._get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
                    chosts = pecan.request.dbapi.ihost_get_by_personality(constants.CONTROLLER)
                    for host in chosts:
                        if utils.is_aio_simplex_host_unlocked(host):
                            msg = _("Cannot complete the action because Host {} "
                                    "is in administrative state = unlocked"
                                    .format(host['hostname']))
                            raise wsme.exc.ClientSideError(msg)
                    continue

            # An addresspool except the admin and system controller's pools
            # are considered read-only after the initial configuration is
            # complete. During bootstrap it should be modifiable even though
            # it is allocated to a network.
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
        values = {'address': ip_address,
                  'prefix': pool['prefix'],
                  'family': pool['family'],
                  'enable_dad': constants.IP_DAD_STATES[pool['family']],
                  'address_pool_id': pool['id'],
                  'interface_id': interface_id}
        if address_name:
            values['name'] = address_name
        try:
            existing_address = dbapi.address_get_by_address(ip_address)
            if existing_address.pool_id != pool.id:
                # If the address already exists, it could belong to an unassigned address pool
                # and has to be removed from it
                remove_address_from_pool(existing_address, dbapi)
            address_obj = dbapi.address_update(existing_address.id, values)
        except exception.AddressNotFoundByAddress:
            address_obj = dbapi.address_create(values)
        return address_obj

    def _validate_range_updates(self, addrpool, updates):
        addresses = pecan.request.dbapi.addresses_get_by_pool(addrpool.id)
        if not addresses:
            return

        address_index = {}
        for address in addresses:
            address_index[address.id] = address

        for field, id_field in ADDRESS_FIELDS.items():
            address_id = getattr(addrpool, id_field)
            if address_id:
                address_index.pop(address_id, None)

        if not address_index:
            return

        new_ranges = netaddr.IPSet()
        for r in updates['ranges']:
            new_ranges.add(netaddr.IPRange(*r))

        lines = []
        for address in address_index.values():
            if address.address in new_ranges:
                continue
            line = f"{address.address}/{address.prefix}"
            if address.ifname:
                line += f" for interface '{address.ifname}' on host {address.forihostid}"
            lines.append(line)

        if lines:
            raise exception.AddressPoolRangesExcludeExistingAddress(addresses=', '.join(lines))

    def _check_address_duplicates(self, addrpool_dict):
        addr_map = {}
        for field in ADDRESS_FIELDS.keys():
            addr = addrpool_dict.get(field, None)
            if not addr:
                continue
            if addr in addr_map:
                msg = _("%s can not be the same as %s: %s" % (field, addr_map[addr], addr))
                raise wsme.exc.ClientSideError(msg)
            addr_map[addr] = field

    def _validate_addresses(self, subnet, addrpool):
        for addr_field in ADDRESS_FIELDS.keys():
            address = addrpool[addr_field]
            if address:
                self._check_valid_address(subnet, address)

    def _check_existing_addresses(self, addrpool, updates):
        existing_addresses = {}
        for addr_field in ADDRESS_FIELDS.keys():
            if not self._is_field_updated(addrpool, updates, addr_field):
                continue
            ip_address = updates[addr_field]
            if not ip_address:
                continue
            try:
                address = pecan.request.dbapi.address_get_by_address(ip_address)
            except exception.AddressNotFoundByAddress:
                continue
            if address.pool_uuid == addrpool.uuid:
                continue
            self._check_address_assigned(address)
            existing_addresses[addr_field] = address
        return existing_addresses

    def _is_field_updated(self, addrpool, updates, field):
        if field not in updates:
            return False
        return updates[field] != getattr(addrpool, field)

    def _validate_updates(self, addrpool, network_types, updates):
        self._parse_nullable_fields(updates)

        original_addrpool = addrpool.as_dict()
        new_addrpool = copy.deepcopy(original_addrpool)
        self._apply_updates(new_addrpool, updates)

        subnet = self._get_addrpool_subnet(new_addrpool)

        if self._is_field_updated(addrpool, updates, 'name'):
            self._validate_name(new_addrpool)

        needs_ranges_validation = False
        if (self._is_field_updated(addrpool, updates, 'prefix') or
                self._is_field_updated(addrpool, updates, 'network')):
            self._check_valid_subnet(subnet, original_addrpool['family'])
            self._check_pool_overlap(new_addrpool, network_types)
            needs_ranges_validation = True

        if self._is_field_updated(addrpool, updates, 'ranges'):
            self._validate_range_updates(addrpool, updates)
            self._sort_ranges(new_addrpool)
            needs_ranges_validation = True

        if needs_ranges_validation:
            self._check_valid_ranges(new_addrpool, subnet)

        if self._is_field_updated(addrpool, updates, 'order'):
            AddressPool._validate_allocation_order(new_addrpool['order'])

        self._validate_addresses(subnet, new_addrpool)
        self._check_address_duplicates(new_addrpool)
        self._do_network_specific_validations(addrpool, new_addrpool, network_types, updates)
        return self._check_existing_addresses(addrpool, updates)

    def _apply_updates(self, addrpool_dict, updates):
        for field, value in updates.items():
            addrpool_dict[field] = value

    def _do_network_specific_validations(self, original_addrpool, updated_addrpool, network_types,
                                         updates):
        if constants.NETWORK_TYPE_OAM in network_types:
            self._do_oam_validations(original_addrpool, updated_addrpool, updates)

    def _do_oam_validations(self, original_addrpool, updated_addrpool, updates):
        fields = ['floating_address']
        if utils.get_system_mode() != constants.SYSTEM_MODE_SIMPLEX:
            fields.extend(['controller0_address', 'controller1_address'])
        null_fields = [field for field in fields if updated_addrpool[field] is None]
        if null_fields:
            msg = _("The field%s must not be empty: %s" %
                    ('s' if len(null_fields) > 1 else '', ', '.join(null_fields)))
            raise wsme.exc.ClientSideError(msg)

    NULLABLE_FIELDS = ['floating_address', 'controller0_address', 'controller1_address',
                       'gateway_address']

    NULL_VALUES = ('none', 'null', 'nothing', 'empty', 'undefined', 'unspecified')

    def _parse_nullable_fields(self, updates):
        for field, value in updates.items():
            if field in self.NULLABLE_FIELDS:
                if value.lower() in self.NULL_VALUES:
                    updates[field] = None

    def _create_address_pool(self, addrpool):
        addrpool.validate_syntax()
        addrpool_dict = addrpool.as_dict()
        self._set_defaults(addrpool_dict)
        self._sort_ranges(addrpool_dict)

        subnet = self._get_addrpool_subnet(addrpool_dict)

        # Check for semantic conflicts
        self._check_name_conflict(addrpool_dict)
        self._check_valid_subnet(subnet)
        self._check_valid_ranges(addrpool_dict, subnet)
        self._check_address_duplicates(addrpool_dict)

        # Search for addresses that already exist in the database
        existing_addresses = self._get_existing_addresses(addrpool, subnet)

        new_addresses = []
        for addr_field, id_field in ADDRESS_FIELDS.items():
            ip_address = addrpool_dict.pop(addr_field, None)
            if not ip_address:
                continue
            existing_addr = existing_addresses.get(addr_field, None)
            if existing_addr:
                addrpool_dict[id_field] = existing_addr.id
                continue
            values = {'address': str(ip_address),
                      'name': '{}-{}'.format(addrpool_dict['name'], addr_field),
                      'prefix': addrpool_dict['prefix'],
                      'family': addrpool_dict['family'],
                      'enable_dad': constants.IP_DAD_STATES[addrpool_dict['family']]}
            address_obj = pecan.request.dbapi.address_create(values)
            new_addresses.append(address_obj)
            addrpool_dict[id_field] = address_obj.id

        # Attempt to create the new address pool record
        new_pool = pecan.request.dbapi.address_pool_create(addrpool_dict)

        # Update the existing addresses
        if existing_addresses:
            values = {'address_pool_id': new_pool.id,
                      'prefix': new_pool.prefix,
                      'enable_dad': constants.IP_DAD_STATES[new_pool.family]}
            for addr_field, address in existing_addresses.items():
                # If the address already exists, it could belong to an unassigned address pool
                # and has to be removed from it
                remove_address_from_pool(address)
                values['name'] = '{}-{}'.format(addrpool_dict['name'], addr_field)
                pecan.request.dbapi.address_update(address.id, values)

        # Update the address_pool_id field in each of the new addresses
        values = {'address_pool_id': new_pool.id}
        for address in new_addresses:
            pecan.request.dbapi.address_update(address.id, values)

        return new_pool

    def _get_existing_addresses(self, addrpool, subnet):
        address_index = {}
        for field in ADDRESS_FIELDS.keys():
            address = getattr(addrpool, field, None)
            if not address:
                continue
            self._check_valid_address(subnet, address)
            try:
                address_obj = pecan.request.dbapi.address_get_by_address(address)
            except exception.AddressNotFoundByAddress:
                continue
            self._check_address_assigned(address_obj)
            address_index[field] = address_obj
        return address_index

    def _check_address_assigned(self, address):
        if utils.is_address_assigned(address):
            if address.interface_id:
                msg = _("Address {} already assigned to the {} interface in host {}".format(
                    address.address, address.ifname, address.forihostid))
                raise wsme.exc.ClientSideError(msg)
            if address.pool_uuid:
                msg = _("Address {} already assigned to the following address pool: {}".format(
                    address.address, address.pool_uuid))
                raise wsme.exc.ClientSideError(msg)

    def _get_networks(self, addrpool):
        return pecan.request.dbapi.networks_get_by_pool(addrpool.id)

    def _get_network_types(self, networks):
        return {network.type for network in networks}

    def _get_system_mode(self):
        mode = self.cache.get('system_mode', None)
        if not mode:
            mode = utils.get_system_mode()
            self.cache['system_mode'] = mode
        return mode

    def _setup_cache(self):
        self.cache = {}

    def _update_address_pool(self, address_pool_uuid, patch):
        self._setup_cache()
        addrpool = self._get_one(address_pool_uuid)
        networks = self._get_networks(addrpool)
        network_types = self._get_network_types(networks)
        updates = self._get_updates(patch)
        self._check_modification_allowed(network_types)
        existing_addresses = self._validate_updates(addrpool, network_types, updates)
        field_updates = self._update_addresses(addrpool, network_types, updates, existing_addresses)
        addrpool = self._apply_addrpool_updates(addrpool, updates, field_updates)
        self._update_no_proxy_list(addrpool, network_types, updates)
        self._address_pool_updated(addrpool, network_types)
        return addrpool

    def _apply_addrpool_updates(self, addrpool, updates, field_updates):
        if updates:
            addrpool = pecan.request.dbapi.address_pool_update(addrpool.uuid, updates)
        for field, value in field_updates.items():
            setattr(addrpool, field, value)
        return addrpool

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

    def _prefix_updated(self, addrpool, updates):
        prefix_field = 'prefix'
        if prefix_field not in updates:
            return False
        return getattr(addrpool, prefix_field) != updates[prefix_field]

    def _remove_conflicting_addresses(self, update_cmds, existing_addresses):
        for field in update_cmds.keys():
            address = existing_addresses.pop(field, None)
            if address:
                remove_address_from_pool(address)
                pecan.request.dbapi.address_destroy(address.id)

    def _update_addresses(self, addrpool, network_types, updates, existing_addresses):
        update_cmds = {}
        delete_cmds = set()
        create_cmds = {}
        field_updates = {}

        prefix_updated = self._prefix_updated(addrpool, updates)

        for addr_field, addr_id_field in ADDRESS_FIELDS.items():
            current_addr = getattr(addrpool, addr_field)
            if addr_field in updates:
                new_addr = updates.pop(addr_field)
                if new_addr != current_addr:
                    if not new_addr:
                        delete_cmds.add(addr_id_field)
                        continue
                    if not current_addr:
                        values = {'address': new_addr}
                        if prefix_updated:
                            values['prefix'] = updates['prefix']
                        create_cmds[addr_field] = values
                        continue
                    update_cmds.setdefault(addr_field, {})['address'] = new_addr
            if prefix_updated and current_addr:
                update_cmds.setdefault(addr_field, {})['prefix'] = updates['prefix']

        commands = {'update': update_cmds, 'delete': delete_cmds, 'create': create_cmds}

        self._apply_network_specific_address_updates(addrpool, network_types, commands)

        self._remove_conflicting_addresses(update_cmds, existing_addresses)
        self._apply_address_update_cmds(addrpool, updates, update_cmds, field_updates)
        self._process_address_delete_cmds(addrpool, updates, delete_cmds, field_updates)
        self._process_address_create_cmds(addrpool, updates, create_cmds, field_updates,
                                          network_types, existing_addresses)

        return field_updates

    def _apply_address_update_cmds(self, addrpool, updates, update_index, field_updates):
        for addr_field, values in update_index.items():
            addr_id_field = ADDRESS_FIELDS[addr_field]
            address_obj = pecan.request.dbapi.address_get_by_id(getattr(addrpool, addr_id_field))
            pecan.request.dbapi.address_update(address_obj.uuid, values)
            if 'address' in values:
                field_updates[addr_field] = values['address']

    def _process_address_delete_cmds(self, addrpool, updates, delete_index, field_updates):
        for addr_id_field in delete_index:
            pecan.request.dbapi.address_destroy_by_id(getattr(addrpool, addr_id_field))
            updates[addr_id_field] = None

    FIELD_TO_HOSTNAME = {value[0]: key for key, value in CONTROLLER_ADDRESS_FIELDS.items()}

    def _get_address_hostname(self, field, network_type, dc_role):
        if field == 'gateway_address':
            if network_type != constants.NETWORK_TYPE_OAM and \
                    dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
                return constants.SYSTEM_CONTROLLER_GATEWAY_IP_NAME
            else:
                return constants.CONTROLLER_GATEWAY
        return self.FIELD_TO_HOSTNAME[field]

    def _process_address_create_cmds(self, addrpool, updates, create_index, field_updates,
                                     network_types, existing_addresses):
        if not create_index:
            return

        create_params = {'address_pool_id': addrpool.id,
                         'prefix': addrpool.prefix,
                         'family': addrpool.family,
                         'enable_dad': constants.IP_DAD_STATES[addrpool.family]}

        network_type = next(iter(network_types)) if len(network_types) == 1 else None
        if network_type:
            dc_role = utils.get_distributed_cloud_role()

        for addr_field, values in create_index.items():
            addr_id_field = ADDRESS_FIELDS[addr_field]
            params = create_params.copy()
            params.update(values)
            if network_type:
                hostname = self._get_address_hostname(addr_field, network_type, dc_role)
                params['name'] = cutils.format_address_name(hostname, network_type)
            else:
                params['name'] = '{}-{}'.format(addrpool.name, addr_field)
            existing_addr = existing_addresses.get(addr_field, None)
            if existing_addr:
                address = pecan.request.dbapi.address_update(existing_addr.id, params)
                remove_address_from_pool(existing_addr)
            else:
                address = pecan.request.dbapi.address_create(params)
            field_updates[addr_field] = address.address
            updates[addr_id_field] = address.id

    def _apply_network_specific_address_updates(self, addrpool, network_types, commands):
        if constants.NETWORK_TYPE_OAM in network_types:
            self._apply_oam_address_updates(addrpool, commands)

    def _apply_oam_address_updates(self, addrpool, commands):
        system = pecan.request.dbapi.isystem_get_one()
        if system.capabilities.get('simplex_to_duplex_migration') or \
                system.capabilities.get('simplex_to_duplex-direct_migration'):
            self._aio_sx_to_dx_oam_migration(addrpool, commands)

    def _aio_sx_to_dx_oam_migration(self, addrpool, commands):
        create_cmd = commands['create'].get('controller0_address', None)
        if not create_cmd:
            return
        floating_address = pecan.request.dbapi.address_get_by_id(addrpool.floating_address_id)
        create_cmd['interface_id'] = floating_address.interface_id
        commands['update'].setdefault('floating_address', {})['interface_id'] = None

    def _update_no_proxy_list(self, addrpool, network_types, updates):
        if not has_to_update_no_proxy_list(network_types):
            return
        no_proxy_entry = _get_docker_no_proxy_entry()
        if not no_proxy_entry:
            return
        to_remove = []
        to_add = []
        for field in ['floating_address', 'controller0_address']:
            if self._is_field_updated(addrpool, updates, field):
                old = getattr(addrpool, field)
                if old:
                    to_remove.append(addrpool.family, old)
                new = updates[field]
                if new:
                    to_add.append(addrpool.family, new)
        if to_remove or to_add:
            _update_docker_no_proxy_list(no_proxy_entry, to_remove, to_add)

    def _address_pool_updated(self, addrpool, network_types):
        if constants.NETWORK_TYPE_OAM in network_types:
            pecan.request.rpcapi.update_oam_config(pecan.request.context)

        if constants.NETWORK_TYPE_MGMT in network_types:
            if self._get_system_mode() == constants.SYSTEM_MODE_SIMPLEX and \
                    cutils.is_initial_config_complete():
                pecan.request.rpcapi.set_mgmt_network_reconfig_flag(pecan.request.context)

    def _check_delete_primary(self, addrpool, networks):
        nets = []
        for network in networks:
            if network.pool_uuid == addrpool.uuid:
                nets.append(network.type)
        if nets:
            msg = _("Address pool is the primary for the following network"
                    "%s: %s. Not possible to delete." %
                    ('s' if len(nets) > 1 else '', ', '.join(nets)))
            raise wsme.exc.ClientSideError(msg)

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
        return self._update_address_pool(address_pool_uuid, patch)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, address_pool_uuid):
        """Delete an IP address pool."""
        self._setup_cache()
        addrpool = self._get_one(address_pool_uuid)
        networks = self._get_networks(addrpool)
        network_types = self._get_network_types(networks)

        self._check_delete_primary(addrpool, networks)
        self._check_modification_allowed(network_types)

        # if proxy is being used, remove the old management network IPs
        # from the no_proxy list
        if has_to_update_no_proxy_list(network_types):
            remove_management_addresses_from_no_proxy_list([addrpool])

        addresses = pecan.request.dbapi.addresses_get_by_pool(addrpool.id)
        for addr in addresses:
            pecan.request.dbapi.address_destroy(addr.uuid)

        # Delete the address pool, which will also delete any associated
        # network and interface association.
        pecan.request.dbapi.address_pool_destroy(address_pool_uuid)

        if networks:
            # Delete associated network_addrpool database entries
            netpools = pecan.request.dbapi.network_addrpool_get_by_pool_id(addrpool.id)
            for netpool in netpools:
                pecan.request.dbapi.network_addrpool_destroy(netpool.uuid)

        if constants.NETWORK_TYPE_ADMIN in network_types:
            # If the admin address pool is deleted, this allows the
            # subcloud to automatically revert to using the management
            # network
            chosts = pecan.request.dbapi.ihost_get_by_personality(constants.CONTROLLER)
            for host in chosts:
                pecan.request.rpcapi.update_admin_config(pecan.request.context, host, disable=True)

        if constants.NETWORK_TYPE_OAM in network_types:
            pecan.request.rpcapi.update_oam_config(pecan.request.context)


def _get_docker_no_proxy_entry():
    try:
        no_proxy_entry = pecan.request.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_DOCKER,
            section=constants.SERVICE_PARAM_SECTION_DOCKER_PROXY,
            name=constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY)
    except exception.NotFound:
        return None
    return no_proxy_entry


def _update_docker_no_proxy_list(no_proxy_entry, to_remove=None, to_add=None):
    no_proxy_list = no_proxy_entry.value.split(',') if no_proxy_entry.value else []

    if to_remove:
        for family, address in to_remove:
            if family == constants.IPV6_FAMILY:
                address = '[' + address + ']'
            if address in no_proxy_list:
                no_proxy_list.remove(address)

    if to_add:
        for family, address in to_add:
            if family == constants.IPV6_FAMILY:
                address = '[' + address + ']'
            if address not in no_proxy_list:
                no_proxy_list.append(address)

    no_proxy_string = ','.join(no_proxy_list)
    pecan.request.dbapi.service_parameter_update(no_proxy_entry.uuid, {'value': no_proxy_string})


def is_mgmt_network_associated_to_interface():
    if_networks = pecan.request.dbapi.interface_networks_get_by_network_type(
        constants.NETWORK_TYPE_MGMT)
    if if_networks:
        return True
    return False


def has_to_update_no_proxy_list(network_types):
    if constants.NETWORK_TYPE_MGMT not in network_types:
        return False
    if utils.get_system_mode() != constants.SYSTEM_MODE_SIMPLEX:
        return False
    if not cutils.is_initial_config_complete():
        return False
    if is_mgmt_network_associated_to_interface():
        return True
    return False


def _collect_management_addresses(addrpool):
    addresses = []
    if addrpool.floating_address:
        addresses.append((addrpool.family, addrpool.floating_address))
    if addrpool.controller0_address:
        addresses.append((addrpool.family, addrpool.controller0_address))
    return addresses


def add_management_addresses_to_no_proxy_list(addrpools):
    no_proxy_entry = _get_docker_no_proxy_entry()
    if not no_proxy_entry:
        return
    for addrpool in addrpools:
        addresses = _collect_management_addresses(addrpool)
        if addresses:
            _update_docker_no_proxy_list(no_proxy_entry, to_add=addresses)


def remove_management_addresses_from_no_proxy_list(addrpools):
    no_proxy_entry = _get_docker_no_proxy_entry()
    if not no_proxy_entry:
        return
    for addrpool in addrpools:
        addresses = _collect_management_addresses(addrpool)
        if addresses:
            _update_docker_no_proxy_list(no_proxy_entry, to_remove=addresses)


def remove_address_from_pool(address, dbapi=None):
    if not address.pool_uuid:
        return
    if not dbapi:
        dbapi = pecan.request.dbapi
    addrpool = dbapi.address_pool_get(address.pool_uuid)
    for field in ADDRESS_FIELDS.values():
        if getattr(addrpool, field, None) is not None:
            dbapi.address_pool_update(addrpool.id, {field: None})
            LOG.info("Address {} removed from address pool {{{}}}, field '{}'".format(
                address.address, addrpool.uuid, field))
            return


def add_address_to_pool(addrpool, address_id, hostname, dbapi=None):
    field = CONTROLLER_ADDRESS_FIELDS.get(hostname, None)
    if not field:
        return
    if getattr(addrpool, field[1]) != address_id:
        if not dbapi:
            dbapi = pecan.request.dbapi
        dbapi.address_pool_update(addrpool.id, {field[1]: address_id})
