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
# Copyright (c) 2015 Wind River Systems, Inc.
#


import netaddr
import uuid

import pecan
from pecan import rest

from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import route
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log

LOG = log.getLogger(__name__)

# Defines the list of interface network types that support addresses
ALLOWED_NETWORK_TYPES = [constants.NETWORK_TYPE_MGMT,
                         constants.NETWORK_TYPE_INFRA,
                         constants.NETWORK_TYPE_OAM,
                         constants.NETWORK_TYPE_DATA]


class Address(base.APIBase):
    """API representation of an IP address.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of an IP
    address.
    """

    id = int
    "Unique ID for this address"

    uuid = types.uuid
    "Unique UUID for this address"

    interface_uuid = types.uuid
    "Unique UUID of the parent interface"

    ifname = wtypes.text
    "User defined name of the interface"

    address = types.ipaddress
    "IP address"

    prefix = int
    "IP address prefix length"

    name = wtypes.text
    "User defined name of the address"

    enable_dad = bool
    "Enables or disables duplicate address detection"

    forihostid = int
    "The ID of the host this interface belongs to"

    pool_uuid = wtypes.text
    "The UUID of the address pool from which this address was allocated"

    def __init__(self, **kwargs):
        self.fields = objects.address.fields.keys()
        for k in self.fields:
            if not hasattr(self, k):
                # Skip fields that we choose to hide
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    def _get_family(self):
        value = netaddr.IPAddress(self.address)
        return value.version

    def as_dict(self):
        """
        Sets additional DB only attributes when converting from an API object
        type to a dictionary that will be used to populate the DB.
        """
        data = super(Address, self).as_dict()
        data['family'] = self._get_family()
        return data

    @classmethod
    def convert_with_links(cls, rpc_address, expand=True):
        address = Address(**rpc_address.as_dict())
        if not expand:
            address.unset_fields_except(['uuid', 'address',
                                         'prefix', 'interface_uuid', 'ifname',
                                         'forihostid', 'enable_dad',
                                         'pool_uuid'])
        return address

    def _validate_prefix(self):
        if self.prefix < 1:
            raise ValueError(_("Address prefix must be greater than 1 for "
                               "data network type"))

    def _validate_zero_address(self):
        data = netaddr.IPAddress(self.address)
        if data.value == 0:
            raise ValueError(_("Address must not be null"))

    def _validate_zero_network(self):
        data = netaddr.IPNetwork(self.address + "/" + str(self.prefix))
        network = data.network
        if network.value == 0:
            raise ValueError(_("Network must not be null"))

    def _validate_address(self):
        """
        Validates that the prefix is valid for the IP address family.
        """
        try:
            value = netaddr.IPNetwork(self.address + "/" + str(self.prefix))
        except netaddr.core.AddrFormatError:
            raise ValueError(_("Invalid IP address and prefix"))
        mask = value.hostmask
        host = value.ip & mask
        if host.value == 0:
            raise ValueError(_("Host bits must not be zero"))
        if host == mask:
            raise ValueError(_("Address cannot be the network "
                               "broadcast address"))

    def _validate_address_type(self):
        address = netaddr.IPAddress(self.address)
        if not address.is_unicast():
            raise ValueError(_("Address must be a unicast address"))

    def _validate_name(self):
        if self.name:
            # follows the same naming convention as a host name since it
            # typically contains the hostname with a network type suffix
            utils.is_valid_hostname(self.name)

    def validate_syntax(self):
        """
        Validates the syntax of each field.
        """
        self._validate_prefix()
        self._validate_zero_address()
        self._validate_zero_network()
        self._validate_address()
        self._validate_address_type()
        self._validate_name()


class AddressCollection(collection.Collection):
    """API representation of a collection of IP addresses."""

    addresses = [Address]
    "A list containing IP Address objects"

    def __init__(self, **kwargs):
        self._type = 'addresses'

    @classmethod
    def convert_with_links(cls, rpc_addresses, limit, url=None,
                           expand=False, **kwargs):
        collection = AddressCollection()
        collection.addresses = [Address.convert_with_links(a, expand)
                                for a in rpc_addresses]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'AddressController'


class AddressController(rest.RestController):
    """REST controller for Addresses."""

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    def _get_address_collection(self, parent_uuid,
                                marker=None, limit=None, sort_key=None,
                                sort_dir=None, expand=False,
                                resource_url=None):
        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)
        marker_obj = None

        if marker:
            marker_obj = objects.address.get_by_uuid(
                pecan.request.context, marker)

        if self._parent == "ihosts":
            addresses = pecan.request.dbapi.addresses_get_by_host(
                parent_uuid, family=0,
                limit=limit, marker=marker_obj,
                sort_key=sort_key, sort_dir=sort_dir)
        elif self._parent == "iinterfaces":
            addresses = pecan.request.dbapi.addresses_get_by_interface(
                parent_uuid, family=0,
                limit=limit, marker=marker_obj,
                sort_key=sort_key, sort_dir=sort_dir)
        else:
            addresses = pecan.request.dbapi.addresses_get_all(
                family=0, limit=limit, marker=marker_obj,
                sort_key=sort_key, sort_dir=sort_dir)

        return AddressCollection.convert_with_links(
            addresses, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    def _query_address(self, address):
        try:
            result = pecan.request.dbapi.address_query(address)
        except exception.AddressNotFoundByAddress:
            return None
        return result

    def _get_parent_id(self, interface_uuid):
        interface = pecan.request.dbapi.iinterface_get(interface_uuid)
        return (interface['forihostid'], interface['id'])

    def _check_interface_type(self, interface_id):
        interface = pecan.request.dbapi.iinterface_get(interface_id)
        if not interface.networktype:
            raise exception.InterfaceNetworkTypeNotSet()
        if interface.networktype not in ALLOWED_NETWORK_TYPES:
            raise exception.UnsupportedInterfaceNetworkType(
                networktype=interface.networktype)
        return

    def _check_infra_address(self, interface_id, address):

        # Check that infra network is configured
        try:
            infra = pecan.request.dbapi.iinfra_get_one()
        except exception.NetworkTypeNotFound:
            raise exception.InfrastructureNetworkNotConfigured()

        subnet = netaddr.IPNetwork(infra.infra_subnet)

        # Check that the correct prefix was entered
        prefix = subnet.prefixlen
        if address['prefix'] != prefix:
            raise exception.IncorrectPrefix(length=prefix)
        # Check for existing on the infra subnet and between low/high
        low = infra.infra_start
        high = infra.infra_end
        if netaddr.IPAddress(address['address']) not in \
                netaddr.IPRange(low, high):
            raise exception.IpAddressOutOfRange(address=address['address'],
                                                low=low, high=high)
        return

    def _check_address_mode(self, interface_id, family):
        interface = pecan.request.dbapi.iinterface_get(interface_id)
        if family == constants.IPV4_FAMILY:
            if interface['ipv4_mode'] != constants.IPV4_STATIC:
                raise exception.AddressModeMustBeStatic(
                    family=constants.IP_FAMILIES[family])
        elif family == constants.IPV6_FAMILY:
            if interface['ipv6_mode'] != constants.IPV6_STATIC:
                raise exception.AddressModeMustBeStatic(
                    family=constants.IP_FAMILIES[family])
        return

    def _check_duplicate_address(self, address):
        result = self._query_address(address)
        if not result:
            return
        raise exception.AddressAlreadyExists(address=address['address'],
                                             prefix=address['prefix'])

    def _is_same_subnet(self, a, b):
        if a['prefix'] != b['prefix']:
            return False
        _a = netaddr.IPNetwork(a['address'] + "/" + str(a['prefix']))
        _b = netaddr.IPNetwork(b['address'] + "/" + str(b['prefix']))
        if _a.network == _b.network:
            return True
        return False

    def _check_duplicate_subnet(self, host_id, address):
        result = pecan.request.dbapi.addresses_get_by_host(host_id)
        for entry in result:
            if self._is_same_subnet(entry, address):
                raise exception.AddressInSameSubnetExists(
                    **{'address': entry['address'],
                       'prefix': entry['prefix'],
                       'interface': entry['interface_uuid']})

    def _check_address_count(self, interface_id, host_id):
        interface = pecan.request.dbapi.iinterface_get(interface_id)
        networktype = interface['networktype']
        sdn_enabled = utils.get_sdn_enabled()

        if networktype == constants.NETWORK_TYPE_DATA and not sdn_enabled:
            # Is permitted to add multiple addresses only
            # if SDN L3 mode is not enabled.
            return

        # There can only be one 'data' interface with an IP address
        # where SDN is enabled
        if (sdn_enabled):
            iface_list = pecan.request.dbapi.iinterface_get_all(host_id)
            for iface in iface_list:
                uuid = iface['uuid']
                # skip the one we came in with
                if uuid == interface_id:
                    continue
                if iface['ifclass'] == constants.NETWORK_TYPE_DATA:
                    addresses = (
                        pecan.request.dbapi.addresses_get_by_interface(uuid))
                    if len(addresses) != 0:
                        raise exception.\
                            AddressLimitedToOneWithSDN(iftype=networktype)

    def _check_address_conflicts(self, host_id, interface_id, address):
        self._check_address_count(interface_id, host_id)
        self._check_duplicate_address(address)
        self._check_duplicate_subnet(host_id, address)

    def _check_host_state(self, host_id):
        host = pecan.request.dbapi.ihost_get(host_id)
        if utils.is_aio_simplex_host_unlocked(host):
            raise exception.HostMustBeLocked(host=host['hostname'])
        elif host['administrative'] != constants.ADMIN_LOCKED and not \
                utils.is_host_simplex_controller(host):
            raise exception.HostMustBeLocked(host=host['hostname'])

    def _check_from_pool(self, pool_uuid):
        if pool_uuid:
            raise exception.AddressAllocatedFromPool()

    def _check_orphaned_routes(self, interface_id, address):
        routes = pecan.request.dbapi.routes_get_by_interface(interface_id)
        for r in routes:
            if route.Route.address_in_subnet(r['gateway'],
                                             address['address'],
                                             address['prefix']):
                raise exception.AddressInUseByRouteGateway(
                    address=address['address'],
                    network=r['network'], prefix=r['prefix'],
                    gateway=r['gateway'])

    def _check_dad_state(self, address):
        if address['family'] == constants.IPV4_FAMILY:
            if address['enable_dad']:
                raise exception.DuplicateAddressDetectionNotSupportedOnIpv4()
        else:
            if not address['enable_dad']:
                raise exception.DuplicateAddressDetectionRequiredOnIpv6()

    def _check_managed_addr(self, host_id, interface_id):
        # Check that static address alloc is enabled
        interface = pecan.request.dbapi.iinterface_get(interface_id)
        networktype = interface['networktype']
        if networktype not in [constants.NETWORK_TYPE_MGMT,
                               constants.NETWORK_TYPE_INFRA,
                               constants.NETWORK_TYPE_OAM]:
            return
        network = pecan.request.dbapi.network_get_by_type(networktype)
        if network.dynamic:
            raise exception.StaticAddressNotConfigured()
        host = pecan.request.dbapi.ihost_get(host_id)
        if host['personality'] in [constants.STORAGE]:
            raise exception.ManagedIPAddress()

    def _check_managed_infra_addr(self, host_id):
        # Check that static address alloc is enabled
        network = pecan.request.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_INFRA)
        if network.dynamic:
            raise exception.StaticAddressNotConfigured()
        host = pecan.request.dbapi.ihost_get(host_id)
        if host['personality'] in [constants.STORAGE]:
            raise exception.ManagedIPAddress()

    def _check_name_conflict(self, address):
        name = address.get('name', None)
        if name is None:
            return
        try:
            pecan.request.dbapi.address_get_by_name(name)
            raise exception.AddressNameExists(name=name)
        except exception.AddressNotFoundByName:
            pass

    def _check_subnet_valid(self, pool, address):
        network = {'address': pool.network, 'prefix': pool.prefix}
        if not self._is_same_subnet(network, address):
            raise exception.AddressNetworkInvalid(**address)

    def _set_defaults(self, address):
        address['uuid'] = str(uuid.uuid4())
        if 'enable_dad' not in address:
            family = address['family']
            address['enable_dad'] = constants.IP_DAD_STATES[family]

    def _create_infra_addr(self, address_dict, host_id, interface_id):
        self._check_duplicate_address(address_dict)
        self._check_managed_addr(host_id, interface_id)
        self._check_infra_address(interface_id, address_dict)
        # Inform conductor of the change
        LOG.info("calling rpc with addr %s ihostid %s " % (
            address_dict['address'], host_id))
        return pecan.request.rpcapi.infra_ip_set_by_ihost(
            pecan.request.context, host_id, address_dict['address'])

    def _create_interface_addr(self, address_dict, host_id, interface_id):
        self._check_address_conflicts(host_id, interface_id, address_dict)
        self._check_dad_state(address_dict)
        self._check_managed_addr(host_id, interface_id)
        address_dict['interface_id'] = interface_id
        # Attempt to create the new address record
        return pecan.request.dbapi.address_create(address_dict)

    def _create_pool_addr(self, pool_id, address_dict):
        self._check_duplicate_address(address_dict)
        address_dict['address_pool_id'] = pool_id
        # Attempt to create the new address record
        return pecan.request.dbapi.address_create(address_dict)

    def _create_address(self, address):
        address.validate_syntax()
        address_dict = address.as_dict()
        self._set_defaults(address_dict)
        interface_uuid = address_dict.pop('interface_uuid', None)
        pool_uuid = address_dict.pop('pool_uuid', None)
        if interface_uuid is not None:
            # Query parent object references
            host_id, interface_id = self._get_parent_id(interface_uuid)
            interface = pecan.request.dbapi.iinterface_get(interface_id)

            # Check for semantic conflicts
            self._check_interface_type(interface_id)
            self._check_host_state(host_id)
            self._check_address_mode(interface_id, address_dict['family'])
            if (interface['networktype'] == constants.NETWORK_TYPE_INFRA):
                result = self._create_infra_addr(
                    address_dict, host_id, interface_id)
            else:
                result = self._create_interface_addr(
                    address_dict, host_id, interface_id)
        elif pool_uuid is not None:
            pool = pecan.request.dbapi.address_pool_get(pool_uuid)
            self._check_subnet_valid(pool, address_dict)
            self._check_name_conflict(address_dict)
            result = self._create_pool_addr(pool.id, address_dict)
        else:
            raise ValueError(_("Address must provide an interface or pool"))

        return Address.convert_with_links(result)

    def _get_one(self, address_uuid):
        rpc_address = objects.address.get_by_uuid(
            pecan.request.context, address_uuid)
        return Address.convert_with_links(rpc_address)

    @wsme_pecan.wsexpose(AddressCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, parent_uuid=None,
                marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of IP Addresses."""
        return self._get_address_collection(parent_uuid, marker, limit,
                                            sort_key, sort_dir)

    @wsme_pecan.wsexpose(Address, types.uuid)
    def get_one(self, address_uuid):
        return self._get_one(address_uuid)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Address, body=Address)
    def post(self, addr):
        """Create a new IP address."""
        return self._create_address(addr)

    def _delete_infra_addr(self, address):
        # Check if it's a config-managed infra ip address
        self._check_managed_infra_addr(getattr(address, 'forihostid'))

        # Inform conductor of removal (handles dnsmasq + address object)
        pecan.request.rpcapi.infra_ip_set_by_ihost(
            pecan.request.context,
            getattr(address, 'forihostid'),
            None)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, address_uuid):
        """Delete an IP address."""
        address = self._get_one(address_uuid)
        interface_uuid = getattr(address, 'interface_uuid')
        self._check_orphaned_routes(interface_uuid, address.as_dict())
        self._check_host_state(getattr(address, 'forihostid'))
        self._check_from_pool(getattr(address, 'pool_uuid'))
        interface = pecan.request.dbapi.iinterface_get(interface_uuid)
        if (interface['networktype'] == constants.NETWORK_TYPE_INFRA):
            self._delete_infra_addr(address)
        else:
            pecan.request.dbapi.address_destroy(address_uuid)
