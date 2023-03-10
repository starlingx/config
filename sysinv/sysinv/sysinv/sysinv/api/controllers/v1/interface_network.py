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
# Copyright (c) 2013-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import os
import pecan
from pecan import rest
import uuid
import wsme
import wsmeext.pecan as wsme_pecan
from wsme import types as wtypes

from oslo_log import log
from sysinv._i18n import _
from sysinv import objects
from sysinv.api.controllers.v1 import address_pool
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils

LOG = log.getLogger(__name__)


# Cannot assign any of the following network types
NONASSIGNABLE_NETWORK_TYPES = (constants.NETWORK_TYPE_DATA,
                               constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                               constants.NETWORK_TYPE_PCI_SRIOV)

# Each of these networks may only be provisioned once per node
NONDUPLICATE_NETWORK_TYPES = (constants.NETWORK_TYPE_MGMT,
                              constants.NETWORK_TYPE_OAM,
                              constants.NETWORK_TYPE_CLUSTER_HOST,
                              constants.NETWORK_TYPE_PXEBOOT,
                              constants.NETWORK_TYPE_STORAGE,
                              constants.NETWORK_TYPE_ADMIN)


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
        self.fields = list(objects.interface_network.fields.keys())
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

        interface_obj = pecan.request.dbapi.iinterface_get(interface_uuid)
        interface_id = interface_obj.id
        network_id, network_type = self._get_network_id_and_type(network_uuid)
        host = pecan.request.dbapi.ihost_get(interface_obj.ihost_uuid)

        interface_network_dict['interface_id'] = interface_id
        interface_network_dict['network_id'] = network_id

        self._check_interface_class(interface_uuid)
        self._check_assigned_network_type(network_type)
        self._check_duplicate_interface_network(interface_network_dict)
        self._check_duplicate_type(host, interface_uuid, network_type)
        self._check_pxeboot_network(interface_id, network_type)
        self._check_oam_network(interface_id, network_type)
        self._check_network_type_and_host_type(host, network_type)
        self._check_network_type_and_interface_type(interface_obj, network_type)
        self._check_cluster_host_on_controller(host, interface_obj, network_type)

        result = pecan.request.dbapi.interface_network_create(interface_network_dict)

        # Update address mode based on network type
        if network_type in [constants.NETWORK_TYPE_MGMT,
                            constants.NETWORK_TYPE_OAM,
                            constants.NETWORK_TYPE_CLUSTER_HOST,
                            constants.NETWORK_TYPE_ADMIN]:
            pool_uuid = pecan.request.dbapi.network_get_by_type(network_type).pool_uuid
            pool = pecan.request.dbapi.address_pool_get(pool_uuid)
            if pool.family == constants.IPV4_FAMILY:
                utils.update_address_mode(interface_obj, constants.IPV4_FAMILY,
                                          constants.IPV4_STATIC, None)
                utils.update_address_mode(interface_obj, constants.IPV6_FAMILY,
                                          constants.IPV6_DISABLED, None)
            else:
                utils.update_address_mode(interface_obj, constants.IPV6_FAMILY,
                                          constants.IPV6_STATIC, None)
                utils.update_address_mode(interface_obj, constants.IPV4_FAMILY,
                                          constants.IPV4_DISABLED, None)

        # Assign an address to the interface
        _update_host_address(host, interface_obj, network_type)
        if network_type == constants.NETWORK_TYPE_MGMT:
            ethernet_port_mac = None
            if not interface_obj.uses:
                # Get the ethernet port associated with the interface
                interface_ports = pecan.request.dbapi.ethernet_port_get_by_interface(
                    interface_obj.uuid)
                for p in interface_ports:
                    if p is not None:
                        ethernet_port_mac = p.mac
                        break
            else:
                tmp_interface = interface_obj.as_dict()
                ethernet_port_mac = tmp_interface['imac']
            _update_host_mgmt_mac(host, ethernet_port_mac)
            cutils.perform_distributed_cloud_config(pecan.request.dbapi,
                                                    interface_id)
        elif network_type == constants.NETWORK_TYPE_ADMIN:
            pecan.request.rpcapi.update_admin_config(pecan.request.context, host)
            cutils.perform_distributed_cloud_config(pecan.request.dbapi,
                                                    interface_id)
        elif network_type == constants.NETWORK_TYPE_OAM:
            pecan.request.rpcapi.initialize_oam_config(pecan.request.context, host)

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
        elif interface.ifclass == constants.INTERFACE_CLASS_PCI_SRIOV:
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
        msg = _("Interface network with interface ID '%s' "
                "and network ID '%s' already exists."
                % (interface_network['interface_id'], interface_network['network_id']))
        raise wsme.exc.ClientSideError(msg)

    def _check_duplicate_type(self, host, interface_uuid, network_type):
        if network_type in NONDUPLICATE_NETWORK_TYPES:
            interfaces = pecan.request.dbapi.iinterface_get_by_ihost(host['uuid'])
            for host_interface in interfaces:
                if (network_type in host_interface['networktypelist'] and
                        host_interface['uuid'] != interface_uuid):
                    msg = _("An interface with '%s' network type is "
                            "already provisioned on this node" % network_type)
                    raise wsme.exc.ClientSideError(msg)

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
                                  constants.NETWORK_TYPE_CLUSTER_HOST]
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

    def _check_network_type_and_host_type(self, ihost, network_type):
        if (network_type == constants.NETWORK_TYPE_OAM and
                ihost['personality'] != constants.CONTROLLER):
            msg = _("The '%s' network type is only supported on controller nodes." %
                constants.NETWORK_TYPE_OAM)
            raise wsme.exc.ClientSideError(msg)

    def _check_network_type_and_interface_type(self, interface, network_type):
        # Make sure network type 'mgmt' or 'admin', with if type 'ae',
        # can only be in ae mode 'active_standby' or '802.3ad'
        if (network_type in [constants.NETWORK_TYPE_MGMT,
                             constants.NETWORK_TYPE_ADMIN]):
            valid_aemode = [constants.AE_MODE_LACP,
                            constants.AE_MODE_ACTIVE_STANDBY]
            if (interface.iftype == constants.INTERFACE_TYPE_AE and
                    interface.aemode not in valid_aemode):
                msg = _("Device interface with network type {}, and interface "
                        "type 'aggregated ethernet' must be in mode {}").format(
                        network_type, ', '.join(valid_aemode))
                raise wsme.exc.ClientSideError(msg)
        # Make sure network type 'oam' or 'cluster-host', with if type 'ae',
        # can only be in ae mode 'active_standby' or 'balanced' or '802.3ad'
        elif (network_type in [constants.NETWORK_TYPE_OAM,
                               constants.NETWORK_TYPE_CLUSTER_HOST] and
              interface.iftype == constants.INTERFACE_TYPE_AE and
              (interface.aemode not in constants.VALID_AEMODE_LIST)):
                msg = _("Device interface with network type '%s', and interface "
                        "type 'aggregated ethernet' must be in mode 'active_standby' "
                        "or 'balanced' or '802.3ad'." % network_type)
                raise wsme.exc.ClientSideError(msg)

    def _check_cluster_host_on_controller(self, host, interface, network_type):
        # Check if cluster-host exists on controller, if it doesn't then fail
        if (host['personality'] != constants.CONTROLLER and
                network_type == constants.NETWORK_TYPE_CLUSTER_HOST):
            host_list = pecan.request.dbapi.ihost_get_by_personality(
                personality=constants.CONTROLLER)
            cluster_host_on_controller = False
            for h in host_list:
                interfaces = pecan.request.dbapi.iinterface_get_by_ihost(ihost=h['uuid'])
                for host_interface in interfaces:
                    if (host_interface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM and
                            constants.NETWORK_TYPE_CLUSTER_HOST in host_interface['networktypelist']):
                        cluster_host_on_controller = True
                        break
            if not cluster_host_on_controller:
                msg = _("Interface %s does not have associated"
                        " cluster-host interface on controller." %
                        interface['ifname'])
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
        # Delete address allocated to the interface
        if_network_obj = pecan.request.dbapi.interface_network_get(
            interface_network_uuid)
        network = pecan.request.dbapi.network_get(if_network_obj.network_uuid)
        pool_uuid = pecan.request.dbapi.network_get_by_type(network.type).pool_uuid
        address = None
        try:
            address = pecan.request.dbapi.addresses_get_by_interface_pool(
                if_network_obj.interface_uuid, pool_uuid)
        except exception.AddressNotFoundByInterfacePool:
            pass
        if address:
            pecan.request.dbapi.address_remove_interface(address.uuid)

        pecan.request.dbapi.interface_network_destroy(interface_network_uuid)


def _update_host_address(host, interface, network_type):
    if network_type == constants.NETWORK_TYPE_MGMT:
        _update_host_mgmt_address(host, interface)
    elif network_type == constants.NETWORK_TYPE_ADMIN:
        _update_host_admin_address(host, interface)
    elif network_type == constants.NETWORK_TYPE_CLUSTER_HOST:
        _update_host_cluster_address(host, interface)
    elif network_type == constants.NETWORK_TYPE_IRONIC:
        _update_host_ironic_address(host, interface)
    elif network_type == constants.NETWORK_TYPE_STORAGE:
        _update_host_storage_address(host, interface)
    if host.personality == constants.CONTROLLER:
        if network_type == constants.NETWORK_TYPE_OAM:
            _update_host_oam_address(host, interface)
        elif network_type == constants.NETWORK_TYPE_PXEBOOT:
            _update_host_pxeboot_address(host, interface)


def _dynamic_address_allocation():
    mgmt_network = pecan.request.dbapi.network_get_by_type(
        constants.NETWORK_TYPE_MGMT)
    return mgmt_network.dynamic


def _allocate_pool_address(interface_id, pool_uuid, address_name=None):
    address_pool.AddressPoolController.assign_address(
        interface_id, pool_uuid, address_name)


def _update_host_mgmt_address(host, interface):
    """Check if the host has a static management IP address assigned
    and ensure the address is populated against the interface.  Otherwise,
    if using dynamic address allocation, then allocate an address
    """

    mgmt_ip = utils.lookup_static_ip_address(
        host.hostname, constants.NETWORK_TYPE_MGMT)

    if mgmt_ip:
        pecan.request.rpcapi.mgmt_ip_set_by_ihost(
            pecan.request.context, host.uuid, interface['id'], mgmt_ip)
    elif _dynamic_address_allocation():
        mgmt_pool_uuid = pecan.request.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_MGMT
        ).pool_uuid
        address_name = cutils.format_address_name(host.hostname,
                                                  constants.NETWORK_TYPE_MGMT)
        _allocate_pool_address(interface['id'], mgmt_pool_uuid, address_name)


def _update_host_admin_address(host, interface):
    address_name = cutils.format_address_name(host.hostname,
                                              constants.NETWORK_TYPE_ADMIN)
    try:
        address = pecan.request.dbapi.address_get_by_name(address_name)
        updates = {'interface_id': interface['id']}
        pecan.request.dbapi.address_update(address.uuid, updates)
    except exception.AddressNotFoundByName:
        # For non-controller hosts, allocate address from pool if dynamic
        admin_network = pecan.request.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_ADMIN)
        if admin_network.dynamic:
            _allocate_pool_address(interface['id'],
                                   admin_network.pool_uuid,
                                   address_name)


def _update_host_oam_address(host, interface):
    if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
        address_name = cutils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                                  constants.NETWORK_TYPE_OAM)
    else:
        address_name = cutils.format_address_name(host.hostname,
                                                  constants.NETWORK_TYPE_OAM)
    address = pecan.request.dbapi.address_get_by_name(address_name)
    updates = {'interface_id': interface['id']}
    pecan.request.dbapi.address_update(address.uuid, updates)


def _update_host_pxeboot_address(host, interface):
    address_name = cutils.format_address_name(host.hostname,
                                              constants.NETWORK_TYPE_PXEBOOT)
    address = pecan.request.dbapi.address_get_by_name(address_name)
    updates = {'interface_id': interface['id']}
    pecan.request.dbapi.address_update(address.uuid, updates)


def _update_host_cluster_address(host, interface):
    """
    Check if the host has a cluster-host IP address assigned
    and the address is populated against the interface.
    Otherwise, allocate an address from the pool.
    """
    address_name = cutils.format_address_name(
        host.hostname, constants.NETWORK_TYPE_CLUSTER_HOST)
    try:
        address = pecan.request.dbapi.address_get_by_name(address_name)
        updates = {'interface_id': interface['id']}
        pecan.request.dbapi.address_update(address.uuid, updates)
    except exception.AddressNotFoundByName:
        cluster_host_network = pecan.request.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST)
        if cluster_host_network.dynamic:
            _allocate_pool_address(interface['id'],
                                   cluster_host_network.pool_uuid,
                                   address_name)


def _update_host_ironic_address(host, interface):
    address_name = cutils.format_address_name(host.hostname,
                                              constants.NETWORK_TYPE_IRONIC)
    address = pecan.request.dbapi.address_get_by_name(address_name)
    updates = {'interface_id': interface['id']}
    pecan.request.dbapi.address_update(address.uuid, updates)


def _update_host_storage_address(host, interface):
    address_name = cutils.format_address_name(host.hostname,
                                              constants.NETWORK_TYPE_STORAGE)
    try:
        address = pecan.request.dbapi.address_get_by_name(address_name)
        updates = {'interface_id': interface['id']}
        pecan.request.dbapi.address_update(address.uuid, updates)
    except exception.AddressNotFoundByName:
        # For non-controller hosts, allocate address from pool if dynamic
        storage_network = pecan.request.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_STORAGE)
        if storage_network.dynamic:
            _allocate_pool_address(interface['id'],
                                   storage_network.pool_uuid,
                                   address_name)


def _update_host_mgmt_mac(host, mgmt_mac):
    """Update host mgmt mac to reflect interface change.
    """

    if (os.path.isfile(constants.ANSIBLE_BOOTSTRAP_FLAG) and
            mgmt_mac is not None):
        # This must be called during management interface provisioning
        # following controller-0 bootstrap.
        if host['mgmt_mac'] != mgmt_mac:
            pecan.request.rpcapi.mgmt_mac_set_by_ihost(
                pecan.request.context, host, mgmt_mac)
