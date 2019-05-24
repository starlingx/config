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
# Copyright (c) 2013-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


import jsonpatch
import os
import six
import uuid

import pecan
from pecan import rest
import copy
import wsme
import string
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import address
from sysinv.api.controllers.v1 import address_pool
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import port as port_api
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import route
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.api.controllers.v1 import interface_network
from sysinv.api.controllers.v1 import interface_datanetwork
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.objects import utils as object_utils
from sysinv.openstack.common import log
from sysinv.openstack.common import uuidutils
from sysinv.openstack.common.rpc import common as rpc_common
from sysinv.openstack.common.gettextutils import _
from fm_api import constants as fm_constants
from fm_api import fm_api

LOG = log.getLogger(__name__)

FM = fm_api.FaultAPIs()

# These are the only valid network type values
VALID_NETWORK_TYPES = [constants.NETWORK_TYPE_NONE,
                       constants.NETWORK_TYPE_PXEBOOT,
                       constants.NETWORK_TYPE_OAM,
                       constants.NETWORK_TYPE_MGMT,
                       constants.NETWORK_TYPE_CLUSTER_HOST,
                       constants.NETWORK_TYPE_DATA,
                       constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                       constants.NETWORK_TYPE_PCI_SRIOV]

VALID_INTERFACE_CLASS = [constants.INTERFACE_CLASS_PLATFORM,
                         constants.INTERFACE_CLASS_DATA,
                         constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                         constants.INTERFACE_CLASS_PCI_SRIOV]

# Interface network types that require coordination with neutron
NEUTRON_NETWORK_TYPES = [constants.NETWORK_TYPE_DATA,
                         constants.NETWORK_TYPE_PCI_PASSTHROUGH,
                         constants.NETWORK_TYPE_PCI_SRIOV]

NEUTRON_INTERFACE_CLASS = [constants.INTERFACE_CLASS_DATA,
                           constants.INTERFACE_CLASS_PCI_PASSTHROUGH,
                           constants.INTERFACE_CLASS_PCI_SRIOV]

# Interface network types that are PCI based
PCI_NETWORK_TYPES = [constants.NETWORK_TYPE_PCI_PASSTHROUGH, constants.NETWORK_TYPE_PCI_SRIOV]

VALID_AEMODE_LIST = ['active_standby', 'balanced', '802.3ad']

DATA_NETWORK_TYPES = [constants.NETWORK_TYPE_DATA]

# Kernel allows max 15 chars. For Ethernet/AE, leave 5 for VLAN id.
# For VLAN interfaces, support the full 15 char limit
MAX_IFNAME_LEN = 10
MAX_VLAN_ID_LEN = 5

# Maximum number of characters in data network list
MAX_DATANETWORK_LEN = 255

DEFAULT_MTU = 1500


class InterfacePatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return ['/address', '/ihost_uuid']


class Interface(base.APIBase):
    """API representation of an interface.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    an interface.
    """

    uuid = types.uuid
    "Unique UUID for this interface"

    ifname = wtypes.text
    "Represent the unique name of the interface"

    iftype = wtypes.text
    "Represent the unique type of the interface"

    # mac = wsme.wsattr(types.macaddress, mandatory=True)
    imac = wsme.wsattr(types.macaddress, mandatory=False)
    "MAC Address for this interface"

    imtu = int
    "MTU bytes size for this interface"

    ifclass = wtypes.text
    "Represent the class of the interface"

    networktype = wtypes.text
    "Represent the network type of the interface"

    aemode = wtypes.text
    "Represent the aemode of the interface"

    schedpolicy = wtypes.text
    "Represent the schedpolicy of the interface"

    txhashpolicy = wtypes.text
    "Represent the txhashpolicy of the interface"

    datanetworks = [wtypes.text]
    "Represent the datanetworks of the interface"

    ifcapabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                                                    six.integer_types)}
    "This interface's meta data"

    forihostid = int
    "The ihostid that this interface belongs to"

    ihost_uuid = types.uuid
    "The UUID of the host this interface belongs to"

    ports = [link.Link]
    "Links to the collection of Ports on this interface"

    links = [link.Link]
    "A list containing a self link and associated interface links"

    vlan_id = int
    "VLAN id for this interface"

    uses = [wtypes.text]
    "A list containing the interface(s) that this interface uses"

    usesmodify = wtypes.text
    "A list containing the interface(s) that this interface uses"

    used_by = [wtypes.text]
    "A list containing the interface(s) that use this interface"

    ipv4_mode = wtypes.text
    "Represents the current IPv4 address mode"

    ipv4_pool = wtypes.text
    "Represents the current IPv4 address pool selection"

    ipv6_mode = wtypes.text
    "Represents the current IPv6 address mode"

    ipv6_pool = wtypes.text
    "Represents the current IPv6 address pool selection"

    sriov_numvfs = int
    "The number of configured SR-IOV VFs"

    networks = [wtypes.text]
    "Represent the networks of the interface"

    def __init__(self, **kwargs):
        self.fields = list(objects.interface.fields.keys())
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        # API-only attributes
        self.fields.append('ports')
        setattr(self, 'ports', kwargs.get('ports', None))

    @classmethod
    def convert_with_links(cls, rpc_interface, expand=True):
        # fields = ['uuid', 'address'] if not expand else None
        # interface = iinterface.from_rpc_object(rpc_interface, fields)

        kwargs = rpc_interface.as_dict()
        datanetworks_list = kwargs.pop('datanetworks')

        interface = Interface(**kwargs)
        if not expand:
            interface.unset_fields_except(['uuid', 'ifname', 'iftype',
                                           'imac', 'imtu', 'ifclass', 'networktype', 'networks',
                                           'ihost_uuid', 'forihostid',
                                           'aemode', 'schedpolicy', 'txhashpolicy',
                                           'vlan_id', 'uses', 'usesmodify', 'used_by',
                                           'ipv4_mode', 'ipv6_mode', 'ipv4_pool', 'ipv6_pool',
                                           'sriov_numvfs',
                                           'datanetworks'])

        # never expose the ihost_id attribute
        interface.ihost_id = wtypes.Unset
        # interface.networktype = wtypes.Unset

        interface.links = [link.Link.make_link('self', pecan.request.host_url,
                                               'iinterfaces', interface.uuid),
                           link.Link.make_link('bookmark',
                                               pecan.request.host_url,
                                               'iinterfaces', interface.uuid,
                                               bookmark=True)
                           ]
        if expand:
            interface.ports = [
                link.Link.make_link('self',
                                    pecan.request.host_url,
                                    'iinterfaces',
                                    interface.uuid + "/ports"),
                link.Link.make_link(
                    'bookmark',
                    pecan.request.host_url,
                    'iinterfaces',
                    interface.uuid + "/ports",
                    bookmark=True)
            ]

        ifclass = rpc_interface.as_dict()['ifclass']
        networks = rpc_interface.as_dict()['networks']
        networktypelist = []
        if ifclass == constants.INTERFACE_CLASS_PLATFORM:
            for network_id in networks:
                network = pecan.request.dbapi.network_get_by_id(network_id)
                networktypelist.append(network.type)
        elif ifclass:
            networktypelist.append(ifclass)
        else:
            networktypelist.append(constants.INTERFACE_CLASS_NONE)
        if not any(networktype in address.ALLOWED_NETWORK_TYPES
                   for networktype in networktypelist):

            # Hide this functionality when the network type does not support
            # setting or updating the network type
            interface.ipv4_mode = wtypes.Unset
            interface.ipv6_mode = wtypes.Unset
            interface.ipv4_pool = wtypes.Unset
            interface.ipv6_pool = wtypes.Unset

        # It is not necessary to show these fields if the interface is not
        # configured to allocate addresses from a pool
        if interface.ipv4_mode != constants.IPV4_POOL:
            interface.ipv4_pool = wtypes.Unset
        if interface.ipv6_mode != constants.IPV6_POOL:
            interface.ipv6_pool = wtypes.Unset

        datanetworks_names_list = []
        for dn in datanetworks_list:
            dn = pecan.request.dbapi.datanetwork_get(dn)
            datanetworks_names_list.append(dn.name)

        interface.datanetworks = datanetworks_names_list

        return interface


class InterfaceCollection(collection.Collection):
    """API representation of a collection of interfaces."""

    iinterfaces = [Interface]
    "A list containing interface objects"

    def __init__(self, **kwargs):
        self._type = 'iinterfaces'

    @classmethod
    def convert_with_links(cls, rpc_interfaces, limit, url=None,
                           expand=False, **kwargs):
        collection = InterfaceCollection()
        collection.iinterfaces = [Interface.convert_with_links(p, expand)
                                  for p in rpc_interfaces]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'InterfaceController'


class InterfaceController(rest.RestController):
    """REST controller for iinterfaces."""

    ports = port_api.PortController(from_iinterface=True)
    "Expose ports as a sub-element of interface"

    addresses = address.AddressController(parent="iinterfaces")
    "Expose addresses as a sub-element of interface"

    routes = route.RouteController(parent="iinterfaces")
    "Expose routes as a sub-element of interface"

    interface_networks = interface_network.InterfaceNetworkController(
        parent="iinterfaces")
    "Expose interface_networks as a sub-element of interface"

    interface_datanetworks = \
        interface_datanetwork.InterfaceDataNetworkController(
            parent="iinterfaces")
    "Expose interface_datanetworks as a sub-element of interface"

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_ihosts=False):
        self._from_ihosts = from_ihosts

    def _get_interfaces_collection(self, ihost_uuid, marker, limit, sort_key,
                                   sort_dir, expand=False, resource_url=None):
        if self._from_ihosts and not ihost_uuid:
            raise exception.InvalidParameterValue(_(
                "Host id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.interface.get_by_uuid(
                pecan.request.context,
                marker)

        if ihost_uuid:
            interfaces = pecan.request.dbapi.iinterface_get_by_ihost(
                ihost_uuid, limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)
        else:
            interfaces = pecan.request.dbapi.iinterface_get_list(
                limit, marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)

        return InterfaceCollection.convert_with_links(interfaces, limit,
                                                      url=resource_url,
                                                      expand=expand,
                                                      sort_key=sort_key,
                                                      sort_dir=sort_dir)

    @wsme_pecan.wsexpose(InterfaceCollection, wtypes.text, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, ihost=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of interfaces."""

        if uuidutils.is_uuid_like(ihost) or cutils.is_int_like(ihost):
            ihost_id = ihost
        else:
            try:
                host = pecan.request.dbapi.ihost_get(ihost)
                ihost_id = host.uuid
            except exception.SysinvException:
                raise wsme.exc.ClientSideError(_("Invalid ihost %s" % ihost))

        return self._get_interfaces_collection(ihost_id, marker, limit,
                                               sort_key, sort_dir)

    @wsme_pecan.wsexpose(InterfaceCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, ihost_uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of interfaces with detail."""
        # NOTE(lucasagomes): /detail should only work agaist collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "iinterfaces":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['interfaces', 'detail'])
        return self._get_interfaces_collection(ihost_uuid,
                                               marker, limit,
                                               sort_key, sort_dir,
                                               expand, resource_url)

    @wsme_pecan.wsexpose(Interface, types.uuid)
    def get_one(self, interface_uuid):
        """Retrieve information about the given interface."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_interface = objects.interface.get_by_uuid(
            pecan.request.context, interface_uuid)
        return Interface.convert_with_links(rpc_interface)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Interface, body=Interface)
    def post(self, interface):
        """Create a new interface."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        try:
            interface = interface.as_dict()
            new_interface = _create(interface)
        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(str(e))
        except exception.HTTPNotFound:
            raise wsme.exc.ClientSideError(_("Interface create failed: interface %s"
                                             % (interface['ifname'])))
        return Interface.convert_with_links(new_interface)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [InterfacePatchType])
    @wsme_pecan.wsexpose(Interface, types.uuid,
                         body=[InterfacePatchType])
    def patch(self, interface_uuid, patch):
        """Update an existing interface."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        LOG.debug("patch_data: %s" % patch)

        uses = None
        ports = None
        ethernet_port_mac = None
        networks = []
        networks_to_add = []
        interface_networks_to_remove = []
        datanetworks = []
        datanetworks_to_add = []
        interface_datanetworks_to_remove = []
        patches_to_remove = []
        for p in patch:
            if '/ifclass' == p['path']:
                if p['value'] == constants.INTERFACE_CLASS_NONE:
                    p['value'] = None
            elif '/usesmodify' == p['path']:
                uses = p['value'].split(',')
                patches_to_remove.append(p)
            elif '/ports' == p['path']:
                ports = p['value']
                patches_to_remove.append(p)
            elif '/networks' == p['path']:
                networks = p['value'].split(',')
                patches_to_remove.append(p)
            elif '/networks_to_add' == p['path']:
                networks_to_add = p['value'].split(',')
                patches_to_remove.append(p)
            elif '/interface_networks_to_remove' == p['path']:
                interface_networks_to_remove = p['value'].split(',')
                patches_to_remove.append(p)
            elif '/datanetworks' == p['path']:
                datanetworks = p['value'].split(',')
                patches_to_remove.append(p)
            elif '/datanetworks_to_add' == p['path']:
                datanetworks_to_add = p['value'].split(',')
                patches_to_remove.append(p)
            elif '/interface_datanetworks_to_remove' == p['path']:
                interface_datanetworks_to_remove = p['value'].split(',')
                patches_to_remove.append(p)

        if uses:
            patch.append(dict(path='/uses', value=uses, op='replace'))

        patch = [p for p in patch if p not in patches_to_remove]

        LOG.debug("patch_ports: %s" % ports)
        LOG.debug("patch_networks: %s" % networks)

        rpc_interface = objects.interface.get_by_uuid(pecan.request.context,
                                                      interface_uuid)

        # create a temp interface for semantics checks
        temp_interface = copy.deepcopy(rpc_interface)

        if 'forihostid' in rpc_interface:
            ihostId = rpc_interface['forihostid']
        else:
            ihostId = rpc_interface['ihost_uuid']

        ihost = pecan.request.dbapi.ihost_get(ihostId)

        # Check mtu before updating ports
        imtu = None
        for p in patch:
            if '/imtu' in p['path']:
                # Update the imtu to the new value
                if rpc_interface['imtu']:
                    if int(p['value']) != int(rpc_interface['imtu']):
                        imtu = p['value']
                break

        temp_interface['imtu'] = imtu
        LOG.debug("rpc_mtu: %s" % rpc_interface['imtu'])
        _check_interface_mtu(temp_interface.as_dict(), ihost)

        # Check SR-IOV before updating the ports
        for p in patch:
            if '/ifclass' == p['path']:
                temp_interface['ifclass'] = p['value']
            elif '/sriov_numvfs' == p['path']:
                temp_interface['sriov_numvfs'] = p['value']
        # If network type is not pci-sriov, reset the sriov-numvfs to zero
        if (temp_interface['sriov_numvfs'] is not None and
                temp_interface['ifclass'] is not None and
                temp_interface[
                        'ifclass'] != constants.INTERFACE_CLASS_PCI_SRIOV):
            temp_interface['sriov_numvfs'] = None

        sriov_update = _check_interface_sriov(temp_interface.as_dict(), ihost)

        # Get the ethernet port associated with the interface if network type
        # is changed
        interface_ports = pecan.request.dbapi.ethernet_port_get_by_interface(
            rpc_interface.uuid)
        for p in interface_ports:
            if p is not None:
                ports = p.name
                ethernet_port_mac = p.mac
                break

        # Process updates
        vlan_id = None
        delete_addressing = False
        delete_ifdn = False

        for p in patch:
            if '/vlan_id' in p['path']:
                # Update vlan_id to the new value
                if rpc_interface['vlan_id']:
                    if int(p['value']) != int(rpc_interface['vlan_id']):
                        vlan_id = p['value']

        temp_interface['vlan_id'] = vlan_id
        _check_interface_vlan_id("modify", temp_interface.as_dict(), ihost)

        # replace ihost_uuid and iinterface_uuid with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)
        for p in patch_obj:
            if p['path'] == '/ihost_uuid':
                p['path'] = '/forihostid'
                ihost = objects.host.get_by_uuid(pecan.request.context,
                                                 p['value'])
                p['value'] = ihost.id

        try:
            interface = Interface(**jsonpatch.apply_patch(
                rpc_interface.as_dict(),
                patch_obj)).as_dict()
        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # if the aemode is changed adjust the txhashpolicy if necessary
        if interface['aemode'] == 'active_standby':
            interface['txhashpolicy'] = None

        # The variable 'networks' contains a list of networks that the
        # interface should have by the end of this update. These should be
        # compared to the previous networks assigned to the interface
        interface['networks'] = networks

        if (not interface['ifclass'] or
                interface['ifclass'] == constants.INTERFACE_CLASS_NONE):
            # If the interface class is reset, make sure any network
            # specific fields are reset as well
            interface['networktype'] = None
            interface['sriov_numvfs'] = 0
            interface['ipv4_mode'] = None
            interface['ipv6_mode'] = None
            delete_addressing = True
            delete_ifdn = True
        else:
            # Otherwise make sure that appropriate defaults are set.
            interface = _set_defaults(interface)

        # clear address pool values if address mode no longer set to pool
        if interface['ipv4_mode'] != constants.IPV4_POOL:
            interface['ipv4_pool'] = None
        if interface['ipv6_mode'] != constants.IPV6_POOL:
            interface['ipv6_pool'] = None

        interface = _check("modify", interface,
                           ports=ports, ifaces=uses,
                           existing_interface=rpc_interface.as_dict(),
                           datanetworks=datanetworks)

        if uses:
            # Update MAC address if uses list changed
            interface = set_interface_mac(ihost, interface)
            update_upper_interface_macs(ihost, interface)

        if ports:
            _update_ports("modify", rpc_interface, ihost, ports)

        if (not interface['ifclass'] or
                interface['ifclass'] == constants.NETWORK_TYPE_NONE):
            ifclass = None
        else:
            ifclass = interface['ifclass']
        orig_ifclass = rpc_interface['ifclass']
        if (not ifclass and
                orig_ifclass == constants.INTERFACE_CLASS_PLATFORM):
            for network_id in rpc_interface['networks']:
                network = pecan.request.dbapi.network_get_by_id(network_id)
                if network.type == constants.NETWORK_TYPE_MGMT:
                    # Remove mgmt address associated with this interface
                    pecan.request.rpcapi.mgmt_ip_set_by_ihost(
                        pecan.request.context,
                        ihost['uuid'],
                        interface['id'],
                        None)

        if delete_addressing:
            for family in constants.IP_FAMILIES:
                _delete_addressing(interface, family, rpc_interface)
        else:
            if _is_ipv4_address_mode_updated(interface, rpc_interface):
                _update_ipv4_address_mode(interface)
            if _is_ipv6_address_mode_updated(interface, rpc_interface):
                _update_ipv6_address_mode(interface)

        # Update interface-datanetworks
        if datanetworks_to_add:
            for datanetwork_id in datanetworks_to_add:
                values = {'interface_id': interface['id'],
                          'datanetwork_id': datanetwork_id}
                try:
                    pecan.request.dbapi.interface_datanetwork_create(values)
                except exception.InterfaceDataNetworkAlreadyExists:
                    pass
        elif datanetworks:
            _update_interface_datanetworks(
                ihost['uuid'], interface, datanetworks, delete_ifdn)

        try:
            # Remove old datanetworks from the interface
            if interface_datanetworks_to_remove:
                for ifdatanet_id in interface_datanetworks_to_remove:
                    pecan.request.dbapi.interface_datanetwork_destroy(
                        ifdatanet_id)
            elif (orig_ifclass == constants.INTERFACE_CLASS_DATA and
                  (not ifclass or
                   ifclass != constants.INTERFACE_CLASS_DATA)):
                # data networks apply only for DATA
                ifdatanets = \
                    pecan.request.dbapi.interface_datanetwork_get_by_interface(
                        rpc_interface['uuid'])
                for ifdatanet in ifdatanets:
                    pecan.request.dbapi.interface_datanetwork_destroy(ifdatanet.uuid)
        except Exception as e:
            LOG.exception(e)
            msg = _("Failed to remove interface datanetwork association for "
                    "interface %s" % (interface['ifname']))
            raise wsme.exc.ClientSideError(msg)

        # Commit operation with neutron
        if (interface['ifclass'] and
                interface['ifclass'] in NEUTRON_INTERFACE_CLASS):
            _neutron_bind_interface(ihost, interface)
        if (rpc_interface['ifclass'] and
                rpc_interface['ifclass'] in NEUTRON_INTERFACE_CLASS and
                interface['ifclass'] not in NEUTRON_INTERFACE_CLASS):
            _neutron_unbind_interface(ihost, rpc_interface)

        saved_interface = copy.deepcopy(rpc_interface)

        # Update interface-network
        try:
            if networks_to_add:
                for network_id in networks_to_add:
                    values = {'interface_id': interface['id'],
                              'network_id': network_id}
                    pecan.request.dbapi.interface_network_create(values)
            elif networks:
                for network_id in networks:
                    values = {'interface_id': interface['id'],
                              'network_id': network_id}
                    pecan.request.dbapi.interface_network_create(values)
        except exception.InterfaceNetworkAlreadyExists:
            pass
        except Exception as e:
            LOG.exception(e)
            msg = _("Failed to create interface network association for "
                    "interface %s" % (interface['ifname']))
            raise wsme.exc.ClientSideError(msg)

        try:
            # Remove old networks from the interface
            if interface_networks_to_remove:
                for ifnet_id in interface_networks_to_remove:
                    pecan.request.dbapi.interface_network_destroy(ifnet_id)
            elif (orig_ifclass == constants.INTERFACE_CLASS_PLATFORM and
                  (not ifclass or
                   ifclass != constants.INTERFACE_CLASS_PLATFORM)):
                ifnets = pecan.request.dbapi.interface_network_get_by_interface(
                    rpc_interface['uuid'])
                for ifnet in ifnets:
                    pecan.request.dbapi.interface_network_destroy(ifnet.uuid)
        except Exception as e:
            LOG.exception(e)
            msg = _("Failed to remove interface network association for "
                    "interface %s" % (interface['ifname']))
            raise wsme.exc.ClientSideError(msg)

        try:
            # Update only the fields that have changed
            for field in objects.interface.fields:
                if field in rpc_interface.as_dict():
                    if rpc_interface[field] != interface[field]:
                        rpc_interface[field] = interface[field]

            rpc_interface.save()
            # Re-read from the DB to populate extended attributes
            new_interface = objects.interface.get_by_uuid(
                pecan.request.context, rpc_interface.uuid)

            networktypelist = []
            if new_interface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM:
                for network_id in new_interface['networks']:
                    network = pecan.request.dbapi.network_get_by_id(network_id)
                    networktypelist.append(network.type)
            elif new_interface['ifclass']:
                networktypelist = [new_interface['ifclass']]
            else:
                networktypelist = [constants.NETWORK_TYPE_NONE]

            # Update mgmt_ip and mgmt_mac (if required)
            if constants.NETWORK_TYPE_MGMT in networktypelist:
                _update_host_mgmt_address(ihost, interface)
                _update_host_mgmt_mac(ihost, ethernet_port_mac)

            if constants.NETWORK_TYPE_CLUSTER_HOST in networktypelist:
                _update_host_cluster_address(ihost, interface)
            if ihost['personality'] == constants.CONTROLLER:
                if constants.NETWORK_TYPE_OAM in networktypelist:
                    _update_host_oam_address(ihost, interface)
                elif constants.NETWORK_TYPE_PXEBOOT in networktypelist:
                    _update_host_pxeboot_address(ihost, interface)

            # Update the MTU of underlying interfaces of an AE
            if new_interface['iftype'] == constants.INTERFACE_TYPE_AE:
                for ifname in new_interface['uses']:
                    _update_interface_mtu(ifname, ihost, new_interface['imtu'])

                # Restore the default MTU for removed AE members
                old_members = set(saved_interface['uses'])
                new_members = set(new_interface['uses'])
                removed_members = old_members - new_members
                for ifname in removed_members:
                    _update_interface_mtu(ifname, ihost, DEFAULT_MTU)

            # Update shared data interface bindings, if required
            _update_shared_interface_neutron_bindings(ihost, new_interface)
            if sriov_update:
                pecan.request.rpcapi.update_sriov_config(
                    pecan.request.context,
                    ihost['uuid'])

            return Interface.convert_with_links(new_interface)
        except Exception as e:
            LOG.exception(e)
            msg = _("Interface update failed: host %s if %s : patch %s"
                    % (ihost['hostname'], interface['ifname'], patch))
            if (saved_interface['ifclass'] and
                    saved_interface['ifclass'] in NEUTRON_INTERFACE_CLASS):
                # Restore Neutron bindings
                _neutron_bind_interface(ihost, saved_interface)

            # Update shared data interface bindings, if required
            _update_shared_interface_neutron_bindings(ihost, saved_interface)

            raise wsme.exc.ClientSideError(msg)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, interface_uuid):
        """Delete a interface."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        interface = objects.interface.get_by_uuid(pecan.request.context,
                                                  interface_uuid)
        interface = interface.as_dict()

        _delete(interface)


##############
# UTILS
##############

def _update_interface_datanetworks(host_uuid, interface,
                                   datanetworks=None,
                                   delete_ifdn=False):

    pns = []

    if datanetworks:
        # remove 'none' from datanetworks
        datanetworks = \
            [x for x in datanetworks if x != constants.DATANETWORK_TYPE_NONE]
        for datanetwork_id in datanetworks:
            dn = pecan.request.dbapi.datanetwork_get(datanetwork_id)
            pns.append(dn.name)
    elif 'datanetworks' in interface:
        pns = interface['datanetworks']

    LOG.info("_update_interface_datanetworks interface=%s datanetworks=%s pns=%s" %
             (interface, datanetworks, pns))

    # remove from the interface datanetworks not in list
    ifdns = \
        pecan.request.dbapi.interface_datanetwork_get_by_host(
            host_uuid)
    for ifdn in ifdns:
        # if this is not this interface, continue
        if_uuid = interface.get('uuid', None)
        if if_uuid:
            if if_uuid != ifdn.interface_uuid:
                continue
        elif ifdn.ifname != interface.get('ifname'):
            continue

        LOG.debug("_update_interface_datanetworks host_uuid %s "
                  "interface=%s ifdn=%s" %
                  (host_uuid, interface, ifdn.as_dict()))
        if (pns and ifdn.datanetwork_name not in pns) or delete_ifdn:
            LOG.info("interface_datanetwork_destroy %s %s delete_ifdn=%s" %
                     (ifdn.uuid, ifdn.ifname, delete_ifdn))
            pecan.request.dbapi.interface_datanetwork_destroy(
                ifdn.uuid)

    for pn in pns:
        dn = pecan.request.dbapi.datanetwork_get(pn)
        values = {'interface_id': interface['id'],
                  'datanetwork_id': dn.id}
        try:
            ifdn = pecan.request.dbapi.interface_datanetwork_create(values)
        except exception.InterfaceDataNetworkAlreadyExists:
            pass
        except Exception as e:
            LOG.exception(e)
            msg = _("Failed to create interface datanetwork "
                    "assignment for interface %s" %
                    (interface['ifname']))
            raise wsme.exc.ClientSideError(msg)

    return ifdns


def _dynamic_address_allocation():
    mgmt_network = pecan.request.dbapi.network_get_by_type(
        constants.NETWORK_TYPE_MGMT)
    return mgmt_network.dynamic


def _set_address_family_defaults_by_pool(defaults, pool_type):
    pool_uuid = pecan.request.dbapi.network_get_by_type(pool_type).pool_uuid
    pool = pecan.request.dbapi.address_pool_get(pool_uuid)
    if pool.family == constants.IPV4_FAMILY:
        defaults['ipv4_mode'] = constants.IPV4_STATIC
        defaults['ipv6_mode'] = constants.IPV6_DISABLED
    else:
        defaults['ipv6_mode'] = constants.IPV6_STATIC
        defaults['ipv4_mode'] = constants.IPV4_DISABLED


def _set_defaults(interface):
    defaults = {'imtu': DEFAULT_MTU,
                'networktype': constants.NETWORK_TYPE_DATA,
                'aemode': 'active_standby',
                'txhashpolicy': None,
                'vlan_id': None,
                'sriov_numvfs': 0}

    networktypelist = []
    if interface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM:
        if interface['networks']:
            for network_id in interface['networks']:
                network = pecan.request.dbapi.network_get_by_id(network_id)
                networktypelist.append(network.type)
            interface['networktype'] = ",".join(networktypelist)
        elif interface['networktype']:
            networks = []
            networktypelist = interface['networktype'].split(',')
            for network_type in networktypelist:
                if network_type in constants.PLATFORM_NETWORK_TYPES:
                    network = pecan.request.dbapi.network_get_by_type(
                        network_type
                    )
                    networks.append(str(network.id))
            interface['networks'] = networks
    elif interface['ifclass'] in NEUTRON_NETWORK_TYPES:
        interface['networktype'] = interface['ifclass']

    family_defaults = [constants.NETWORK_TYPE_MGMT,
                       constants.NETWORK_TYPE_OAM,
                       constants.NETWORK_TYPE_CLUSTER_HOST]
    if interface['ifclass'] == constants.INTERFACE_CLASS_DATA:
        defaults['ipv4_mode'] = constants.IPV4_DISABLED
        defaults['ipv6_mode'] = constants.IPV6_DISABLED
    else:
        for network_type in networktypelist:
            if network_type in family_defaults:
                _set_address_family_defaults_by_pool(defaults,
                                                     network_type)

    interface_merged = interface.copy()
    for key in interface_merged:
        if interface_merged[key] is None and key in defaults:
            interface_merged[key] = defaults[key]

    return interface_merged


def _check_interface_vlan_id(op, interface, ihost, from_profile=False):
    # Check vlan_id
    if 'vlan_id' in interface.keys() and interface['vlan_id'] is not None:
        if not str(interface['vlan_id']).isdigit():
            raise wsme.exc.ClientSideError(_("VLAN id is an integer value."))

        interface['vlan_id'] = int(interface['vlan_id'])
        if interface['vlan_id'] < 1 or interface['vlan_id'] > 4094:
            raise wsme.exc.ClientSideError(_("VLAN id must be between 1 and 4094."))
        else:
            interface['vlan_id'] = six.text_type(interface['vlan_id'])
    return interface


def _check_interface_name(op, interface, ihost, from_profile=False):
    ihost_id = interface['forihostid']
    ifname = interface['ifname']
    iftype = interface['iftype']

    # Check for ifname that has only spaces
    if ifname and not ifname.strip():
        raise wsme.exc.ClientSideError(_("Interface name cannot be "
                                         "whitespace."))
    # Check that ifname contains only lower case
    if not ifname.islower():
        raise wsme.exc.ClientSideError(_("Interface name must be in "
                                         "lower case."))

    # Check that the ifname is the right character length
    # Account for VLAN interfaces
    iflen = MAX_IFNAME_LEN
    if iftype == constants.INTERFACE_TYPE_VLAN:
        iflen = iflen + MAX_VLAN_ID_LEN
    if ifname and len(ifname) > iflen:
        raise wsme.exc.ClientSideError(_("Interface {} has name length "
                                         "greater than {}.".
                                         format(ifname, iflen)))

    # Check for invalid characters
    vlan_id = None
    if iftype == constants.INTERFACE_TYPE_VLAN:
        vlan_id = interface['vlan_id']
    invalidChars = set(string.punctuation.replace("_", ""))
    if vlan_id is not None:
        # Allow VLAN interfaces to have "." in the name
        invalidChars.remove(".")
    if any(char in invalidChars for char in ifname):
        msg = _("Cannot use special characters in interface name.")
        raise wsme.exc.ClientSideError(msg)

    # ifname must be unique within the host
    if op == "add":
        this_interface_id = 0
    else:
        this_interface_id = interface['id']
    interface_list = pecan.request.dbapi.iinterface_get_all(
        forihostid=ihost_id)
    for i in interface_list:
        if i.id == this_interface_id:
            continue
        if i.ifname == ifname:
            raise wsme.exc.ClientSideError(_("Name must be unique."))
    return interface


def _check_interface_mtu(interface, ihost, from_profile=False):
    # Check imtu
    if 'imtu' in interface.keys() and interface['imtu'] is not None:
        if not str(interface['imtu']).isdigit():
            raise wsme.exc.ClientSideError(_("MTU is an integer value."))

        interface['imtu'] = int(interface['imtu'])
        utils.validate_mtu(interface['imtu'])
    return interface


def _check_interface_sriov(interface, ihost, from_profile=False):
    sriov_update = False

    if 'ifclass' in interface.keys() and not interface['ifclass']:
        return sriov_update

    if (interface['ifclass'] == constants.INTERFACE_CLASS_PCI_SRIOV and
            'sriov_numvfs' not in interface.keys()):
        raise wsme.exc.ClientSideError(_("A network type of pci-sriov must specify "
                                         "a number for SR-IOV VFs."))

    if ('sriov_numvfs' in interface.keys() and interface['sriov_numvfs']
            is not None and int(interface['sriov_numvfs']) > 0 and
            ('ifclass' not in interface.keys() or
             interface['ifclass'] != constants.INTERFACE_CLASS_PCI_SRIOV)):
        raise wsme.exc.ClientSideError(_("Number of SR-IOV VFs is specified "
                                         "but interface class is not "
                                         "pci-sriov."))

    if ('ifclass' in interface.keys() and
            interface['ifclass'] == constants.INTERFACE_CLASS_PCI_SRIOV and
            'sriov_numvfs' in interface.keys()):

        if interface['sriov_numvfs'] is None:
            raise wsme.exc.ClientSideError(_("Value for number of SR-IOV VFs must be specified."))

        if not str(interface['sriov_numvfs']).isdigit():
            raise wsme.exc.ClientSideError(_("Value for number of SR-IOV VFs is an integer value."))

        if interface['sriov_numvfs'] <= 0:
            raise wsme.exc.ClientSideError(_("Value for number of SR-IOV VFs must be > 0."))

        ports = pecan.request.dbapi.ethernet_port_get_all(hostid=ihost['id'])
        port_list = [
            (p.name, p.sriov_totalvfs, p.driver) for p in ports
            if p.interface_id and p.interface_id == interface['id']
        ]

        if len(port_list) != 1:
            raise wsme.exc.ClientSideError(_("At most one port must be enabled."))

        sriov_totalvfs = port_list[0][1]
        if sriov_totalvfs is None or sriov_totalvfs == 0:
            raise wsme.exc.ClientSideError(_("SR-IOV can't be configured on this interface"))

        if int(interface['sriov_numvfs']) > sriov_totalvfs:
            raise wsme.exc.ClientSideError(_("The interface support a maximum of %s VFs" % sriov_totalvfs))

        driver = port_list[0][2]
        if driver is None or not driver:
            raise wsme.exc.ClientSideError(_("Corresponding port has invalid driver"))
        sriov_update = True
    return sriov_update


def _check_host(ihost):
    if utils.is_aio_simplex_host_unlocked(ihost):
        raise wsme.exc.ClientSideError(_("Host must be locked."))
    elif ihost['administrative'] != 'locked' and not \
            utils.is_host_simplex_controller(ihost):
        unlocked = False
        current_ihosts = pecan.request.dbapi.ihost_get_list()
        for h in current_ihosts:
            if h['administrative'] != 'locked' and h['hostname'] != ihost['hostname']:
                unlocked = True
        if unlocked:
            raise wsme.exc.ClientSideError(_("Host must be locked."))


def _check_network_type_validity(networktypelist):
    if any(nt not in VALID_NETWORK_TYPES for nt in networktypelist):
        msg = (_("Network type list may only contain one or more of these "
                 "values: {}").format(', '.join(VALID_NETWORK_TYPES)))
        raise wsme.exc.ClientSideError(msg)


def _check_network_type_and_host_type(ihost, networktypelist):
    for nt in DATA_NETWORK_TYPES:
        if (nt in networktypelist and
                constants.WORKER not in ihost['subfunctions']):
            msg = _("The '%s' network type is only supported on nodes "
                    "supporting worker functions" % nt)
            raise wsme.exc.ClientSideError(msg)

    if (constants.NETWORK_TYPE_OAM in networktypelist and
            ihost['personality'] != constants.CONTROLLER):
        msg = _("The '%s' network type is only supported on controller nodes." %
                constants.NETWORK_TYPE_OAM)
        raise wsme.exc.ClientSideError(msg)


def _check_network_type_and_interface_type(interface, networktypelist):
    if interface['iftype'] == 'vlan':
        if constants.NETWORK_TYPE_NONE in networktypelist:
            msg = _("VLAN interfaces cannot have an interface class of %s." %
                    constants.NETWORK_TYPE_NONE)
            raise wsme.exc.ClientSideError(msg)

    if (any(nt in networktypelist for nt in PCI_NETWORK_TYPES) and
            interface['iftype'] != "ethernet"):
        msg = (_("The {} network types are only valid on Ethernet interfaces").
               format(', '.join(PCI_NETWORK_TYPES)))
        raise wsme.exc.ClientSideError(msg)


def _check_network_type_duplicates(ihost, interface, networktypelist):
    # Check that we are not creating duplicate interface types
    interfaces = pecan.request.dbapi.iinterface_get_by_ihost(ihost['uuid'])
    for host_interface in interfaces:
        if not host_interface['networks']:
            continue
        host_networktypelist = []
        for network_id in host_interface['networks']:
            network = pecan.request.dbapi.network_get_by_id(network_id)
            host_networktypelist.append(network.type)

        for nt in interface_network.NONDUPLICATE_NETWORK_TYPES:
            if nt in host_networktypelist and nt in networktypelist:
                if host_interface['uuid'] != interface['uuid']:
                    msg = _("An interface with '%s' network type is "
                            "already provisioned on this node" % nt)
                    raise wsme.exc.ClientSideError(msg)


def _check_interface_class_transition(interface, existing_interface):
    if not existing_interface:
        return
    ifclass = interface['ifclass']
    existing_ifclass = existing_interface['ifclass']
    if ifclass == existing_ifclass:
        return
    if (ifclass and
            existing_interface[
                'ifclass'] == constants.INTERFACE_CLASS_PLATFORM and
            existing_interface['used_by'] and
            existing_interface['networks']):
        msg = _("The class of an interface with platform networks cannot "
                "be changed to %s since it is being used by %s" %
                (ifclass, existing_interface['used_by']))
        raise wsme.exc.ClientSideError(msg)
    elif (ifclass and ifclass == constants.INTERFACE_CLASS_PLATFORM and
          existing_interface['ifclass'] in NEUTRON_INTERFACE_CLASS and
          existing_interface['used_by']):
        msg = _("The class of a non-platform interface cannot "
                "be changed to platform since it is being used by %s" %
                existing_interface['used_by'])
        raise wsme.exc.ClientSideError(msg)


def _check_network_type_and_interface_name(interface, networktypelist):
    if (utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX and
            constants.NETWORK_TYPE_NONE in networktypelist and
            interface['ifname'] == constants.LOOPBACK_IFNAME):
        msg = _("The loopback interface cannot be changed for an all-in-one "
                "simplex system")
        raise wsme.exc.ClientSideError(msg)


def _check_network_type(op, interface, ihost, existing_interface):
    networktypelist = []
    if interface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM:
        for network_id in interface['networks']:
            network = pecan.request.dbapi.network_get_by_id(network_id)
            networktypelist.append(network.type)
    elif interface['ifclass']:
        networktypelist.append(interface['ifclass'])
    else:
        networktypelist.append(constants.INTERFACE_CLASS_NONE)

    _check_network_type_validity(networktypelist)
    _check_interface_class_transition(interface, existing_interface)
    _check_network_type_and_host_type(ihost, networktypelist)
    _check_network_type_and_interface_type(interface, networktypelist)
    _check_network_type_duplicates(ihost, interface, networktypelist)
    _check_network_type_and_interface_name(interface, networktypelist)


def _check_network_type_and_port(interface, ihost,
                                 interface_port,
                                 host_port,
                                 networktypelist):
    if interface_port.pciaddr == host_port.pciaddr and \
                    interface_port.dev_id != host_port.dev_id:
        pif = pecan.request.dbapi.iinterface_get(host_port.interface_id)
        if interface['id'] == pif['id']:
            return
        # shared devices cannot be assigned to a data and non-data
        # interface at the same time
        pif_networktypelist = []
        if pif.networktype is None and pif.used_by:
            for name in pif.used_by:
                used_by_if = pecan.request.dbapi.iinterface_get(name,
                                                                ihost['uuid'])
                if used_by_if and used_by_if.networktype:
                    pif_networktypelist = cutils.get_network_type_list(used_by_if)
        elif pif.networktype:
            pif_networktypelist = cutils.get_network_type_list(pif)
        if (pif_networktypelist and
                ((constants.NETWORK_TYPE_DATA in pif_networktypelist and
                    constants.NETWORK_TYPE_DATA not in networktypelist) or
                    (constants.NETWORK_TYPE_DATA not in pif_networktypelist and
                        constants.NETWORK_TYPE_DATA in networktypelist))):
            msg = (_("Shared device %(device)s cannot be shared "
                     "with different network types when device "
                     "is associated with a data network type") %
                   {'device': interface_port.pciaddr})
            raise wsme.exc.ClientSideError(msg)


def _check_interface_class(interface, existing_interface):
    if not interface['ifclass'] or interface['ifclass'] == constants.INTERFACE_CLASS_NONE:
        return

    if interface['ifclass'] not in VALID_INTERFACE_CLASS:
        msg = (_("Invalid interface class %s" % interface['ifclass']))
        raise wsme.exc.ClientSideError(msg)

    if interface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM:
        for network_id in interface['networks']:
            network = pecan.request.dbapi.network_get_by_id(network_id)
            if network.type not in constants.PLATFORM_NETWORK_TYPES:
                msg = (_("Invalid network type %s for interface class %s" %
                         (network.type, interface['ifclass'])))
                raise wsme.exc.ClientSideError(msg)

    if (interface['ifclass'] in NEUTRON_INTERFACE_CLASS and
            interface['networks']):
        msg = _("Associating platform network to interface with %s class "
                "is not allowed" % interface['ifclass'])
        raise wsme.exc.ClientSideError(msg)


def _check_address_mode(op, interface, ihost, existing_interface):
    # Check for valid values:
    interface_id = interface['id']
    ipv4_mode = interface.get('ipv4_mode')
    ipv6_mode = interface.get('ipv6_mode')
    object_utils.ipv4_mode_or_none(ipv4_mode)
    object_utils.ipv6_mode_or_none(ipv6_mode)

    # Check for supported interface network types
    networktypelist = []
    if interface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM:
        for network_id in interface['networks']:
            network = pecan.request.dbapi.network_get_by_id(network_id)
            networktypelist.append(network.type)
    elif interface['ifclass']:
        networktypelist.append(interface['ifclass'])
    else:
        networktypelist.append(constants.INTERFACE_CLASS_NONE)

    if not any(network_type in address.ALLOWED_NETWORK_TYPES
               for network_type in networktypelist):
        if (ipv4_mode and ipv4_mode != constants.IPV4_DISABLED):
            raise exception.AddressModeOnlyOnSupportedTypes(
                types=", ".join(address.ALLOWED_NETWORK_TYPES))
        if (ipv6_mode and ipv6_mode != constants.IPV6_DISABLED):
            raise exception.AddressModeOnlyOnSupportedTypes(
                types=", ".join(address.ALLOWED_NETWORK_TYPES))

    # Check for valid combinations of mode+pool
    ipv4_pool = interface.get('ipv4_pool')
    ipv6_pool = interface.get('ipv6_pool')
    if ipv4_mode != constants.IPV4_POOL and ipv4_pool:
        raise exception.AddressPoolRequiresAddressMode(
            family=constants.IP_FAMILIES[constants.IPV4_FAMILY])

    if ipv4_mode == constants.IPV4_POOL:
        if not ipv4_pool:
            raise exception.AddressPoolRequired(
                family=constants.IP_FAMILIES[constants.IPV4_FAMILY])
        pool = pecan.request.dbapi.address_pool_get(ipv4_pool)
        if pool['family'] != constants.IPV4_FAMILY:
            raise exception.AddressPoolFamilyMismatch()
        # Convert to UUID
        ipv4_pool = pool['uuid']
        interface['ipv4_pool'] = ipv4_pool

    if ipv6_mode != constants.IPV6_POOL and ipv6_pool:
        raise exception.AddressPoolRequiresAddressMode(
            family=constants.IP_FAMILIES[constants.IPV6_FAMILY])

    if ipv6_mode == constants.IPV6_POOL:
        if not ipv6_pool:
            raise exception.AddressPoolRequired(
                family=constants.IP_FAMILIES[constants.IPV6_FAMILY])
        pool = pecan.request.dbapi.address_pool_get(ipv6_pool)
        if pool['family'] != constants.IPV6_FAMILY:
            raise exception.AddressPoolFamilyMismatch()
        # Convert to UUID
        ipv6_pool = pool['uuid']
        interface['ipv6_pool'] = ipv6_pool

    if existing_interface:
        # Check for valid transitions
        existing_ipv4_mode = existing_interface.get('ipv4_mode')
        if ipv4_mode != existing_ipv4_mode:
            if (existing_ipv4_mode == constants.IPV4_STATIC and
                    (ipv4_mode and ipv4_mode != constants.IPV4_DISABLED)):
                if pecan.request.dbapi.addresses_get_by_interface(
                        interface_id, constants.IPV4_FAMILY):
                    raise exception.AddressesStillExist(
                        family=constants.IP_FAMILIES[constants.IPV4_FAMILY])

        existing_ipv6_mode = existing_interface.get('ipv6_mode')
        if ipv6_mode != existing_ipv6_mode:
            if (existing_ipv6_mode == constants.IPV6_STATIC and
                    (ipv6_mode and ipv6_mode != constants.IPV6_DISABLED)):
                if pecan.request.dbapi.addresses_get_by_interface(
                        interface_id, constants.IPV6_FAMILY):
                    raise exception.AddressesStillExist(
                        family=constants.IP_FAMILIES[constants.IPV6_FAMILY])


def _check_networks(interface):
    NONASSIGNABLE_WITH_OAM = [constants.NETWORK_TYPE_MGMT,
                              constants.NETWORK_TYPE_PXEBOOT,
                              constants.NETWORK_TYPE_CLUSTER_HOST]
    ifclass = interface['ifclass']
    networks = interface['networks']
    if ifclass == constants.INTERFACE_CLASS_PLATFORM and len(networks) > 1:
        networktypelist = []
        for network_id in networks:
            network = pecan.request.dbapi.network_get_by_id(network_id)
            networktypelist.append(network.type)
        if constants.NETWORK_TYPE_PXEBOOT in networktypelist:
            msg = _("An interface assigned with a network of "
                    "type '%s' cannot contain additional networks."
                    % constants.NETWORK_TYPE_PXEBOOT)
            raise wsme.exc.ClientSideError(msg)
        elif any(network_type in NONASSIGNABLE_WITH_OAM
                 for network_type in networktypelist) and \
                any(network_type == constants.NETWORK_TYPE_OAM
                    for network_type in networktypelist):
            msg = _("An interface assigned with a network of "
                    "type '%s' cannot assign any networks "
                    "of type '%s'."
                    % (constants.NETWORK_TYPE_OAM, NONASSIGNABLE_WITH_OAM))
            raise wsme.exc.ClientSideError(msg)


def _check_datanetworks(ihost,
                        interface,
                        interface_list,
                        existing_interface,
                        networktypelist,
                        datanetworks=None):

    if 'id' in interface:
        this_interface_id = interface['id']
    else:
        this_interface_id = 0

    ifclass = interface['ifclass']
    iftype = interface['iftype']

    if not datanetworks:
        datanetworks = interface.get('datanetworks') or []

    # remove 'none' from datanetworks
    datanetworks = \
        [x for x in datanetworks if x != constants.DATANETWORK_TYPE_NONE]

    LOG.debug("_check_datanetworks datanetworks interface=%s datanetworks=%s" %
              (interface, datanetworks))

    # Get all provisioned datanetworks
    all_datanetworks = {}
    db_datanetworks = pecan.request.dbapi.datanetworks_get_all()
    for db in db_datanetworks:
        all_datanetworks[db.name] = {
            'network_type': db.network_type}

    # Ensure a valid datanetwork is specified
    # Ensure at least one datanetwork is selected for 'data',
    #    and none for 'oam', 'mgmt' and 'cluster-host'
    # Ensure uniqueness of the datanetworks

    datanetworks_list = []
    for datanetwork in datanetworks:
        if datanetwork == constants.DATANETWORK_TYPE_NONE:
            continue
        dn = pecan.request.dbapi.datanetwork_get(datanetwork)
        datanetworks_list.append(dn.name)

    if interface['ifclass'] in NEUTRON_INTERFACE_CLASS:
        if not datanetworks:
            msg = _("At least one data network must be selected.")
            raise wsme.exc.ClientSideError(msg)
        if len(datanetworks) > MAX_DATANETWORK_LEN:
            msg = _("Data network list must not exceed %d characters." %
                    MAX_DATANETWORK_LEN)
            raise wsme.exc.ClientSideError(msg)

        for pn in [n.strip() for n in datanetworks_list]:
            if pn not in all_datanetworks.keys():
                msg = _("Data network '%s' does not exist." % pn)
                raise wsme.exc.ClientSideError(msg)
            if datanetworks_list.count(pn) > 1:
                msg = (_("Specifying duplicate data network '%(name)s' "
                         "is not permitted") % {'name': pn})
                raise wsme.exc.ClientSideError(msg)
            datanet = all_datanetworks[pn]
            if iftype == constants.INTERFACE_TYPE_VLAN:
                if datanet['network_type'] == \
                        constants.DATANETWORK_TYPE_VLAN:
                    msg = _("VLAN based data network '%s' cannot be "
                            "assigned to a VLAN interface" % pn)
                    raise wsme.exc.ClientSideError(msg)

            # If pxeboot, Mgmt network types are consolidated
            # with a data network type on the same interface,
            # in which case, they would be the primary network
            # type. Ensure that the only data type that
            # can be assigned is VLAN.
            if (datanet['network_type'] != constants.DATANETWORK_TYPE_VLAN and
                    ifclass not in NEUTRON_NETWORK_TYPES):
                msg = _("Data network '%s' of type '%s' cannot be assigned "
                        "to an interface with interface class '%s'"
                        % (pn, datanet['network_type'], ifclass))
                raise wsme.exc.ClientSideError(msg)

        # This ensures that a specific data network type can
        # only be assigned to 1 data interface. Such as the case of
        # when only 1 vxlan data is required when SDN is enabled
        if constants.NETWORK_TYPE_DATA in networktypelist and interface_list:
            for pn in [n.strip() for n in datanetworks_list]:
                for i in interface_list:
                    if i.id == this_interface_id:
                        continue
                    if not i.ifclass or not i.datanetworks:
                        continue
                    if constants.NETWORK_TYPE_DATA != i.ifclass:
                        continue

                    other_datanetworks = []
                    for datanetwork in i.datanetworks:
                        dn = pecan.request.dbapi.datanetwork_get(datanetwork)
                        other_datanetworks.append(dn.name)
                    if pn in other_datanetworks:
                        msg = _("Data interface %(ifname)s is already "
                                "attached to this Data Network: "
                                "%(datanetwork)s." %
                                {'ifname': i.ifname, 'datanetwork': pn})
                        raise wsme.exc.ClientSideError(msg)

    elif (not _neutron_providernet_extension_supported() and
          any(nt in PCI_NETWORK_TYPES for nt in networktypelist)):
        # When the neutron implementation is not our own and it does not
        # support our data network extension we still want to do minimal
        # validation of the data network list but we cannot do more
        # complex validation because we do not have any additional information
        # about the data networks.
        if not datanetworks:
            msg = _("At least one data network must be selected.")
            raise wsme.exc.ClientSideError(msg)

    elif (interface['ifclass'] and
            interface['ifclass'] not in NEUTRON_INTERFACE_CLASS and
            not existing_interface):
        if datanetworks:
            msg = _("Data network(s) not supported "
                    "for non-data interfaces. (%s) (%s)" %
                    (interface['ifclass'], str(existing_interface)))
            raise wsme.exc.ClientSideError(msg)
    elif (_neutron_providernet_extension_supported() or
          interface['ifclass'] not in NEUTRON_INTERFACE_CLASS):
        interface['datanetworks'] = None


def _check_interface_data(op, interface, ihost, existing_interface,
                          datanetworks=None):
    # Get data
    ihost_id = interface['forihostid']
    ihost_uuid = interface['ihost_uuid']
    ifclass = interface['ifclass']
    networktypelist = []
    if ifclass == constants.INTERFACE_CLASS_PLATFORM:
        for network_id in interface['networks']:
            platform_network = pecan.request.dbapi.network_get_by_id(network_id)
            networktypelist.append(platform_network.type)
    elif ifclass:
        networktypelist.append(ifclass)
    else:
        networktypelist.append(constants.INTERFACE_CLASS_NONE)

    # Check interface name for validity
    _check_interface_name(op, interface, ihost, existing_interface)

    if op == "add":
        this_interface_id = 0
    else:
        this_interface_id = interface['id']

    iftype = interface['iftype']

    # Check vlan interfaces
    if iftype == constants.INTERFACE_TYPE_VLAN:
        vlan_id = interface['vlan_id']
        lower_ifname = interface['uses'][0]
        lower_iface = (
            pecan.request.dbapi.iinterface_get(lower_ifname, ihost_uuid))
        if lower_iface['iftype'] == constants.INTERFACE_TYPE_VLAN:
            msg = _("VLAN interfaces cannot be created over existing "
                    "VLAN interfaces")
            raise wsme.exc.ClientSideError(msg)
        vlans = _get_interface_vlans(ihost_uuid, lower_iface)
        if op != "modify" and str(vlan_id) in vlans.split(","):
            msg = _("VLAN id %s already in use on interface %s" %
                    (str(vlan_id), lower_iface['ifname']))
            raise wsme.exc.ClientSideError(msg)
        if (lower_iface['ifclass'] == constants.INTERFACE_CLASS_DATA and
                interface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM):
            msg = _("Platform VLAN interface cannot be created over a data "
                    "interface ")
            raise wsme.exc.ClientSideError(msg)
        elif (lower_iface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM and
                interface['ifclass'] == constants.INTERFACE_CLASS_DATA):
            msg = _("Data VLAN interface cannot be created over a platform "
                    "interface ")
            raise wsme.exc.ClientSideError(msg)

    # Check if the 'uses' interface is already used by another AE or VLAN
    # interface
    interface_list = pecan.request.dbapi.iinterface_get_all(
        forihostid=ihost_id)
    for i in interface_list:
        if i.id == this_interface_id:
            continue
        if (iftype != constants.INTERFACE_TYPE_ETHERNET and
                i.uses is not None):
            for p in i.uses:
                parent = pecan.request.dbapi.iinterface_get(p, ihost_uuid)
                if (parent.uuid in interface['uses'] or
                        parent.ifname in interface['uses']):
                    if i.iftype == constants.INTERFACE_TYPE_AE:
                        msg = _("Interface '{}' is already used by another"
                                " AE interface '{}'".format(p, i.ifname))
                        raise wsme.exc.ClientSideError(msg)
                    elif (i.iftype == constants.INTERFACE_TYPE_VLAN and
                            iftype != constants.INTERFACE_TYPE_VLAN):
                        msg = _("Interface '{}' is already used by another"
                                " VLAN interface '{}'".format(p, i.ifname))
                        raise wsme.exc.ClientSideError(msg)

    # Ensure that the interfaces being used in the AE interface
    # are originally set to None when creating the AE interface
    if iftype == constants.INTERFACE_TYPE_AE:
        for i in interface['uses']:
            iface_lower = pecan.request.dbapi.iinterface_get(i, ihost_uuid)
            if iface_lower.ifclass:
                msg = _("All interfaces being used in an AE interface "
                        "must have the interface class set to 'none'.")
                raise wsme.exc.ClientSideError(msg)

    # Ensure that the interfaces being used in the AE interface
    # are not changed after the AE interface has been created
    if interface['used_by']:
        for i in interface['used_by']:
            iface = pecan.request.dbapi.iinterface_get(i, ihost_uuid)
            if iface.iftype == constants.INTERFACE_TYPE_AE and \
                    interface['ifclass']:
                msg = _("Interface '{}' is being used by interface '{}' "
                        "as an AE interface and therefore the interface "
                        "class cannot be changed from 'none'.".format(interface['ifname'],
                                                                      iface.ifname))
                raise wsme.exc.ClientSideError(msg)

    # check interface class validity
    _check_interface_class(interface, existing_interface)

    # check networktype combinations and transitions for validity
    _check_network_type(op, interface, ihost, existing_interface)

    # check to ensure that the interface assigned with an OAM or
    # PXEBOOT network has no other networks
    _check_networks(interface)

    # check mode/pool combinations and transitions for validity
    _check_address_mode(op, interface, ihost, existing_interface)

    # Make sure txhashpolicy for data is layer2
    aemode = interface['aemode']
    txhashpolicy = interface['txhashpolicy']

    if aemode in ['balanced', '802.3ad'] and not txhashpolicy:
        msg = _("Device interface with interface type 'aggregated ethernet' "
                "in 'balanced' or '802.3ad' mode require a valid Tx Hash "
                "Policy.")
        raise wsme.exc.ClientSideError(msg)
    elif aemode in ['active_standby'] and txhashpolicy is not None:
        msg = _("Device interface with interface type 'aggregated ethernet' "
                "in '%s' mode should not specify a Tx Hash Policy." % aemode)
        raise wsme.exc.ClientSideError(msg)

    # Make sure interface type is valid
    supported_type = [constants.INTERFACE_TYPE_AE,
                      constants.INTERFACE_TYPE_VLAN,
                      constants.INTERFACE_TYPE_ETHERNET,
                      constants.INTERFACE_TYPE_VIRTUAL]
    if not iftype or iftype not in supported_type:
        msg = (_("Device interface type must be one of "
                 "{}").format(', '.join(supported_type)))
        raise wsme.exc.ClientSideError(msg)

    # Make sure network type 'data' with if type 'ae' can only be in ae mode
    # 'active_standby', 'balanced', or '802.3ad', and can only support a
    # txhashpolicy of 'layer2'.
    for nt in DATA_NETWORK_TYPES:
        if iftype == 'ae' and nt in networktypelist:
            if aemode not in ['balanced', 'active_standby', '802.3ad']:
                msg = _("Device interface with network type '%s', and interface "
                        "type 'aggregated ethernet' must be in mode "
                        "'active_standby', 'balanced', or '802.3ad'." % nt)
                raise wsme.exc.ClientSideError(msg)
            if aemode in ['balanced', '802.3ad'] and txhashpolicy != 'layer2':
                msg = _("Device interface with network type '%s', and interface "
                        "type 'aggregated ethernet' must have a Tx Hash Policy of "
                        "'layer2'." % nt)
                raise wsme.exc.ClientSideError(msg)

    # Make sure network type 'mgmt', with if type 'ae',
    # can only be in ae mode 'active_standby' or '802.3ad'
    valid_mgmt_aemode = ['802.3ad', 'active_standby']
    if (constants.NETWORK_TYPE_MGMT in networktypelist and iftype == 'ae' and
            aemode not in valid_mgmt_aemode):
        msg = _("Device interface with network type {}, and interface "
                "type 'aggregated ethernet' must be in mode {}").format(
            (str(networktypelist)), ', '.join(valid_mgmt_aemode))
        raise wsme.exc.ClientSideError(msg)

    # Make sure network type 'oam' or 'cluster-host', with if type 'ae',
    # can only be in ae mode 'active_standby' or 'balanced' or '802.3ad'
    if (any(network in [constants.NETWORK_TYPE_OAM, constants.NETWORK_TYPE_CLUSTER_HOST] for network in networktypelist) and
            iftype == 'ae' and (aemode not in VALID_AEMODE_LIST)):
        msg = _("Device interface with network type '%s', and interface "
                "type 'aggregated ethernet' must be in mode 'active_standby' "
                "or 'balanced' or '802.3ad'." % (str(networktypelist)))
        raise wsme.exc.ClientSideError(msg)

    # Ensure that data and non-data interfaces are not using the same
    # shared device
    if (iftype != constants.INTERFACE_TYPE_VLAN and
            iftype != constants.INTERFACE_TYPE_VIRTUAL):
        port_list_host = \
            pecan.request.dbapi.ethernet_port_get_all(hostid=ihost['id'])
        for name in interface['uses']:
            uses_if = pecan.request.dbapi.iinterface_get(name, ihost['uuid'])
            uses_if_port = pecan.request.dbapi.ethernet_port_get_all(
                interfaceid=uses_if.id)
            for interface_port in uses_if_port:
                for host_port in port_list_host:
                    _check_network_type_and_port(interface, ihost,
                                                 interface_port,
                                                 host_port,
                                                 networktypelist)

    # Check datanetworks (formerly known as providernetworks)
    _check_datanetworks(ihost,
                        interface,
                        interface_list,
                        existing_interface,
                        networktypelist,
                        datanetworks)

    # check MTU
    if interface['iftype'] == constants.INTERFACE_TYPE_VLAN:
        vlan_mtu = interface['imtu']
        for name in interface['uses']:
            parent = pecan.request.dbapi.iinterface_get(name, ihost_uuid)
            if int(vlan_mtu) > int(parent['imtu']):
                msg = _("VLAN MTU (%s) cannot be larger than MTU of "
                        "underlying interface (%s)" % (vlan_mtu, parent['imtu']))
                raise wsme.exc.ClientSideError(msg)
    elif interface['used_by']:
        mtus = _get_interface_mtus(ihost_uuid, interface)
        for mtu in mtus:
            if int(interface['imtu']) < int(mtu):
                msg = _("Interface MTU (%s) cannot be smaller than the "
                        "interface MTU (%s) using this interface" %
                        (interface['imtu'], mtu))
                raise wsme.exc.ClientSideError(msg)

    # Check if cluster-host exists on controller, if it doesn't then fail
    if (ihost['personality'] != constants.CONTROLLER and
            constants.NETWORK_TYPE_CLUSTER_HOST in networktypelist):
        host_list = pecan.request.dbapi.ihost_get_by_personality(
            personality=constants.CONTROLLER)
        cluster_host_on_controller = False
        for h in host_list:
            # find any interface in controller host that is of type cluster-host
            interfaces = pecan.request.dbapi.iinterface_get_by_ihost(ihost=h['uuid'])
            for host_interface in interfaces:
                if host_interface['ifclass']:
                    hi_networktypelist = []
                    if host_interface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM:
                        for network_id in host_interface['networks']:
                            network = pecan.request.dbapi.network_get_by_id(network_id)
                            hi_networktypelist.append(network.type)
                    else:
                        hi_networktypelist.append(host_interface['ifclass'])
                    if constants.NETWORK_TYPE_CLUSTER_HOST in hi_networktypelist:
                        cluster_host_on_controller = True
                        break
            if cluster_host_on_controller is True:
                break
        if not cluster_host_on_controller:
            msg = _("Interface %s does not have associated"
                    " cluster-host interface on controller." % interface['ifname'])
            raise wsme.exc.ClientSideError(msg)

    return interface


def _check_ports(op, interface, ihost, ports):
    port_list = []

    if ports:
        port_list = ports.split(',')

    if op == "add":
        this_interface_id = 0
    else:
        this_interface_id = interface['id']

    # Basic checks on number of ports for Ethernet vs Aggregated Ethernet
    if not port_list or len(port_list) == 0:
        raise wsme.exc.ClientSideError(_("A port must be selected."))
    elif (interface['iftype'] == constants.INTERFACE_TYPE_ETHERNET and
            len(port_list) > 1):
        raise wsme.exc.ClientSideError(_(
            "For Ethernet, select a single port."))

    # Make sure that no other interface is currently using these ports
    host_ports = pecan.request.dbapi.ethernet_port_get_all(hostid=ihost['id'])
    for p in host_ports:
        if p.name in port_list or p.uuid in port_list:
            if p.interface_id and p.interface_id != this_interface_id:
                pif = pecan.request.dbapi.iinterface_get(p.interface_id)
                msg = _("Another interface %s is already using this port"
                        % pif.uuid)
                raise wsme.exc.ClientSideError(msg)

        # If someone enters name with spaces anywhere, such as " eth2", "eth2 "
        # The the bottom line will prevent it
        if p.name == "".join(interface['ifname'].split()):

            if interface['iftype'] == 'ae':
                msg = _("Aggregated Ethernet interface name cannot be '%s'. "
                        "An Aggregated Ethernet name must not be the same as"
                        " an existing port name. " % p.name)
                raise wsme.exc.ClientSideError(msg)

            if (p.uuid not in port_list) and (p.name not in port_list):
                msg = _("Interface name cannot be '%s'. Port name can be "
                        "used as interface name only if the interface uses"
                        " that port. " % p.name)
                raise wsme.exc.ClientSideError(msg)

    # Check to see if the physical port actually exists
    for p in port_list:
        port_exists = False
        for pTwo in host_ports:
            if p == pTwo.name or p == pTwo.uuid:
                # port exists
                port_exists = True
                break

        if not port_exists:
            # Port does not exist
            msg = _("Port %s does not exist." % p)
            raise wsme.exc.ClientSideError(msg)

    # Semantic check not needed as the node is locked
    # Make sure the Boot IF is not removed from the management interface
    # networktype = interface['networktype']
    # if networktype == constants.NETWORK_TYPE_MGMT:
    #    for p in port_list:
    #        if (p.uuid in ports or p.name in ports) and p.bootp:
    #            break
    #   else:
    #       msg = _("The boot interface can NOT be removed from the mgmt interface.")
    #       raise wsme.exc.ClientSideError(msg)

    # Perform network type checks for shared PCI devices.
    networktypelist = []
    if interface['networktype']:
        networktypelist = cutils.get_network_type_list(interface)
    if constants.NETWORK_TYPE_NONE not in networktypelist:
        for p in port_list:
            interface_port = \
                pecan.request.dbapi.ethernet_port_get(p, ihost['id'])
            for host_port in host_ports:
                _check_network_type_and_port(interface, ihost,
                                             interface_port,
                                             host_port,
                                             networktypelist)


def _update_address_mode(interface, family, mode, pool):
    interface_id = interface['id']
    pool_id = pecan.request.dbapi.address_pool_get(pool)['id'] if pool else None
    try:
        # retrieve the existing value and compare
        existing = pecan.request.dbapi.address_mode_query(
            interface_id, family)
        if existing.mode == mode:
            if (mode != 'pool' or existing.pool_uuid == pool):
                return
        if existing.mode == 'pool' or (not mode or mode == 'disabled'):
            pecan.request.dbapi.routes_destroy_by_interface(
                interface_id, family)
            pecan.request.dbapi.addresses_destroy_by_interface(
                interface_id, family)
    except exception.AddressModeNotFoundByFamily:
        # continue and update DB with new record
        pass
    updates = {'family': family, 'mode': mode, 'address_pool_id': pool_id}
    pecan.request.dbapi.address_mode_update(interface_id, updates)


def _delete_addressing(interface, family, existing_interface):
    interface_id = interface['id']
    pecan.request.dbapi.routes_destroy_by_interface(
        interface_id, family)
    for network_id in existing_interface['networks']:
        network = pecan.request.dbapi.network_get_by_id(network_id)
        orig_networktype = network.type
        if ((orig_networktype == constants.NETWORK_TYPE_OAM) or
                (orig_networktype == constants.NETWORK_TYPE_PXEBOOT)):
            pecan.request.dbapi.addresses_remove_interface_by_interface(
                interface['id']
            )
        elif ((orig_networktype != constants.NETWORK_TYPE_MGMT) and
              (orig_networktype != constants.NETWORK_TYPE_CLUSTER_HOST)):
            pecan.request.dbapi.addresses_destroy_by_interface(
                interface_id, family)
    pecan.request.dbapi.address_modes_destroy_by_interface(
        interface_id, family)


def _allocate_pool_address(interface_id, pool_uuid, address_name=None):
    address_pool.AddressPoolController.assign_address(
        interface_id, pool_uuid, address_name)


def _update_ipv6_address_mode(interface, mode=None, pool=None,
                              from_profile=False):
    mode = interface['ipv6_mode'] if not mode else mode
    pool = interface['ipv6_pool'] if not pool else pool
    _update_address_mode(interface, constants.IPV6_FAMILY, mode, pool)
    if mode == constants.IPV6_POOL and not from_profile:
        _allocate_pool_address(interface['id'], pool)


def _update_ipv4_address_mode(interface, mode=None, pool=None,
                              interface_profile=False):
    mode = interface['ipv4_mode'] if not mode else mode
    pool = interface['ipv4_pool'] if not pool else pool
    _update_address_mode(interface, constants.IPV4_FAMILY, mode, pool)
    if mode == constants.IPV4_POOL and not interface_profile:
        _allocate_pool_address(interface['id'], pool)


def _is_ipv4_address_mode_updated(interface, existing_interface):
    if interface['ipv4_mode'] != existing_interface['ipv4_mode']:
        return True
    if interface['ipv4_pool'] != existing_interface['ipv4_pool']:
        return True
    return False


def _is_ipv6_address_mode_updated(interface, existing_interface):
    if interface['ipv6_mode'] != existing_interface['ipv6_mode']:
        return True
    if interface['ipv6_pool'] != existing_interface['ipv6_pool']:
        return True
    return False


def _add_extended_attributes(ihost, interface, attributes):
    """
    Adds additional attributes to a newly create interface database instance.
    The attributes argument is actually the interface object as it was
    received on the initial API post() request with some additional values
    that got added before sending the object to the database.
    """
    interface_data = interface.as_dict()
    networktype = interface_data['networktype']
    if networktype not in address.ALLOWED_NETWORK_TYPES:
        # No need to create new address mode records if the interface type
        # does not support it
        return
    if attributes.get('ipv4_mode'):
        _update_ipv4_address_mode(interface_data,
                                  attributes.get('ipv4_mode'),
                                  attributes.get('ipv4_pool'),
                                  attributes.get('interface_profile'))
    if attributes.get('ipv6_mode'):
        _update_ipv6_address_mode(interface_data,
                                  attributes.get('ipv6_mode'),
                                  attributes.get('ipv6_pool'),
                                  attributes.get('interface_profile'))


def _update_ports(op, interface, ihost, ports):
    port_list = ports.split(',')

    if op == "add":
        this_interface_id = 0
    else:
        this_interface_id = interface['id']

    # Update Ports' iinterface_uuid attribute
    host_ports = pecan.request.dbapi.ethernet_port_get_all(hostid=ihost['id'])
    if port_list:
        for p in host_ports:
            # if new port associated
            if (p.uuid in port_list or p.name in port_list) and \
                    not p.interface_id:
                values = {'interface_id': interface['id']}
            # else if old port disassociated
            elif ((p.uuid not in port_list and p.name not in port_list) and
                      p.interface_id and p.interface_id == this_interface_id):
                values = {'interface_id': None}
            # else move on
            else:
                continue
            try:
                pecan.request.dbapi.port_update(p.uuid, values)
            except exception.HTTPNotFound:
                msg = _("Port update of interface uuid failed: host %s port %s"
                        % (ihost['hostname'], p.name))
                raise wsme.exc.ClientSideError(msg)


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


def _update_host_oam_address(host, interface):
    if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
        address_name = cutils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                                  constants.NETWORK_TYPE_OAM)
    else:
        address_name = cutils.format_address_name(host.hostname,
                                                  constants.NETWORK_TYPE_OAM)
    address = pecan.request.dbapi.address_get_by_name(address_name)
    if not interface['networktype']:
        updates = {'interface_id': None}
    else:
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
        cluster_host_pool_uuid = pecan.request.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_CLUSTER_HOST
        ).pool_uuid
        _allocate_pool_address(interface['id'], cluster_host_pool_uuid,
                               address_name)


def _get_interface_vlans(ihost_uuid, interface):
    """
    Retrieve the VLAN id values (if any) that are dependent on this
    interface.
    """
    used_by = interface['used_by']
    vlans = []
    for ifname in used_by:
        child = pecan.request.dbapi.iinterface_get(ifname, ihost_uuid)
        if child.get('iftype') != constants.INTERFACE_TYPE_VLAN:
            continue
        vlan_id = child.get('vlan_id', 0)
        if vlan_id:
            vlans.append(str(vlan_id))
    return ','.join(vlans)


def _get_interface_mtus(ihost_uuid, interface):
    """
    Retrieve the MTU values of interfaces that are dependent on this
    interface.
    """
    used_by = interface['used_by']
    mtus = []
    for ifname in used_by:
        child = pecan.request.dbapi.iinterface_get(ifname, ihost_uuid)
        mtu = child.get('imtu', 0)
        if mtu:
            mtus.append(str(mtu))
    return mtus


def _update_interface_mtu(ifname, host, mtu):
    """Update the MTU of the interface on this host with the supplied ifname"""
    interface = pecan.request.dbapi.iinterface_get(ifname, host['uuid'])
    values = {'imtu': mtu}
    pecan.request.dbapi.iinterface_update(interface['uuid'], values)


def _get_shared_data_interfaces(ihost, interface):
    """
    Retrieve a list of data interfaces, if any, that are dependent on
    this interface (used_by) as well as the data interface(s) that
    this interface depends on (uses).
    """
    used_by = []
    shared_data_interfaces = []
    uses = interface['uses']
    if uses:
        for ifname in uses:
            parent = pecan.request.dbapi.iinterface_get(ifname, ihost['uuid'])
            used_by.extend(parent['used_by'])
            interface_class = parent.get('ifclass', None)
            if interface_class:
                # This should only match 'data' interface class since that
                # is the only type that can be shared on multiple interfaces.
                if interface_class == constants.INTERFACE_CLASS_DATA:
                    shared_data_interfaces.append(parent)
    else:
        used_by = interface['used_by']

    for ifname in used_by:
        child = pecan.request.dbapi.iinterface_get(ifname, ihost['uuid'])
        interface_class = child.get('ifclass', None)
        if interface_class:
            # This should only match 'data' interface class since that
            # is the only type that can be shared on multiple interfaces.
            if interface_class == constants.INTERFACE_CLASS_DATA:
                shared_data_interfaces.append(child)

    return shared_data_interfaces


def _neutron_host_extension_supported():
    """
    Reports whether the neutron "host" extension is supported or not.  This
    indicator is used to determine whether certain neutron operations are
    necessary or not.  If it is not supported then this is an indication that
    we are running against a vanilla openstack installation.
    """
    return True
    # TODO: This should be looking at the neutron extension list, but because
    # our config file is not setup properly to have a different region on a per
    # service basis we cannot.
    #
    # The code should like something like this:
    #
    # extensions = pecan.request.rpcapi.neutron_extension_list(
    #     pecan.request.context)
    # return bool(constants.NEUTRON_HOST_ALIAS in extensions)


def _neutron_providernet_extension_supported():
    """
    Reports whether the neutron "wrs-provider" extension is supported or not.
    This indicator is used to determine whether certain neutron operations are
    necessary or not.  If it is not supported then this is an indication that
    we are running against a vanilla openstack installation.
    """
    # In the case of a kubernetes config, neutron may not be running, and
    # sysinv should not rely on talking to containerized neutron.
    if utils.is_kubernetes_config():
        return False

    return True
    # TODO: This should be looking at the neutron extension list, but because
    # our config file is not setup properly to have a different region on a per
    # service basis we cannot.
    #
    # The code should like something like this:
    #
    # extensions = pecan.request.rpcapi.neutron_extension_list(
    #    pecan.request.context)
    # return bool(constants.NEUTRON_WRS_PROVIDER_ALIAS in extensions)


def _neutron_providernet_list():
    pnets = {}
    if _neutron_providernet_extension_supported():
        pnets = pecan.request.rpcapi.iinterface_get_providernets(
            pecan.request.context)
    return pnets


def _update_shared_interface_neutron_bindings(ihost, interface, test=False):
    if not _neutron_host_extension_supported():
        # No action required if neutron does not support the host extension
        return
    shared_data_interfaces = _get_shared_data_interfaces(ihost, interface)
    for shared_interface in shared_data_interfaces:
        if shared_interface['uuid'] != interface['uuid']:
            _neutron_bind_interface(ihost, shared_interface, test)


def _datanetworks_get_by_interface(interface_uuid):
    ifdatanets = pecan.request.dbapi.interface_datanetwork_get_by_interface(
        interface_uuid)

    LOG.debug("_datanetworks_get_by_interface %s ifdnets=%s" %
              (interface_uuid, ifdatanets))

    datanetworks = []
    for ifdatanet in ifdatanets:
        datanetworks.append(ifdatanet.datanetwork_uuid)

    datanetworks_list = []
    datanetworks_names_list = []
    for datanetwork in datanetworks:
        dn = pecan.request.dbapi.datanetwork_get(datanetwork)
        datanetwork_dict = \
            {'name': dn.name,
             'uuid': dn.uuid,
             'network_type': dn.network_type,
             'mtu': dn.mtu}
        datanetworks_names_list.append(dn.name)
        if dn.network_type == constants.DATANETWORK_TYPE_VXLAN:
            datanetwork_dict.update(
                {'port_num': dn.port_num,
                 'multicast_group': dn.multicast_group,
                 'ttl': dn.ttl,
                 'mode': dn.mode})
        datanetworks_list.append(datanetwork_dict)

    return datanetworks_names_list, datanetworks_list


def _neutron_bind_interface(ihost, interface, test=False):
    """
    Send a request to neutron to bind the interface to the specified
    providernetworks and perform validation against a subset of the interface
    attributes.
    """
    ihost_uuid = ihost['uuid']
    recordtype = ihost['recordtype']
    if recordtype in ['profile']:
        # No action required if we are operating on a profile record
        return
    if not _neutron_providernet_extension_supported():
        # No action required if neutron does not support the pnet extension
        return
    if not _neutron_host_extension_supported():
        # No action required if neutron does not support the host extension
        return

    if interface['ifclass'] == constants.INTERFACE_CLASS_DATA:
        networktype = constants.NETWORK_TYPE_DATA
    elif interface['ifclass'] == constants.INTERFACE_CLASS_PCI_PASSTHROUGH:
        networktype = constants.NETWORK_TYPE_PCI_PASSTHROUGH
    elif interface['ifclass'] == constants.INTERFACE_CLASS_PCI_SRIOV:
        networktype = constants.NETWORK_TYPE_PCI_SRIOV
    else:
        msg = _("Invalid interface class %s: " % interface['ifclass'])
        raise wsme.exc.ClientSideError(msg)

    interface_uuid = interface['uuid']
    datanetworks_names_list, _dl = \
        _datanetworks_get_by_interface(interface_uuid)

    providernetworks = ",".join([str(x) for x in datanetworks_names_list])
    LOG.info("_neutron_bind_interface uuid=%s datanetworks_names=%s" %
             (interface_uuid, providernetworks))

    vlans = _get_interface_vlans(ihost_uuid, interface)
    try:
        # Send the request to neutron
        pecan.request.rpcapi.neutron_bind_interface(
            pecan.request.context,
            ihost_uuid, interface_uuid, networktype, providernetworks,
            interface['imtu'], vlans=vlans, test=test)
    except rpc_common.RemoteError as e:
        raise wsme.exc.ClientSideError(str(e.value))


def _neutron_unbind_interface(ihost, interface):
    """
    Send a request to neutron to unbind the interface from all provider
    networks.
    """
    ihost_uuid = ihost['uuid']
    recordtype = ihost['recordtype']
    if recordtype in ['profile']:
        # No action required if we are operating on a profile record
        return
    if not _neutron_providernet_extension_supported():
        # No action required if neutron does not support the pnet extension
        return
    if not _neutron_host_extension_supported():
        # No action required if neutron does not support the host extension
        return
    try:
        # Send the request to neutron
        pecan.request.rpcapi.neutron_unbind_interface(
            pecan.request.context, ihost_uuid, interface['uuid'])
    except rpc_common.RemoteError as e:
        raise wsme.exc.ClientSideError(str(e.value))


def _get_boot_interface(ihost):
    """
    Find the interface from which this host booted.
    """
    ports = pecan.request.dbapi.ethernet_port_get_all(hostid=ihost['id'])
    for p in ports:
        if p.bootp == 'True':
            return pecan.request.dbapi.iinterface_get(p.interface_id,
                                                      ihost['uuid'])
    return None


def _get_lower_interface_macs(ihost, interface):
    """
    Return a dictionary mapping interface name to MAC address for any interface
    in the 'uses' list of the given interface object.
    """
    result = {}
    for lower_ifname in interface['uses']:
        lower_iface = pecan.request.dbapi.iinterface_get(lower_ifname,
                                                         ihost['uuid'])
        result[lower_iface['ifname']] = lower_iface['imac']
    return result


def set_interface_mac(ihost, interface):
    """
    Sets the MAC address on new interface.  The MAC is selected from the list
    of lower interface MAC addresses.

    1) If this is a VLAN interface then there is only 1 choice.
    2) If this is an AE interface then we select the first available lower
       interface unless the interface type is a mgmt interface in which case
       it may include the bootif which we prefer.
    """
    selected_mac = None
    selected_ifname = None
    if interface['iftype'] == constants.INTERFACE_TYPE_VIRTUAL:
        selected_mac = constants.ETHERNET_NULL_MAC
    if interface['iftype'] == constants.INTERFACE_TYPE_AE:
        boot_interface = _get_boot_interface(ihost)
        if boot_interface:
            boot_ifname = boot_interface['ifname']
            boot_uuid = boot_interface['uuid']
            if (any(x in interface['uses'] for x in [boot_ifname, boot_uuid])):
                selected_mac = boot_interface['imac']
                selected_ifname = boot_interface['ifname']
        else:
            LOG.warn("No boot interface found for host {}".format(
                ihost['hostname']))
    if not selected_mac:
        # Fallback to selecting the first interface in the list.
        available_macs = _get_lower_interface_macs(ihost, interface)
        selected_ifname = sorted(available_macs)[0]
        selected_mac = available_macs[selected_ifname]
    if interface.get('imac') != selected_mac:
        interface['imac'] = selected_mac
        LOG.info("Setting MAC of interface {} to {}; taken from {}".format(
            interface['ifname'], interface['imac'], selected_ifname))
    return interface


def update_upper_interface_macs(ihost, interface):
    """
    Updates the MAC address on any interface that uses this interface.
    """
    for upper_ifname in interface['used_by']:
        upper_iface = pecan.request.dbapi.iinterface_get(upper_ifname,
                                                         ihost['uuid'])
        if upper_iface['imac'] != interface['imac']:
            values = {'imac': interface['imac']}
            pecan.request.dbapi.iinterface_update(upper_iface['uuid'], values)
            LOG.info("Updating MAC address of {} from {} to {}".format(
                upper_iface['ifname'], upper_iface['imac'], values['imac']))


# This method allows creating an interface through a non-HTTP
# request e.g. through profile.py while still passing
# through interface semantic checks and osd configuration
# Hence, not declared inside a class
#
# Param:
#       interface - dictionary of interface values
def _create(interface, from_profile=False):
    # Get host
    ihostId = interface.get('forihostid') or interface.get('ihost_uuid')
    ihost = pecan.request.dbapi.ihost_get(ihostId)
    if uuidutils.is_uuid_like(ihostId):
        forihostid = ihost['id']
    else:
        forihostid = ihostId

    datanetworks = interface.get('datanetworks')

    LOG.debug("iinterface post interfaces ihostid: %s" % forihostid)

    interface.update({'forihostid': ihost['id'],
                      'ihost_uuid': ihost['uuid']})

    # Assign an UUID if not already done.
    if not interface.get('uuid'):
        interface['uuid'] = str(uuid.uuid4())

    if 'ifclass' in interface \
            and interface['ifclass'] == constants.INTERFACE_CLASS_NONE:
        interface.update({'ifclass': None})

    # Get ports
    ports = None
    ethernet_port_mac = None
    uses_if = None

    if 'uses' in interface:
        uses_if = interface['uses']
    if 'ports' in interface:
        ports = interface['ports']

    if 'uses' in interface and interface['uses'] is None:
        interface.update({'uses': []})
    elif 'uses' not in interface:
        interface.update({'uses': []})

    if 'used_by' in interface and interface['used_by'] is None:
        interface.update({'used_by': []})
    elif 'used_by' not in interface:
        interface.update({'used_by': []})

    if 'networks' in interface and interface['networks'] is None:
        interface.update({'networks': []})
    elif 'networks' not in interface:
        interface.update({'networks': []})

    # Check mtu before setting defaults
    interface = _check_interface_mtu(interface, ihost, from_profile=from_profile)

    # Check vlan_id before setting defaults
    interface = _check_interface_vlan_id("add", interface, ihost, from_profile=from_profile)

    # Set defaults - before checks to allow for optional attributes
    if not from_profile:
        interface = _set_defaults(interface)

    # Semantic checks
    interface = _check("add", interface, ports=ports, ifaces=uses_if, from_profile=from_profile)

    if not from_profile:
        # Select appropriate MAC address from lower interface(s)
        interface = set_interface_mac(ihost, interface)
        ethernet_port_mac = interface['imac']

    new_interface = pecan.request.dbapi.iinterface_create(
        forihostid,
        interface)

    # Create interface-datanetworks
    _update_interface_datanetworks(ihost['uuid'], new_interface, datanetworks)

    # Create network-interface
    try:
        if (new_interface['ifclass'] and
                new_interface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM):
            if 'networks' in interface.keys() and interface['networks']:
                for network_id in interface['networks']:
                    values = {'interface_id': new_interface['id'],
                              'network_id': network_id}
                    pecan.request.dbapi.interface_network_create(values)
    except Exception as e:
        LOG.exception("Failed to create network interface association: "
                      "new_interface={} interface={}".format(
                          new_interface.as_dict(), interface))
        pecan.request.dbapi.iinterface_destroy(new_interface.as_dict()['uuid'])
        raise e

    try:
        # Add extended attributes stored in other tables
        _add_extended_attributes(ihost['uuid'], new_interface, interface)
    except Exception as e:
        LOG.exception("Failed to set extended attributes on interface: "
                      "new_interface={} interface={}".format(
                          new_interface.as_dict(), interface))
        pecan.request.dbapi.iinterface_destroy(new_interface.as_dict()['uuid'])
        raise e

    try:
        if (interface['ifclass'] and
                interface['ifclass'] in NEUTRON_INTERFACE_CLASS):
            _neutron_bind_interface(ihost, new_interface.as_dict())
    except Exception as e:
        LOG.exception("Failed to update neutron bindings: "
                      "new_interface={} interface={}".format(
                          new_interface.as_dict(), interface))
        pecan.request.dbapi.iinterface_destroy(new_interface.as_dict()['uuid'])
        raise e

    try:
        _update_shared_interface_neutron_bindings(ihost, new_interface.as_dict())
    except Exception as e:
        LOG.exception("Failed to update neutron bindings for shared "
                      "interfaces: new_interface={} interface={}".format(
                          new_interface.as_dict(), interface))
        pecan.request.dbapi.iinterface_destroy(interface['uuid'])
        _neutron_unbind_interface(ihost, new_interface.as_dict())
        _update_shared_interface_neutron_bindings(ihost, new_interface.as_dict())
        raise e

    # Update ports
    if ports:
        try:
            _update_ports("modify", new_interface.as_dict(), ihost, ports)
        except Exception as e:
            LOG.exception("Failed to update ports for interface "
                          "interfaces: new_interface={} ports={}".format(
                              new_interface.as_dict(), ports))
            if (interface['ifclass'] and
                    interface['ifclass'] in NEUTRON_INTERFACE_CLASS):
                _neutron_unbind_interface(ihost, new_interface.as_dict())
            pecan.request.dbapi.iinterface_destroy(new_interface.as_dict()['uuid'])
            raise e

    # Update the MTU of underlying interfaces of an AE
    if new_interface['iftype'] == constants.INTERFACE_TYPE_AE:
        try:
            for ifname in new_interface['uses']:
                _update_interface_mtu(ifname, ihost, new_interface['imtu'])
        except Exception as e:
            LOG.exception("Failed to update AE member MTU: "
                          "new_interface={} mtu={}".format(
                                new_interface.as_dict(), new_interface['imtu']))

            pecan.request.dbapi.iinterface_destroy(new_interface['uuid'])
            raise e

    if ihost['recordtype'] != "profile":
        try:
            ifclass = new_interface['ifclass']
            if ifclass == constants.INTERFACE_CLASS_PLATFORM and interface['networks']:
                for network_id in interface['networks']:
                    network = pecan.request.dbapi.network_get_by_id(network_id)
                    if network.type == constants.NETWORK_TYPE_MGMT:
                        _update_host_mgmt_address(ihost, new_interface.as_dict())
                        _update_host_mgmt_mac(ihost, ethernet_port_mac)
                    elif network.type == constants.NETWORK_TYPE_CLUSTER_HOST:
                        _update_host_cluster_address(ihost,
                                                     new_interface.as_dict())
                    if ihost['personality'] == constants.CONTROLLER:
                        if network.type == constants.NETWORK_TYPE_OAM:
                            _update_host_oam_address(ihost, new_interface.as_dict())
                        elif network.type == constants.NETWORK_TYPE_PXEBOOT:
                            _update_host_pxeboot_address(ihost, new_interface.as_dict())

        except Exception as e:
            LOG.exception(
                "Failed to add static interface address: "
                "interface={}".format(new_interface.as_dict()))
            pecan.request.dbapi.iinterface_destroy(
                new_interface.as_dict()['uuid'])
            raise e

        # Covers off LAG case here.
        ifclass = new_interface['ifclass']
        if ifclass == constants.INTERFACE_CLASS_PLATFORM and interface['networks']:
            for network_id in interface['networks']:
                network = pecan.request.dbapi.network_get_by_id(network_id)
                if network.type == constants.NETWORK_TYPE_MGMT:
                    cutils.perform_distributed_cloud_config(pecan.request.dbapi,
                                                            new_interface['id'])

    return new_interface


def _check(op, interface, ports=None, ifaces=None, from_profile=False,
           existing_interface=None, datanetworks=None):
    # Semantic checks
    ihost = pecan.request.dbapi.ihost_get(interface['ihost_uuid']).as_dict()
    _check_host(ihost)
    if not from_profile:
        if ports:
            _check_ports(op, interface, ihost, ports)
        if ifaces:
            interfaces = pecan.request.dbapi.iinterface_get_by_ihost(interface['ihost_uuid'])
            if len(ifaces) > 1 and \
                    interface['iftype'] == constants.INTERFACE_TYPE_VLAN:
                # Can only have one interface associated to vlan interface type
                raise wsme.exc.ClientSideError(
                    _("Can only have one interface for vlan type. (%s)" % ifaces))
            for i in ifaces:
                for iface in interfaces:
                    if iface['uuid'] == i or iface['ifname'] == i:
                        existing_iface = copy.deepcopy(iface)

                        # Get host
                        ihost = pecan.request.dbapi.ihost_get(
                            iface.get('forihostid'))

                        if 'vlan_id' not in iface:
                            iface['vlan_id'] = None

                        if 'aemode' not in iface:
                            iface['aemode'] = None

                        if 'txhashpolicy' not in iface:
                            iface['txhashpolicy'] = None

                        _check_interface_data(
                            "modify", iface, ihost, existing_iface, datanetworks)

        interface = _check_interface_data(
            op, interface, ihost, existing_interface, datanetworks)

    return interface


def _update(interface_uuid, interface_values, from_profile):
    return objects.interface.get_by_uuid(pecan.request.context, interface_uuid)


def _get_port_entity_type_id():
    return "{}.{}".format(fm_constants.FM_ENTITY_TYPE_HOST,
                          fm_constants.FM_ENTITY_TYPE_PORT)


def _get_port_entity_instance_id(hostname, port_uuid):
    return "{}={}.{}={}".format(fm_constants.FM_ENTITY_TYPE_HOST,
                                hostname,
                                fm_constants.FM_ENTITY_TYPE_PORT,
                                port_uuid)


def _clear_port_state_fault(hostname, port_uuid):
    """
    Clear a fault management alarm condition for port state fault
    """
    LOG.debug("Clear port state fault: {}".format(port_uuid))

    entity_instance_id = _get_port_entity_instance_id(hostname, port_uuid)
    FM.clear_fault(fm_constants.FM_ALARM_ID_NETWORK_PORT, entity_instance_id)


def _get_interface_entity_type_id():
    return "{}.{}".format(fm_constants.FM_ENTITY_TYPE_HOST,
                          fm_constants.FM_ENTITY_TYPE_INTERFACE)


def _get_interface_entity_instance_id(hostname, interface_uuid):
    return "{}={}.{}={}".format(fm_constants.FM_ENTITY_TYPE_HOST,
                                hostname,
                                fm_constants.FM_ENTITY_TYPE_INTERFACE,
                                interface_uuid)


def _clear_interface_state_fault(hostname, interface_uuid):
    """
    Clear a fault management alarm condition for interface state fault
    """
    LOG.debug("Clear interface state fault: {}".format(interface_uuid))

    entity_instance_id = _get_interface_entity_instance_id(hostname, interface_uuid)
    FM.clear_fault(fm_constants.FM_ALARM_ID_NETWORK_INTERFACE, entity_instance_id)


def _delete(interface, from_profile=False):
    ihost = pecan.request.dbapi.ihost_get(interface['forihostid']).as_dict()

    if not from_profile:
        # Semantic checks
        _check_host(ihost)

    if not from_profile and interface['iftype'] == 'ethernet':
        msg = _("Cannot delete an ethernet interface type.")
        raise wsme.exc.ClientSideError(msg)

    # Allow the removal of the virtual management interface during bootstrap.
    # Once the initial configuration is complete, this type of request will be
    # rejected.
    if (interface['networks'] and cutils.is_initial_config_complete()):
        for network_id in interface['networks']:
            network = pecan.request.dbapi.network_get_by_id(network_id)
            if interface['iftype'] == constants.INTERFACE_TYPE_VIRTUAL and \
                    network.type == constants.NETWORK_TYPE_MGMT:
                msg = _("Cannot delete a virtual management interface.")
                raise wsme.exc.ClientSideError(msg)

    # Update ports
    ports = pecan.request.dbapi.ethernet_port_get_all(
        hostid=ihost['id'], interfaceid=interface['id'])
    for port in ports:
        values = {'interface_id': None}
        try:
            pecan.request.dbapi.port_update(port.id, values)
            # Clear outstanding alarms that were raised by the neutron vswitch
            # agent against ports associated with this interface
            _clear_port_state_fault(ihost['hostname'], port.uuid)
        except exception.HTTPNotFound:
            msg = _("Port update of iinterface_uuid failed: "
                    "host %s port %s"
                    % (ihost['hostname'], port.name))
            raise wsme.exc.ClientSideError(msg)

    # Clear any faults on underlying ports, Eg. when deleting an
    # AE interface, we do not want to leave a dangling port fault (that may
    # never be cleared). We purposefully do not remove the underlying ports
    # from their respective interfaces.
    for ifname in interface['uses']:
        lower_iface = (
            pecan.request.dbapi.iinterface_get(ifname, ihost['uuid']))
        lports = pecan.request.dbapi.ethernet_port_get_all(
            hostid=ihost['id'], interfaceid=lower_iface['id'])
        for lport in lports:
            _clear_port_state_fault(ihost['hostname'], lport.uuid)

    # Restore the default MTU for AE members
    if interface['iftype'] == constants.INTERFACE_TYPE_AE:
        for ifname in interface['uses']:
            _update_interface_mtu(ifname, ihost, DEFAULT_MTU)

    # Delete interface
    try:
        primary_ifclass = interface['ifclass']
        if primary_ifclass == constants.INTERFACE_CLASS_PLATFORM:
            for network_id in interface['networks']:
                network = pecan.request.dbapi.network_get_by_id(network_id)
                if ((network.type == constants.NETWORK_TYPE_MGMT) or
                        (network.type == constants.NETWORK_TYPE_CLUSTER_HOST) or
                        (network.type == constants.NETWORK_TYPE_PXEBOOT) or
                        (network.type == constants.NETWORK_TYPE_OAM)):
                    pecan.request.dbapi.addresses_remove_interface_by_interface(
                        interface['id']
                    )
        pecan.request.dbapi.iinterface_destroy(interface['uuid'])
        if (interface['ifclass'] and
                    interface['ifclass'] in NEUTRON_INTERFACE_CLASS):
            # Unbind the interface in neutron
            _neutron_unbind_interface(ihost, interface)
        # Update shared data interface bindings, if required
        _update_shared_interface_neutron_bindings(ihost, interface)
        # Clear outstanding alarms that were raised by the neutron vswitch
        # agent against interface
        _clear_interface_state_fault(ihost['hostname'], interface['uuid'])
    except exception.HTTPNotFound:
        msg = _("Delete interface failed: host %s if %s"
                % (ihost['hostname'], interface['ifname']))
        raise wsme.exc.ClientSideError(msg)
