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
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#


import copy
import jsonpatch

import pecan
from pecan import rest

import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from netaddr import IPNetwork, IPAddress, AddrFormatError

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.api.controllers.v1 import address_pool
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _


LOG = log.getLogger(__name__)


class InfraNetworkPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return []


class InfraNetwork(base.APIBase):
    """API representation of a infrastructure network.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    an infra.
    """

    uuid = types.uuid
    "Unique UUID for this infra"

    infra_subnet = wtypes.text
    "Represent the infrastructure subnet."

    infra_start = wtypes.text
    "Represent the start address of the infra allocation range"

    infra_end = wtypes.text
    "Represent the end address of the infra allocation range"

    infra_mtu = wtypes.text
    "Represent the mtu of the infrastructure network"

    infra_vlan_id = wtypes.text
    "Represent the VLAN ID of the infrastructure network"

    action = wtypes.text
    "Represent the action on the infrastructure network."

    forisystemid = int
    "The isystemid that this iinfra belongs to"

    isystem_uuid = types.uuid
    "The UUID of the system this infra belongs to"

    links = [link.Link]
    "A list containing a self link and associated infra links"

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    def __init__(self, **kwargs):
        self.fields = objects.infra_network.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        # 'action' is not part of objects.iinfra.fields
        # (it's an API-only attribute)
        self.fields.append('action')
        setattr(self, 'action', kwargs.get('action', None))

    @classmethod
    def convert_with_links(cls, rpc_infra, expand=True):
        # fields = ['uuid', 'address'] if not expand else None
        # infra = iinfra.from_rpc_object(rpc_infra, fields)

        infra = InfraNetwork(**rpc_infra.as_dict())
        if not expand:
            infra.unset_fields_except(['uuid',
                                       'infra_subnet',
                                       'infra_start',
                                       'infra_end',
                                       'infra_mtu',
                                       'infra_vlan_id',
                                       'isystem_uuid',
                                       'created_at',
                                       'updated_at'])

        # never expose the isystem_id attribute
        infra.isystem_id = wtypes.Unset

        # never expose the isystem_id attribute, allow exposure for now
        # infra.forisystemid = wtypes.Unset

        infra.links = [link.Link.make_link('self', pecan.request.host_url,
                                         'iinfras', infra.uuid),
                     link.Link.make_link('bookmark',
                                         pecan.request.host_url,
                                         'iinfras', infra.uuid,
                                         bookmark=True)
                       ]

        return infra


class InfraNetworkCollection(collection.Collection):
    """API representation of a collection of infras."""

    iinfras = [InfraNetwork]
    "A list containing infra objects"

    def __init__(self, **kwargs):
        self._type = 'iinfras'

    @classmethod
    def convert_with_links(cls, rpc_infras, limit, url=None,
                           expand=False, **kwargs):
        collection = InfraNetworkCollection()
        collection.iinfras = [InfraNetwork.convert_with_links(p, expand)
                              for p in rpc_infras]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'InfraNetworkController'


class InfraNetworkController(rest.RestController):
    """REST controller for iinfras."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_isystems=False):
        self._from_isystems = from_isystems

    def _get_infras_collection(self, isystem_uuid, marker, limit, sort_key,
                             sort_dir, expand=False, resource_url=None):

        if self._from_isystems and not isystem_uuid:
            raise exception.InvalidParameterValue(_(
                  "System id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.infra_network.get_by_uuid(pecan.request.context,
                                                           marker)

        infras = pecan.request.dbapi.iinfra_get_list(limit, marker_obj,
                                                     sort_key=sort_key,
                                                     sort_dir=sort_dir)

        return InfraNetworkCollection.convert_with_links(infras, limit,
                                                         url=resource_url,
                                                         expand=expand,
                                                         sort_key=sort_key,
                                                         sort_dir=sort_dir)

    def _check_host_states(self):
        current_ihosts = pecan.request.dbapi.ihost_get_list()
        for h in current_ihosts:
            if (h['administrative'] != constants.ADMIN_LOCKED and
                    not utils.is_host_active_controller(h)):
                raise wsme.exc.ClientSideError(_(
                    "Infrastructure subnet configuration cannot be "
                    "updated with hosts other than the active controller "
                    "in an unlocked state. Please lock all hosts except "
                    "the active controller."))

    def _check_host_interfaces(self):
        controller_ihosts = pecan.request.dbapi.ihost_get_by_personality(
            personality=constants.CONTROLLER)
        for host in controller_ihosts:
            if utils.is_host_active_controller(host):
                interface_list = pecan.request.dbapi.iinterface_get_by_ihost(
                    host.uuid)
                network = pecan.request.dbapi.network_get_by_type(constants.NETWORK_TYPE_INFRA)
                for interface in interface_list:
                    if interface['ifclass'] == constants.INTERFACE_CLASS_PLATFORM:
                        if str(network['id']) in interface['networks']:
                            return True
        raise wsme.exc.ClientSideError(_(
            "Infrastructure interface must be configured on the active "
            "controller prior to applying infrastructure network "
            "configuration."))

    @staticmethod
    def get_management_ip_version():
        mgmt_network = pecan.request.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_MGMT)
        mgmt_address_pool = pecan.request.dbapi.address_pool_get(
            mgmt_network.pool_uuid)
        return mgmt_address_pool.family

    @staticmethod
    def _check_mtu_syntax(infra):
        if 'infra_mtu' in infra.keys() and infra['infra_mtu'] is not None:
            if not str(infra['infra_mtu']).isdigit():
                raise wsme.exc.ClientSideError(_("MTU is an integer value."))
            infra['infra_mtu'] = int(infra['infra_mtu'])
            utils.validate_mtu(infra['infra_mtu'])
        else:
            infra['infra_mtu'] = constants.DEFAULT_MTU
        return infra

    @staticmethod
    def _check_vlan_id_syntax(infra):
        if 'infra_vlan_id' in infra.keys() and \
                infra['infra_vlan_id'] is not None:
            if not str(infra['infra_vlan_id']).isdigit():
                raise wsme.exc.ClientSideError(_(
                    "VLAN id is an integer value."))

            infra['infra_vlan_id'] = int(infra['infra_vlan_id'])
            if infra['infra_vlan_id'] == 0:
                infra['infra_vlan_id'] = None
            elif infra['infra_vlan_id'] < 1 or infra['infra_vlan_id'] > 4094:
                raise wsme.exc.ClientSideError(_(
                    "VLAN id must be between 1 and 4094."))
            else:
                infra['infra_vlan_id'] = six.text_type(infra['infra_vlan_id'])
        return infra

    @staticmethod
    def _check_interface_mtu(infra):
        # Check for mtu of interface and its underlying interface compatibility
        interfaces = pecan.request.dbapi.iinterface_get_by_network(
            constants.NETWORK_TYPE_INFRA)
        for interface in interfaces:
            if interface['iftype'] != 'vlan':
                continue
            ihost = pecan.request.dbapi.ihost_get(interface['forihostid'])
            lower_ifname = interface['uses'][0]
            lower_iface = (
                pecan.request.dbapi.iinterface_get(lower_ifname, ihost['uuid']))
            if lower_iface['imtu'] < infra['infra_mtu']:
                msg = _("MTU (%s) of VLAN interface (%s) cannot be larger "
                        "than MTU (%s) of underlying interface (%s) "
                        "on host %s" %
                        (infra['infra_mtu'], interface['ifname'],
                         lower_iface['imtu'], lower_iface['ifname'],
                         ihost['hostname']))
                raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _check_interface_vlan_id(infra):
        # Check for invalid combination of vlan id in network vlan id and
        # infrastructure interface vlan id
        network_vlan_id = infra['infra_vlan_id']
        interfaces = pecan.request.dbapi.iinterface_get_by_network(
            constants.NETWORK_TYPE_INFRA)
        for interface in interfaces:
            if interface['iftype'] != 'vlan':
                continue
            if network_vlan_id is None and interface['vlan_id'] is not None:
                msg = _("VLAN id of infrastructure network must be set since"
                        "Interface (%s) VLAN id (%d) is provisioned. " %
                        (interface['ifname'], interface['vlan_id']))
                raise wsme.exc.ClientSideError(msg)
            if (interface['vlan_id'] is not None and
                        int(network_vlan_id) != interface['vlan_id']):
                msg = _("Interface (%s) VLAN id (%d) must be the same as "
                        "the VLAN id (%s) in the infrastructure network. " %
                        (interface['ifname'], interface['vlan_id'],
                         network_vlan_id))
                raise wsme.exc.ClientSideError(msg)
        return

    def _check_infra_data(self, infra, infra_orig=None):
        subnetkey = 'infra_subnet'
        startkey = 'infra_start'
        endkey = 'infra_end'

        subnet = None
        mgmt_ip_version = InfraNetworkController.get_management_ip_version()
        ip_version_string = constants.IP_FAMILIES[mgmt_ip_version]

        if subnetkey in infra.keys():
            subnet = infra[subnetkey]
            try:
                subnet = IPNetwork(subnet)
            except AddrFormatError:
                raise wsme.exc.ClientSideError(_(
                    "Invalid subnet %s %s. Please configure"
                    "valid %s subnet") %
                    (subnetkey, subnet, ip_version_string))

            utils.is_valid_subnet(subnet, mgmt_ip_version)

            if (infra_orig and infra_orig[subnetkey] and
                    infra[subnetkey] != infra_orig[subnetkey]):
                raise wsme.exc.ClientSideError(_(
                        "Infrastructure subnet cannot be modified."))

        if startkey in infra.keys() or endkey in infra.keys():
            if not subnet:
                raise wsme.exc.ClientSideError(_(
                    "An infrastructure subnet must be specified"))

        if infra.get(startkey):
            start = infra[startkey]
            try:
                start = IPAddress(infra[startkey])
            except AddrFormatError:
                raise wsme.exc.ClientSideError(_(
                    "Invalid infra start address %s %s. Please configure "
                    "valid %s address") %
                    (startkey, start, ip_version_string))

            utils.is_valid_address_within_subnet(start, subnet)
        else:
            infra[startkey] = subnet[2]

        if infra.get(endkey):
            end = infra[endkey]
            try:
                end = IPAddress(infra[endkey])
            except AddrFormatError:
                raise wsme.exc.ClientSideError(_(
                    "Invalid infra end address %s %s. Please configure "
                    "valid %s address") %
                    (startkey, end, ip_version_string))

            utils.is_valid_address_within_subnet(end, subnet)
        else:
            infra[endkey] = subnet[-2]

        if IPAddress(infra[endkey]) <= IPAddress(infra[startkey]):
                raise wsme.exc.ClientSideError(_(
                    "Invalid infra range.  Start address %s must be below end "
                    "address %s") % (infra[startkey], infra[endkey]))

        # regenerate static addresses if start address changed
        if infra_orig and infra[startkey] != infra_orig[startkey]:
            start_address = IPAddress(infra[startkey])
            for index, field in enumerate(InfraNetwork.address_names.keys()):
                infra[field] = str(start_address + index)

        return infra

    def _create_infra_network(self, infra):

        subnet = IPNetwork(infra['infra_subnet'])
        start_address = IPAddress(infra['infra_start'])
        end_address = IPAddress(infra['infra_end'])

        values = {
            'name': 'infrastructure',
            'family': subnet.version,
            'network': str(subnet.network),
            'prefix': subnet.prefixlen,
            'order': address_pool.DEFAULT_ALLOCATION_ORDER,
            'ranges': [(str(start_address), str(end_address))],
        }
        pool = pecan.request.dbapi.address_pool_create(values)

        # create the network for the pool

        # Default the address allocation order to be the same as the
        # management network.
        mgmt_network = pecan.request.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_MGMT)

        values = {
            'type': constants.NETWORK_TYPE_INFRA,
            'dynamic': mgmt_network.dynamic,
            'address_pool_id': pool.id,
        }

        pecan.request.dbapi.network_create(values)

        # reserve static network addresses
        # (except cinder's IP which will be created later)
        address_names = copy.copy(objects.infra_network.address_names)
        del address_names['infra_cinder_ip']
        for index, name in enumerate(address_names.values()):
            address = str(start_address + index)
            values = {
                'address_pool_id': pool.id,
                'family': subnet.version,
                'address': address,
                'prefix': subnet.prefixlen,
                'name': name,
            }
            pecan.request.dbapi.address_create(values)

        # If cinder lvm is enabled it will switch to the infra network.
        pecan.request.rpcapi.reserve_ip_for_cinder(pecan.request.context)

        return pecan.request.dbapi.iinfra_get_one()

    @wsme_pecan.wsexpose(InfraNetworkCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, isystem_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of infras. Only one per system"""

        return self._get_infras_collection(isystem_uuid, marker, limit,
                                          sort_key, sort_dir)

    @wsme_pecan.wsexpose(InfraNetworkCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, isystem_uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of infras with detail."""
        # NOTE(lucasagomes): /detail should only work agaist collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "iinfras":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['infras', 'detail'])
        return self._get_infras_collection(isystem_uuid,
                                           marker, limit,
                                           sort_key, sort_dir,
                                           expand, resource_url)

    @wsme_pecan.wsexpose(InfraNetwork, types.uuid)
    def get_one(self, infra_uuid):
        """Retrieve information about the given infra."""
        if self._from_isystems:
            raise exception.OperationNotPermitted

        rpc_infra = \
            objects.infra_network.get_by_uuid(pecan.request.context, infra_uuid)
        return InfraNetwork.convert_with_links(rpc_infra)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(InfraNetwork, body=InfraNetwork)
    def post(self, infra):
        """Create a new infrastructure network config."""
        if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
            msg = _("Adding an infrastructure network on a simplex system "
                    "is not allowed.")
            raise wsme.exc.ClientSideError(msg)

        self._check_host_states()
        infra_data = self._check_infra_data(infra.as_dict())
        infra = self._create_infra_network(infra_data)

        return InfraNetwork.convert_with_links(infra)

    @staticmethod
    def _update_interface(infra):
        # For each infrastructure interface, update the mtu of the interface
        interfaces = pecan.request.dbapi.iinterface_get_by_network(
            constants.NETWORK_TYPE_INFRA)
        for interface in interfaces:
            updates = {'imtu': infra['infra_mtu'],
                       'vlan_id': infra['infra_vlan_id']}
            pecan.request.dbapi.iinterface_update(interface['uuid'], updates)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [InfraNetworkPatchType])
    @wsme_pecan.wsexpose(InfraNetwork, types.uuid,
                         body=[InfraNetworkPatchType])
    def patch(self, infra_uuid, patch):
        """Update the current infrastructure network config."""
        if self._from_isystems:
            raise exception.OperationNotPermitted

        rpc_infra = objects.infra_network.get_by_uuid(pecan.request.context,
                                                      infra_uuid)

        infra_orig = copy.deepcopy(rpc_infra)

        action = None
        for p in patch:
            if '/action' in p['path']:
                value = p['value']
                patch.remove(p)
                if value in (constants.APPLY_ACTION, constants.INSTALL_ACTION):
                    action = value
                break

        # replace isystem_uuid and iinfra_uuid with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)

        state_rel_path = ['/uuid', '/id', '/forisystemid', '/isystem_uuid',
                          '/created_at', '/updated_at',
                          ]

        if any(p['path'] in state_rel_path for p in patch_obj):
            raise wsme.exc.ClientSideError(_("The following fields can not be "
                                             "modified: %s from this level." %
                                             state_rel_path))

        self._check_host_states()
        if action == constants.APPLY_ACTION:
            self._check_host_interfaces()

        for p in patch_obj:
            if p['path'] == '/isystem_uuid':
                isystem = objects.system.get_by_uuid(pecan.request.context,
                                                     p['value'])
                p['path'] = '/forisystemid'
                p['value'] = isystem.id

        try:
            infra = InfraNetwork(**jsonpatch.apply_patch(rpc_infra.as_dict(),
                                                         patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        infra = self._check_infra_data(infra.as_dict(), infra_orig.as_dict())

        changed_fields = []
        try:
            # Update only the fields that have changed
            for field in objects.infra_network.fields:
                if rpc_infra[field] != infra[field]:
                    rpc_infra[field] = infra[field]
                    changed_fields.append(field)

            rpc_infra.save()

            if action == constants.APPLY_ACTION:
                # perform rpc to conductor to perform config apply
                pecan.request.rpcapi.update_infra_config(pecan.request.context)

            return InfraNetwork.convert_with_links(rpc_infra)

        except exception.HTTPNotFound:
            msg = _("Infrastructure IP update failed: system %s infra %s: patch %s"
                    % (isystem['systemname'], infra, patch))
            raise wsme.exc.ClientSideError(msg)

    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, infra_uuid):
        """Delete a infra."""
        raise exception.OperationNotPermitted
