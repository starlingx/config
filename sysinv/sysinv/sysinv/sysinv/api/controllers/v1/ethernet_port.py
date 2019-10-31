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
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#

import jsonpatch
import pecan
from pecan import rest
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common import log

LOG = log.getLogger(__name__)


class EthernetPortPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return []


class EthernetPort(base.APIBase):
    """API representation of an Ethernet port

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of an
    Ethernet port.
    """

    uuid = types.uuid
    "Unique UUID for this port"

    type = wtypes.text
    "Represent the type of port"

    name = wtypes.text
    "Represent the name of the port. Unique per host"

    namedisplay = wtypes.text
    "Represent the display name of the port. Unique per host"

    pciaddr = wtypes.text
    "Represent the pci address of the port"

    dev_id = int
    "The unique identifier of PCI device"

    pclass = wtypes.text
    "Represent the pci class of the port"

    pvendor = wtypes.text
    "Represent the pci vendor of the port"

    pdevice = wtypes.text
    "Represent the pci device of the port"

    psvendor = wtypes.text
    "Represent the pci svendor of the port"

    psdevice = wtypes.text
    "Represent the pci sdevice of the port"

    numa_node = int
    "Represent the numa node or zone sdevice of the port"

    sriov_totalvfs = int
    "The total number of available SR-IOV VFs"

    sriov_numvfs = int
    "The number of configured SR-IOV VFs"

    sriov_vfs_pci_address = wtypes.text
    "The PCI Addresses of the VFs"

    sriov_vf_driver = wtypes.text
    "The SR-IOV VF driver for this device"

    sriov_vf_pdevice_id = wtypes.text
    "The SR-IOV VF PCI device id for this device"

    driver = wtypes.text
    "The kernel driver for this device"

    mac = wsme.wsattr(types.macaddress, mandatory=False)
    "Represent the MAC Address of the port"

    mtu = int
    "Represent the MTU size (bytes) of the port"

    speed = int
    "Represent the speed (MBytes/sec) of the port"

    link_mode = int
    "Represent the link mode of the port"

    duplex = wtypes.text
    "Represent the duplex mode of the port"

    autoneg = wtypes.text
    "Represent the auto-negotiation mode of the port"

    bootp = wtypes.text
    "Represent the bootp port of the host"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                    six.integer_types)}
    "Represent meta data of the port"

    host_id = int
    "Represent the host_id the port belongs to"

    interface_id = int
    "Represent the interface_id the port belongs to"

    bootif = wtypes.text
    "Represent whether the port is a boot port"

    dpdksupport = bool
    "Represent whether or not the port supports DPDK acceleration"

    host_uuid = types.uuid
    "Represent the UUID of the host the port belongs to"

    interface_uuid = types.uuid
    "Represent the UUID of the interface the port belongs to"

    node_uuid = types.uuid
    "Represent the UUID of the node the port belongs to"

    links = [link.Link]
    "Represent a list containing a self link and associated port links"

    def __init__(self, **kwargs):
        self.fields = objects.ethernet_port.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_port, expand=True):
        port = EthernetPort(**rpc_port.as_dict())
        if not expand:
            port.unset_fields_except(['uuid', 'host_id', 'node_id',
                                      'interface_id', 'type', 'name',
                                      'namedisplay', 'pciaddr', 'dev_id',
                                      'pclass', 'pvendor', 'pdevice',
                                      'psvendor', 'psdevice', 'numa_node',
                                      'mac', 'sriov_totalvfs', 'sriov_numvfs',
                                      'sriov_vfs_pci_address', 'sriov_vf_driver',
                                      'sriov_vf_pdevice_id',
                                      'driver', 'mtu', 'speed', 'link_mode',
                                      'duplex', 'autoneg', 'bootp',
                                      'capabilities',
                                      'host_uuid', 'interface_uuid',
                                      'node_uuid', 'dpdksupport',
                                      'created_at', 'updated_at'])

        # never expose the id attribute
        port.host_id = wtypes.Unset
        port.interface_id = wtypes.Unset
        port.node_id = wtypes.Unset

        port.links = [link.Link.make_link('self', pecan.request.host_url,
                                          'ethernet_ports', port.uuid),
                      link.Link.make_link('bookmark',
                                          pecan.request.host_url,
                                          'ethernet_ports', port.uuid,
                                          bookmark=True)
                      ]
        return port


class EthernetPortCollection(collection.Collection):
    """API representation of a collection of EthernetPort objects."""

    ethernet_ports = [EthernetPort]
    "A list containing EthernetPort objects"

    def __init__(self, **kwargs):
        self._type = 'ethernet_ports'

    @classmethod
    def convert_with_links(cls, rpc_ports, limit, url=None,
                           expand=False, **kwargs):
        collection = EthernetPortCollection()
        collection.ethernet_ports = [EthernetPort.convert_with_links(p, expand)
                                    for p in rpc_ports]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'EthernetPortController'


class EthernetPortController(rest.RestController):
    """REST controller for EthernetPorts."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_ihosts=False, from_iinterface=False,
                 from_inode=False):
        self._from_ihosts = from_ihosts
        self._from_iinterface = from_iinterface
        self._from_inode = from_inode

    def _get_ports_collection(self, uuid, interface_uuid, node_uuid,
                              marker, limit, sort_key, sort_dir,
                              expand=False, resource_url=None):

        if self._from_ihosts and not uuid:
            raise exception.InvalidParameterValue(_(
                  "Host id not specified."))

        if self._from_iinterface and not uuid:
            raise exception.InvalidParameterValue(_(
                  "Interface id not specified."))

        if self._from_inode and not uuid:
            raise exception.InvalidParameterValue(_(
                  "inode id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.ethernet_port.get_by_uuid(
                                        pecan.request.context,
                                        marker)

        if self._from_ihosts:
            ports = pecan.request.dbapi.ethernet_port_get_by_host(
                                                    uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
        elif self._from_inode:
            ports = pecan.request.dbapi.ethernet_port_get_by_numa_node(
                                                    uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
        elif self._from_iinterface:
            ports = pecan.request.dbapi.ethernet_port_get_by_interface(
                                                    uuid,
                                                    limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
        else:
            if uuid and not interface_uuid:
                ports = pecan.request.dbapi.ethernet_port_get_by_host(
                                                    uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
            elif uuid and interface_uuid:   # Need ihost_uuid ?
                ports = pecan.request.dbapi.ethernet_port_get_by_host_interface(
                                                    uuid,
                                                    interface_uuid,
                                                    limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

            elif interface_uuid:   # Need ihost_uuid ?
                ports = pecan.request.dbapi.ethernet_port_get_by_host_interface(
                                                    uuid,  # None
                                                    interface_uuid,
                                                    limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

            else:
                ports = pecan.request.dbapi.ethernet_port_get_list(
                                                    limit, marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

        return EthernetPortCollection.convert_with_links(ports, limit,
                                                 url=resource_url,
                                                 expand=expand,
                                                 sort_key=sort_key,
                                                 sort_dir=sort_dir)

    @wsme_pecan.wsexpose(EthernetPortCollection, types.uuid, types.uuid,
                         types.uuid, types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, uuid=None, interface_uuid=None, node_uuid=None,
                marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of ports."""

        return self._get_ports_collection(uuid,
                                          interface_uuid,
                                          node_uuid,
                                          marker, limit, sort_key, sort_dir)

    @wsme_pecan.wsexpose(EthernetPortCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of ports with detail."""

        # NOTE(lucasagomes): /detail should only work against collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "ethernet_ports":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['ethernet_ports', 'detail'])
        return self._get_ports_collection(uuid, marker, limit, sort_key,
                                          sort_dir, expand, resource_url)

    @wsme_pecan.wsexpose(EthernetPort, types.uuid)
    def get_one(self, port_uuid):
        """Retrieve information about the given port."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_port = objects.ethernet_port.get_by_uuid(
            pecan.request.context, port_uuid)
        return EthernetPort.convert_with_links(rpc_port)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(EthernetPort, body=EthernetPort)
    def post(self, port):
        """Create a new port."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        try:
            host_uuid = port.host_uuid
            new_port = pecan.request.dbapi.ethernet_port_create(host_uuid,
                                                                port.as_dict())
        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data"))
        return port.convert_with_links(new_port)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [EthernetPortPatchType])
    @wsme_pecan.wsexpose(EthernetPort, types.uuid,
                         body=[EthernetPortPatchType])
    def patch(self, port_uuid, patch):
        """Update an existing port."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_port = objects.ethernet_port.get_by_uuid(
            pecan.request.context, port_uuid)

        # replace ihost_uuid and iinterface_uuid with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)
        for p in patch_obj:
            if p['path'] == '/host_uuid':
                p['path'] = '/host_id'
                host = objects.host.get_by_uuid(pecan.request.context,
                                                p['value'])
                p['value'] = host.id

            if p['path'] == '/interface_uuid':
                p['path'] = '/interface_id'
                try:
                    interface = objects.interface.get_by_uuid(
                        pecan.request.context, p['value'])
                    p['value'] = interface.id
                except exception.SysinvException:
                    p['value'] = None

        try:
            port = EthernetPort(**jsonpatch.apply_patch(rpc_port.as_dict(),
                                                        patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Update only the fields that have changed
        for field in objects.ethernet_port.fields:
            if rpc_port[field] != getattr(port, field):
                rpc_port[field] = getattr(port, field)

        rpc_port.save()
        return EthernetPort.convert_with_links(rpc_port)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, port_uuid):
        """Delete a port."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        pecan.request.dbapi.ethernet_port_destroy(port_uuid)
