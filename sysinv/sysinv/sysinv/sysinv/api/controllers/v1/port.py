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


import six

import pecan
from pecan import rest

from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import lldp_agent
from sysinv.api.controllers.v1 import lldp_neighbour
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import exception
from sysinv import objects
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log

LOG = log.getLogger(__name__)


class PortPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return []


class Port(base.APIBase):
    """API representation of a host port

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of an
    port.
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

    driver = wtypes.text
    "The kernel driver for this device"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                    six.integer_types)}
    "Represent meta data of the port"

    host_id = int
    "Represent the host_id the port belongs to"

    interface_id = int
    "Represent the interface_id the port belongs to"

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

    lldp_agents = [link.Link]
    "Links to the collection of LldpAgents on this port"

    lldp_neighbours = [link.Link]
    "Links to the collection of LldpNeighbours on this port"

    def __init__(self, **kwargs):
        self.fields = objects.port.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_port, expand=True):
        port = Port(**rpc_port.as_dict())
        if not expand:
            port.unset_fields_except(['uuid', 'host_id', 'node_id',
                                      'interface_id', 'type', 'name',
                                      'namedisplay', 'pciaddr', 'dev_id',
                                      'pclass', 'pvendor', 'pdevice',
                                      'psvendor', 'psdevice', 'numa_node',
                                      'sriov_totalvfs', 'sriov_numvfs',
                                      'sriov_vfs_pci_address', 'sriov_vf_driver',
                                      'driver', 'capabilities',
                                      'host_uuid', 'interface_uuid',
                                      'node_uuid', 'dpdksupport',
                                      'created_at', 'updated_at'])

        # never expose the id attribute
        port.host_id = wtypes.Unset
        port.interface_id = wtypes.Unset
        port.node_id = wtypes.Unset

        port.links = [link.Link.make_link('self', pecan.request.host_url,
                                          'ports', port.uuid),
                      link.Link.make_link('bookmark',
                                          pecan.request.host_url,
                                          'ports', port.uuid,
                                          bookmark=True)
                      ]

        port.lldp_agents = [link.Link.make_link('self',
                                                pecan.request.host_url,
                                                'ports',
                                                port.uuid + "/lldp_agents"),
                            link.Link.make_link('bookmark',
                                                pecan.request.host_url,
                                                'ports',
                                                port.uuid + "/lldp_agents",
                                                bookmark=True)
                            ]

        port.lldp_neighbours = [link.Link.make_link('self',
                                            pecan.request.host_url,
                                            'ports',
                                            port.uuid + "/lldp_neighbors"),
                                link.Link.make_link('bookmark',
                                            pecan.request.host_url,
                                            'ports',
                                            port.uuid + "/lldp_neighbors",
                                            bookmark=True)
                                ]

        return port


class PortCollection(collection.Collection):
    """API representation of a collection of Port objects."""

    ports = [Port]
    "A list containing Port objects"

    def __init__(self, **kwargs):
        self._type = 'ports'

    @classmethod
    def convert_with_links(cls, rpc_ports, limit, url=None,
                           expand=False, **kwargs):
        collection = PortCollection()
        collection.ports = [Port.convert_with_links(p, expand)
                            for p in rpc_ports]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


class PortController(rest.RestController):
    """REST controller for Ports."""

    lldp_agents = lldp_agent.LLDPAgentController(
        from_ports=True)
    "Expose lldp_agents as a sub-element of ports"

    lldp_neighbours = lldp_neighbour.LLDPNeighbourController(
        from_ports=True)
    "Expose lldp_neighbours as a sub-element of ports"

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
            marker_obj = objects.port.get_by_uuid(
                pecan.request.context,
                marker)

        if self._from_ihosts:
            ports = pecan.request.dbapi.port_get_by_host(
                uuid, limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)
        elif self._from_inode:
            ports = pecan.request.dbapi.port_get_by_numa_node(
                uuid, limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)
        elif self._from_iinterface:
            ports = pecan.request.dbapi.port_get_by_interface(
                uuid,
                limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)
        else:
            if uuid and not interface_uuid:
                ports = pecan.request.dbapi.port_get_by_host(
                    uuid, limit,
                    marker_obj,
                    sort_key=sort_key,
                    sort_dir=sort_dir)
            elif uuid and interface_uuid:   # Need ihost_uuid ?
                ports = pecan.request.dbapi.port_get_by_host_interface(
                    uuid,
                    interface_uuid,
                    limit,
                    marker_obj,
                    sort_key=sort_key,
                    sort_dir=sort_dir)
            elif interface_uuid:   # Need ihost_uuid ?
                ports = pecan.request.dbapi.port_get_by_host_interface(
                    uuid,  # None
                    interface_uuid,
                    limit,
                    marker_obj,
                    sort_key=sort_key,
                    sort_dir=sort_dir)
            else:
                ports = pecan.request.dbapi.port_get_list(
                    limit, marker_obj,
                    sort_key=sort_key,
                    sort_dir=sort_dir)

        return PortCollection.convert_with_links(ports, limit,
                                                 url=resource_url,
                                                 expand=expand,
                                                 sort_key=sort_key,
                                                 sort_dir=sort_dir)

    @wsme_pecan.wsexpose(PortCollection, types.uuid, types.uuid,
                         types.uuid, types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, uuid=None, interface_uuid=None, node_uuid=None,
                marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of ports."""

        return self._get_ports_collection(uuid,
                                          interface_uuid,
                                          node_uuid,
                                          marker, limit, sort_key, sort_dir)

    @wsme_pecan.wsexpose(PortCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, uuid=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of ports with detail."""

        # NOTE(lucasagomes): /detail should only work against collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "ports":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['ports', 'detail'])
        return self._get_ports_collection(uuid, marker, limit, sort_key,
                                          sort_dir, expand, resource_url)

    @wsme_pecan.wsexpose(Port, types.uuid)
    def get_one(self, port_uuid):
        """Retrieve information about the given port."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_port = objects.port.get_by_uuid(
            pecan.request.context, port_uuid)
        return Port.convert_with_links(rpc_port)
