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
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#

import jsonpatch
import pecan
from pecan import rest
import six
import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from oslo_log import log
from sysinv._i18n import _
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import cpu
from sysinv.api.controllers.v1 import memory
from sysinv.api.controllers.v1 import port
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common import uuidutils

LOG = log.getLogger(__name__)


class NodePatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return ['/address', '/ihost_uuid']


class Node(base.APIBase):
    """API representation of a host node.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    an node.
    """

    uuid = types.uuid
    "Unique UUID for this node"

    numa_node = int
    "numa node zone for this inode"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                    six.integer_types)}
    "This node's meta data"

    forihostid = int
    "The ihostid that this inode belongs to"

    ihost_uuid = types.uuid
    "The UUID of the host this node belongs to"

    links = [link.Link]
    "A list containing a self link and associated node links"

    icpus = [link.Link]
    "Links to the collection of icpus on this node"

    imemorys = [link.Link]
    "Links to the collection of imemorys on this node"

    ports = [link.Link]
    "Links to the collection of ports on this node"

    def __init__(self, **kwargs):
        self.fields = objects.node.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_node, expand=True):
        minimum_fields = ['uuid', 'numa_node', 'capabilities',
                          'ihost_uuid',
                          'forihostid'] if not expand else None
        fields = minimum_fields if not expand else None

        # node = inode.from_rpc_object(rpc_node, fields)

        # node = inode(**rpc_node.as_dict())
        node = Node.from_rpc_object(rpc_node, fields)
        # if not expand:
        #     node.unset_fields_except(['uuid',
        #                               'numa_node',
        #                               'capabilities',
        #                               'ihost_uuid', 'forihostid'])

        # never expose the ihost_id attribute
        node.forihostid = wtypes.Unset

        node.links = [link.Link.make_link('self', pecan.request.host_url,
                                          'inodes', node.uuid),
                      link.Link.make_link('bookmark',
                                          pecan.request.host_url,
                                          'inodes', node.uuid,
                                          bookmark=True)
                      ]
        if expand:
            node.icpus = [link.Link.make_link('self',
                                              pecan.request.host_url,
                                              'inodes',
                                              node.uuid + "/icpus"),
                              link.Link.make_link('bookmark',
                                                  pecan.request.host_url,
                                                  'inodes',
                                                  node.uuid + "/icpus",
                                                  bookmark=True)
                          ]

            node.imemorys = [link.Link.make_link('self',
                                              pecan.request.host_url,
                                              'inodes',
                                              node.uuid + "/imemorys"),
                              link.Link.make_link('bookmark',
                                                  pecan.request.host_url,
                                                  'inodes',
                                                  node.uuid + "/imemorys",
                                                  bookmark=True)
                             ]

            node.ports = [link.Link.make_link('self',
                                              pecan.request.host_url,
                                              'inodes',
                                              node.uuid + "/ports"),
                              link.Link.make_link('bookmark',
                                              pecan.request.host_url,
                                              'inodes',
                                              node.uuid + "/ports",
                                              bookmark=True)
                          ]

        return node


class NodeCollection(collection.Collection):
    """API representation of a collection of nodes."""

    inodes = [Node]
    "A list containing node objects"

    def __init__(self, **kwargs):
        self._type = 'inodes'

    @classmethod
    def convert_with_links(cls, rpc_nodes, limit, url=None,
                           expand=False, **kwargs):
        collection = NodeCollection()
        collection.inodes = [Node.convert_with_links(p, expand)
                             for p in rpc_nodes]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'NodeController'


class NodeController(rest.RestController):
    """REST controller for inodes."""

    icpus = cpu.CPUController(from_inode=True)
    "Expose icpus as a sub-element of inodes"

    imemorys = memory.MemoryController(from_inode=True)
    "Expose imemorys as a sub-element of inodes"

    ports = port.PortController(from_inode=True)
    "Expose ports as a sub-element of inodes"

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_ihosts=False):
        self._from_ihosts = from_ihosts

    def _get_nodes_collection(self, ihost_uuid, marker, limit, sort_key,
                              sort_dir, expand=False, resource_url=None):
        if self._from_ihosts and not ihost_uuid:
            raise exception.InvalidParameterValue(_(
                  "Host id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.node.get_by_uuid(pecan.request.context,
                                                  marker)

        if ihost_uuid:
            nodes = pecan.request.dbapi.inode_get_by_ihost(ihost_uuid, limit,
                                                           marker_obj,
                                                           sort_key=sort_key,
                                                           sort_dir=sort_dir)
        else:
            nodes = pecan.request.dbapi.inode_get_list(limit, marker_obj,
                                                       sort_key=sort_key,
                                                       sort_dir=sort_dir)

        return NodeCollection.convert_with_links(nodes, limit,
                                                 url=resource_url,
                                                 expand=expand,
                                                 sort_key=sort_key,
                                                 sort_dir=sort_dir)

    @wsme_pecan.wsexpose(NodeCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def get_all(self, ihost_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of nodes."""

        return self._get_nodes_collection(ihost_uuid, marker, limit,
                                          sort_key, sort_dir)

    @wsme_pecan.wsexpose(NodeCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, ihost_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of nodes with detail."""
        # NOTE(lucasagomes): /detail should only work agaist collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "inodes":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['nodes', 'detail'])
        return self._get_nodes_collection(ihost_uuid,
                                               marker, limit,
                                               sort_key, sort_dir,
                                               expand, resource_url)

    @wsme_pecan.wsexpose(Node, types.uuid)
    def get_one(self, node_uuid):
        """Retrieve information about the given node."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_node = objects.node.get_by_uuid(pecan.request.context, node_uuid)
        return Node.convert_with_links(rpc_node)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Node, body=Node)
    def post(self, node):
        """Create a new node."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        try:
            node = node.as_dict()

            # Get host
            ihostId = node.get('forihostid') or node.get('ihost_uuid')
            if uuidutils.is_uuid_like(ihostId):
                ihost = pecan.request.dbapi.ihost_get(ihostId)
                forihostid = ihost['id']
                node.update({'forihostid': forihostid})
            else:
                forihostid = ihostId

            LOG.debug("inode post nodes ihostid: %s" % forihostid)

            new_node = pecan.request.dbapi.inode_create(
                                  forihostid, node)

        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data"))
        return Node.convert_with_links(new_node)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [NodePatchType])
    @wsme_pecan.wsexpose(Node, types.uuid,
                         body=[NodePatchType])
    def patch(self, node_uuid, patch):
        """Update an existing node."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_node = objects.node.get_by_uuid(
                       pecan.request.context, node_uuid)

        # replace ihost_uuid and inode_uuid with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)
        for p in patch_obj:
            if p['path'] == '/ihost_uuid':
                p['path'] = '/forihostid'
                ihost = objects.host.get_by_uuid(pecan.request.context,
                                                 p['value'])
                p['value'] = ihost.id

        try:
            node = Node(**jsonpatch.apply_patch(
                                               rpc_node.as_dict(),
                                               patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Update only the fields that have changed
        for field in objects.node.fields:
            if rpc_node[field] != getattr(node, field):
                rpc_node[field] = getattr(node, field)

        rpc_node.save()
        return Node.convert_with_links(rpc_node)

    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, node_uuid):
        """Delete a node."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        pecan.request.dbapi.inode_destroy(node_uuid)
