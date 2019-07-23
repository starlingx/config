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
import six

import pecan
from pecan import rest

import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _


LOG = log.getLogger(__name__)


class MemoryPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        # return ['/host_uuid', '/inode_uuid']  # JKUNG
        return []


class Memory(base.APIBase):
    """API representation of host memory.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of a memory.
    """

    _minimum_platform_reserved_mib = None

    def _get_minimum_platform_reserved_mib(self):
        return self._minimum_platform_reserved_mib

    def _set_minimum_platform_reserved_mib(self, value):
        if self._minimum_platform_reserved_mib is None:
            try:
                ihost = objects.host.get_by_uuid(pecan.request.context, value)
                self._minimum_platform_reserved_mib = \
                    cutils.get_minimum_platform_reserved_memory(ihost,
                                                                self.numa_node)
            except exception.NodeNotFound as e:
                # Change error code because 404 (NotFound) is inappropriate
                # response for a POST request to create a Port
                e.code = 400  # BadRequest
                raise e
        elif value == wtypes.Unset:
            self._minimum_platform_reserved_mib = wtypes.Unset

    uuid = types.uuid
    "Unique UUID for this memory"

    memtotal_mib = int
    "Represent the imemory total in MiB"

    memavail_mib = int
    "Represent the imemory available in MiB"

    platform_reserved_mib = int
    "Represent the imemory platform reserved in MiB"

    hugepages_configured = wtypes.text
    "Represent whether huge pages are configured"

    vswitch_hugepages_size_mib = int
    "Represent the imemory vswitch huge pages size in MiB"

    vswitch_hugepages_reqd = int
    "Represent the imemory vswitch required number of hugepages"

    vswitch_hugepages_nr = int
    "Represent the imemory vswitch number of hugepages"

    vswitch_hugepages_avail = int
    "Represent the imemory vswitch number of hugepages available"

    vm_hugepages_nr_2M_pending = int
    "Represent the imemory vm number of hugepages pending (2M pages)"

    vm_hugepages_nr_2M = int
    "Represent the imemory vm number of hugepages (2M pages)"

    vm_hugepages_avail_2M = int
    "Represent the imemory vm number of hugepages available (2M pages)"

    vm_hugepages_nr_1G_pending = int
    "Represent the imemory vm number of hugepages pending (1G pages)"

    vm_hugepages_nr_1G = int
    "Represent the imemory vm number of hugepages (1G pages)"

    vm_hugepages_nr_4K = int
    "Represent the imemory vm number of hugepages (4K pages)"

    vm_hugepages_use_1G = wtypes.text
    "1G hugepage is supported 'True' or not 'False' "

    vm_hugepages_avail_1G = int
    "Represent the imemory vm number of hugepages available (1G pages)"

    vm_hugepages_possible_2M = int
    "Represent the total possible number of vm hugepages available (2M pages)"

    vm_hugepages_possible_1G = int
    "Represent the total possible number of vm hugepages available (1G pages)"

    minimum_platform_reserved_mib = wsme.wsproperty(int,
                                                    _get_minimum_platform_reserved_mib,
                                                    _set_minimum_platform_reserved_mib,
                                                    mandatory=True)
    "Represent the default platform reserved memory in MiB. API only attribute"

    numa_node = int
    "The numa node or zone the imemory. API only attribute"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                    six.integer_types)}
    "This memory's meta data"

    forihostid = int
    "The ihostid that this imemory belongs to"

    forinodeid = int
    "The inodeId that this imemory belongs to"

    ihost_uuid = types.uuid
    "The UUID of the ihost this memory belongs to"

    inode_uuid = types.uuid
    "The UUID of the inode this memory belongs to"

    links = [link.Link]
    "A list containing a self link and associated memory links"

    def __init__(self, **kwargs):
        self.fields = list(objects.memory.fields.keys())
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        # API only attributes
        self.fields.append('minimum_platform_reserved_mib')
        setattr(self, 'minimum_platform_reserved_mib', kwargs.get('forihostid', None))

    @classmethod
    def convert_with_links(cls, rpc_port, expand=True):
        # fields = ['uuid', 'address'] if not expand else None
        # memory = imemory.from_rpc_object(rpc_port, fields)

        memory = Memory(**rpc_port.as_dict())
        if not expand:
            memory.unset_fields_except(['uuid', 'memtotal_mib', 'memavail_mib',
                'platform_reserved_mib', 'hugepages_configured',
                'vswitch_hugepages_size_mib', 'vswitch_hugepages_nr',
                'vswitch_hugepages_reqd',
                'vswitch_hugepages_avail',
                'vm_hugepages_nr_2M',
                'vm_hugepages_nr_1G', 'vm_hugepages_use_1G',
                'vm_hugepages_nr_2M_pending',
                'vm_hugepages_avail_2M',
                'vm_hugepages_nr_1G_pending',
                'vm_hugepages_avail_1G',
                'vm_hugepages_nr_4K',
                'vm_hugepages_possible_2M', 'vm_hugepages_possible_1G',
                'numa_node', 'ihost_uuid', 'inode_uuid',
                'forihostid', 'forinodeid',
                'capabilities',
                'created_at', 'updated_at',
                'minimum_platform_reserved_mib'])

        # never expose the id attribute
        memory.forihostid = wtypes.Unset
        memory.forinodeid = wtypes.Unset

        memory.links = [link.Link.make_link('self', pecan.request.host_url,
                                            'imemorys', memory.uuid),
                        link.Link.make_link('bookmark',
                                            pecan.request.host_url,
                                            'imemorys', memory.uuid,
                                            bookmark=True)
                        ]
        return memory


class MemoryCollection(collection.Collection):
    """API representation of a collection of memorys."""

    imemorys = [Memory]
    "A list containing memory objects"

    def __init__(self, **kwargs):
        self._type = 'imemorys'

    @classmethod
    def convert_with_links(cls, imemorys, limit, url=None,
                           expand=False, **kwargs):
        collection = MemoryCollection()
        collection.imemorys = [
            Memory.convert_with_links(n, expand) for n in imemorys]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'MemoryController'


class MemoryController(rest.RestController):
    """REST controller for imemorys."""

    _custom_actions = {
        'detail': ['GET'],
    }

    def __init__(self, from_ihosts=False, from_inode=False):
        self._from_ihosts = from_ihosts
        self._from_inode = from_inode

    def _get_memorys_collection(self, i_uuid, inode_uuid, marker,
                              limit, sort_key, sort_dir,
                              expand=False, resource_url=None):

        if self._from_ihosts and not i_uuid:
            raise exception.InvalidParameterValue(_(
                  "Host id not specified."))

        if self._from_inode and not i_uuid:
            raise exception.InvalidParameterValue(_(
                  "Node id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.memory.get_by_uuid(pecan.request.context,
                                                    marker)

        if self._from_ihosts:
            memorys = pecan.request.dbapi.imemory_get_by_ihost(
                                                    i_uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

        elif self._from_inode:
            memorys = pecan.request.dbapi.imemory_get_by_inode(
                                                    i_uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
        else:
            if i_uuid and not inode_uuid:
                memorys = pecan.request.dbapi.imemory_get_by_ihost(
                                                    i_uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
            elif i_uuid and inode_uuid:   # Need ihost_uuid ?
                memorys = pecan.request.dbapi.imemory_get_by_ihost_inode(
                                                    i_uuid,
                                                    inode_uuid,
                                                    limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

            elif inode_uuid:   # Need ihost_uuid ?
                memorys = pecan.request.dbapi.imemory_get_by_ihost_inode(
                                                    i_uuid,  # None
                                                    inode_uuid,
                                                    limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

            else:
                memorys = pecan.request.dbapi.imemory_get_list(limit,
                                                     marker_obj,
                                                     sort_key=sort_key,
                                                     sort_dir=sort_dir)

        return MemoryCollection.convert_with_links(memorys, limit,
                                                   url=resource_url,
                                                   expand=expand,
                                                   sort_key=sort_key,
                                                   sort_dir=sort_dir)

    @wsme_pecan.wsexpose(MemoryCollection, types.uuid, types.uuid,
                         types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, ihost_uuid=None, inode_uuid=None,
                marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of memorys."""

        return self._get_memorys_collection(ihost_uuid, inode_uuid,
                                          marker, limit,
                                          sort_key, sort_dir)

    @wsme_pecan.wsexpose(MemoryCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, ihost_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of memorys with detail."""
        # NOTE(lucasagomes): /detail should only work agaist collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "imemorys":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['imemorys', 'detail'])
        return self._get_memorys_collection(ihost_uuid, marker, limit,
                                            sort_key, sort_dir,
                                            expand, resource_url)

    @wsme_pecan.wsexpose(Memory, types.uuid)
    def get_one(self, memory_uuid):
        """Retrieve information about the given memory."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_port = objects.memory.get_by_uuid(pecan.request.context,
                                              memory_uuid)
        return Memory.convert_with_links(rpc_port)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Memory, body=Memory)
    def post(self, memory):
        """Create a new memory."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        try:
            ihost_uuid = memory.ihost_uuid
            new_memory = pecan.request.dbapi.imemory_create(ihost_uuid,
                                                      memory.as_dict())

        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data"))
        return Memory.convert_with_links(new_memory)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [MemoryPatchType])
    @wsme_pecan.wsexpose(Memory, types.uuid,
                         body=[MemoryPatchType])
    def patch(self, memory_uuid, patch):
        """Update an existing memory."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_port = objects.memory.get_by_uuid(
                       pecan.request.context, memory_uuid)

        if 'forihostid' in rpc_port:
            ihostId = rpc_port['forihostid']
        else:
            ihostId = rpc_port['ihost_uuid']

        host_id = pecan.request.dbapi.ihost_get(ihostId)

        vm_hugepages_nr_2M_pending = None
        vm_hugepages_nr_1G_pending = None
        vswitch_hugepages_reqd = None
        vswitch_hugepages_size_mib = None

        platform_reserved_mib = None
        for p in patch:
            if p['path'] == '/platform_reserved_mib':
                platform_reserved_mib = p['value']
            if p['path'] == '/vm_hugepages_nr_2M_pending':
                vm_hugepages_nr_2M_pending = p['value']

            if p['path'] == '/vm_hugepages_nr_1G_pending':
                vm_hugepages_nr_1G_pending = p['value']

            if p['path'] == '/vswitch_hugepages_reqd':
                vswitch_hugepages_reqd = p['value']

            if p['path'] == '/vswitch_hugepages_size_mib':
                vswitch_hugepages_size_mib = p['value']

        # The host must be locked
        if host_id:
            _check_host(host_id)
        else:
            raise wsme.exc.ClientSideError(_(
                  "Hostname or uuid must be defined"))

        try:
            # Semantics checks and update hugepage memory accounting
            patch = _check_huge_values(rpc_port, patch,
                                       vm_hugepages_nr_2M_pending,
                                       vm_hugepages_nr_1G_pending,
                                       vswitch_hugepages_reqd,
                                       vswitch_hugepages_size_mib,
                                       platform_reserved_mib)
        except wsme.exc.ClientSideError as e:
            inode = pecan.request.dbapi.inode_get(inode_id=rpc_port.forinodeid)
            numa_node = inode.numa_node
            msg = _('Processor {0}:'.format(numa_node)) + e.message
            raise wsme.exc.ClientSideError(msg)

        # Semantics checks for platform memory
        _check_memory(rpc_port, host_id, platform_reserved_mib,
                      vm_hugepages_nr_2M_pending, vm_hugepages_nr_1G_pending,
                      vswitch_hugepages_reqd, vswitch_hugepages_size_mib)

        # only allow patching allocated_function and capabilities
        # replace ihost_uuid and inode_uuid with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)

        for p in patch_obj:
            if p['path'] == '/ihost_uuid':
                p['path'] = '/forihostid'
                ihost = objects.host.get_by_uuid(pecan.request.context,
                                                 p['value'])
                p['value'] = ihost.id

            if p['path'] == '/inode_uuid':
                p['path'] = '/forinodeid'
                try:
                    inode = objects.node.get_by_uuid(
                                     pecan.request.context, p['value'])
                    p['value'] = inode.id
                except exception.SysinvException:
                    p['value'] = None

        try:
            memory = Memory(**jsonpatch.apply_patch(rpc_port.as_dict(),
                                                    patch_obj))

        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        # Update only the fields that have changed
        for field in objects.memory.fields:
            if rpc_port[field] != getattr(memory, field):
                rpc_port[field] = getattr(memory, field)

        rpc_port.save()
        return Memory.convert_with_links(rpc_port)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, memory_uuid):
        """Delete a memory."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        pecan.request.dbapi.imemory_destroy(memory_uuid)

##############
# UTILS
##############


def _update(mem_uuid, mem_values):

    vswitch_hugepages_reqd = None
    vswitch_hugepages_size_mib = None

    rpc_port = objects.memory.get_by_uuid(pecan.request.context, mem_uuid)
    if 'forihostid' in rpc_port:
        ihostId = rpc_port['forihostid']
    else:
        ihostId = rpc_port['ihost_uuid']

    host_id = pecan.request.dbapi.ihost_get(ihostId)

    if 'platform_reserved_mib' in mem_values:
        platform_reserved_mib = mem_values['platform_reserved_mib']

    if 'vswitch_hugepages_size_mib' in mem_values:
        vswitch_hugepages_size_mib = mem_values['vswitch_hugepages_size_mib']

    if 'vswitch_hugepages_reqd' in mem_values:
        vswitch_hugepages_reqd = mem_values['vswitch_hugepages_reqd']

    if 'vm_hugepages_nr_2M_pending' in mem_values:
        vm_hugepages_nr_2M_pending = mem_values['vm_hugepages_nr_2M_pending']

    if 'vm_hugepages_nr_1G_pending' in mem_values:
        vm_hugepages_nr_1G_pending = mem_values['vm_hugepages_nr_1G_pending']

    # The host must be locked
    if host_id:
        _check_host(host_id)
    else:
        raise wsme.exc.ClientSideError((
            "Hostname or uuid must be defined"))

    # Semantics checks and update hugepage memory accounting
    mem_values = _check_huge_values(rpc_port, mem_values,
                                    vm_hugepages_nr_2M_pending,
                                    vm_hugepages_nr_1G_pending,
                                    vswitch_hugepages_reqd,
                                    vswitch_hugepages_size_mib,
                                    platform_reserved_mib)

    # Semantics checks for platform memory
    _check_memory(rpc_port, host_id, platform_reserved_mib,
                  vm_hugepages_nr_2M_pending, vm_hugepages_nr_1G_pending,
                  vswitch_hugepages_reqd)

    # update memory values
    pecan.request.dbapi.imemory_update(mem_uuid, mem_values)


def _check_host(ihost):
    if utils.is_aio_simplex_host_unlocked(ihost):
        raise wsme.exc.ClientSideError(_("Host must be locked."))
    elif ihost['administrative'] != 'locked':
        unlocked = False
        current_ihosts = pecan.request.dbapi.ihost_get_list()
        for h in current_ihosts:
            if (h['administrative'] != 'locked' and
                        h['hostname'] != ihost['hostname']):
                unlocked = True
        if unlocked:
            raise wsme.exc.ClientSideError(_("Host must be locked."))


def _check_memory(rpc_port, ihost, platform_reserved_mib=None,
                  vm_hugepages_nr_2M_pending=None, vm_hugepages_nr_1G_pending=None,
                  vswitch_hugepages_reqd=None, vswitch_hugepages_size_mib=None):
    if platform_reserved_mib:
        # Check for lower limit
        inode_id = rpc_port['forinodeid']
        inode = pecan.request.dbapi.inode_get(inode_id)
        min_platform_memory = cutils.get_minimum_platform_reserved_memory(ihost, inode.numa_node)
        if int(platform_reserved_mib) < min_platform_memory:
            raise wsme.exc.ClientSideError(_(
                "Platform reserved memory for numa node %s must be greater than the minimum value %d")
                                           % (inode.numa_node, min_platform_memory))

        # Check if it is within 2/3 percent of the total memory
        node_memtotal_mib = rpc_port['node_memtotal_mib']
        max_platform_reserved = node_memtotal_mib * 2 / 3
        if int(platform_reserved_mib) > max_platform_reserved:
            low_core = cutils.is_low_core_system(ihost, pecan.request.dbapi)
            required_platform_reserved = \
                cutils.get_required_platform_reserved_memory(ihost,
                                                             inode.numa_node, low_core)
            msg_platform_over = (_("Platform reserved memory %s MiB "
                                   "on node %s is not within range [%s, %s]")
                                 % (int(platform_reserved_mib),
                                   inode.numa_node,
                                   required_platform_reserved,
                                   max_platform_reserved))

            if cutils.is_virtual() or cutils.is_virtual_worker(ihost):
                LOG.warn(msg_platform_over)
            else:
                raise wsme.exc.ClientSideError(msg_platform_over)

        # Check if it is within the total amount of memory
        mem_alloc = 0
        if vm_hugepages_nr_2M_pending:
            mem_alloc += int(vm_hugepages_nr_2M_pending) * constants.MIB_2M
        elif rpc_port['vm_hugepages_nr_2M']:
            mem_alloc += int(rpc_port['vm_hugepages_nr_2M']) * constants.MIB_2M
        if vm_hugepages_nr_1G_pending:
            mem_alloc += int(vm_hugepages_nr_1G_pending) * constants.MIB_1G
        elif rpc_port['vm_hugepages_nr_1G']:
            mem_alloc += int(rpc_port['vm_hugepages_nr_1G']) * constants.MIB_1G
        LOG.debug("vm total=%s" % (mem_alloc))

        vs_hp_nr = 0
        if vswitch_hugepages_size_mib:
            vs_hp_size = int(vswitch_hugepages_size_mib)
        else:
            vs_hp_size = rpc_port['vswitch_hugepages_size_mib']
        if vswitch_hugepages_reqd:
            vs_hp_nr = int(vswitch_hugepages_reqd)
        elif rpc_port['vswitch_hugepages_nr']:
            vs_hp_nr = int(rpc_port['vswitch_hugepages_nr'])

        mem_alloc += vs_hp_size * vs_hp_nr
        LOG.debug("vs_hp_nr=%s vs_hp_size=%s" % (vs_hp_nr, vs_hp_size))
        LOG.debug("memTotal %s mem_alloc %s" % (node_memtotal_mib, mem_alloc))

        # Initial configuration defaults mem_alloc to consume 100% of 2M pages,
        # so we may marginally exceed available non-huge memory.
        # Note there will be some variability in total available memory,
        # so we need to allow some tolerance so we do not hit the limit.
        avail = node_memtotal_mib - mem_alloc
        delta = int(platform_reserved_mib) - avail
        mem_thresh = 32
        if int(platform_reserved_mib) > avail + mem_thresh:
            msg = (_("Platform reserved memory %s MiB exceeds %s MiB available "
                     "by %s MiB (2M: %s pages; 1G: %s pages). "
                     "total memory=%s MiB, allocated=%s MiB.")
                   % (platform_reserved_mib, avail,
                      delta, delta / 2, delta / 1024,
                      node_memtotal_mib, mem_alloc))
            raise wsme.exc.ClientSideError(msg)
        else:
            msg = (_("Platform reserved memory %s MiB, %s MiB available, "
                     "total memory=%s MiB, allocated=%s MiB.")
                   % (platform_reserved_mib, avail,
                      node_memtotal_mib, mem_alloc))
            LOG.info(msg)


def _check_huge_values(rpc_port, patch, vm_hugepages_nr_2M=None,
                       vm_hugepages_nr_1G=None, vswitch_hugepages_reqd=None,
                       vswitch_hugepages_size_mib=None,
                       platform_reserved_mib=None):

    if rpc_port['vm_hugepages_use_1G'] == 'False':
        vs_hp_size = vswitch_hugepages_size_mib
        if vm_hugepages_nr_1G or vs_hp_size == constants.MIB_1G:
            # cannot provision 1G huge pages if the processor does not support
            # them
            raise wsme.exc.ClientSideError(_(
                  "Processor does not support 1G huge pages."))

    # Check for invalid characters
    if vm_hugepages_nr_2M:
        try:
            val = int(vm_hugepages_nr_2M)
        except ValueError:
            raise wsme.exc.ClientSideError(_(
                  "VM huge pages 2M must be a number"))
        if int(vm_hugepages_nr_2M) < 0:
            raise wsme.exc.ClientSideError(_(
                  "VM huge pages 2M must be greater than or equal to zero"))

    if vm_hugepages_nr_1G:
        try:
            val = int(vm_hugepages_nr_1G)
        except ValueError:
            raise wsme.exc.ClientSideError(_(
                  "VM huge pages 1G must be a number"))
        if val < 0:
            raise wsme.exc.ClientSideError(_(
                  "VM huge pages 1G must be greater than or equal to zero"))

    if vswitch_hugepages_reqd and not vswitch_hugepages_size_mib:
        raise wsme.exc.ClientSideError(_(
            "No vswitch hugepage size specified."))

    if vswitch_hugepages_reqd:
        try:
            val = int(vswitch_hugepages_reqd)
        except ValueError:
            raise wsme.exc.ClientSideError(_(
                "vSwitch huge pages must be a number"))
        if (utils.get_vswitch_type() != constants.VSWITCH_TYPE_NONE and
           val <= 0):
            raise wsme.exc.ClientSideError(_(
                "vSwitch huge pages must be greater than zero"))
        elif (utils.get_vswitch_type() == constants.VSWITCH_TYPE_NONE and
              val != 0):
            raise wsme.exc.ClientSideError(_(
                "vSwitch huge pages must be 0 when vSwitch type is none"))

    if vswitch_hugepages_size_mib:
        try:
            val = int(vswitch_hugepages_size_mib)
        except ValueError:
            raise wsme.exc.ClientSideError(_(
                "vSwitch huge pages must be a number"))
        if val <= 0:
            raise wsme.exc.ClientSideError(_(
                "vSwitch huge pages size (MiB) must be greater than zero"))
        if (val & (val - 1)) != 0:
            raise wsme.exc.ClientSideError(_(
                "vSwitch hugepage size (MiB) must be a power of 2"))

    # None == unchanged
    if vm_hugepages_nr_1G is not None:
        new_1G_pages = int(vm_hugepages_nr_1G)
    elif rpc_port['vm_hugepages_nr_1G_pending']:
        new_1G_pages = int(rpc_port['vm_hugepages_nr_1G_pending'])
    elif rpc_port['vm_hugepages_nr_1G']:
        new_1G_pages = int(rpc_port['vm_hugepages_nr_1G'])
    else:
        new_1G_pages = 0
    vm_hp_1G_reqd_mib = new_1G_pages * constants.MIB_1G

    # None == unchanged
    if vm_hugepages_nr_2M is not None:
        new_2M_pages = int(vm_hugepages_nr_2M)
    elif rpc_port['vm_hugepages_nr_2M_pending']:
        new_2M_pages = int(rpc_port['vm_hugepages_nr_2M_pending'])
    elif rpc_port['vm_hugepages_nr_2M']:
        new_2M_pages = int(rpc_port['vm_hugepages_nr_2M'])
    else:
        new_2M_pages = 0
    vm_hp_2M_reqd_mib = new_2M_pages * constants.MIB_2M

    # None == unchanged
    if vswitch_hugepages_reqd is not None:
        new_vs_pages = int(vswitch_hugepages_reqd)
    elif rpc_port['vswitch_hugepages_nr']:
        new_vs_pages = rpc_port['vswitch_hugepages_nr']
    else:
        new_vs_pages = 0
    LOG.debug('new 2M pages: %s, 1G pages: %s, vswitch: %s' %
              (new_2M_pages, new_1G_pages, new_vs_pages))

    # None == unchanged
    if vswitch_hugepages_size_mib is not None:
        vs_hp_size_mib = int(vswitch_hugepages_size_mib)
    elif rpc_port['vswitch_hugepages_size_mib']:
        vs_hp_size_mib = rpc_port['vswitch_hugepages_size_mib']
    else:
        # default
        vs_hp_size_mib = constants.MIB_2M
    vs_hp_reqd_mib = new_vs_pages * vs_hp_size_mib

    # The size of possible hugepages is the node mem total - platform reserved
    base_mem_mib = rpc_port['platform_reserved_mib']
    if platform_reserved_mib:
        # Check for invalid characters
        try:
            val = int(platform_reserved_mib)
        except ValueError:
            raise wsme.exc.ClientSideError((
                "Platform memory must be a number"))
        if val < 0:
            raise wsme.exc.ClientSideError((
                "Platform memory must be greater than zero"))
        base_mem_mib = int(platform_reserved_mib)

    hp_possible_mib = rpc_port['node_memtotal_mib'] - base_mem_mib

    # Total requested huge pages
    hp_requested_mib = vm_hp_2M_reqd_mib + vm_hp_1G_reqd_mib + vs_hp_reqd_mib

    # Make sure everything fits
    if hp_possible_mib < hp_requested_mib:
        vm_max_hp_2M = ((hp_possible_mib - vs_hp_reqd_mib - vm_hp_1G_reqd_mib)
                        / constants.MIB_2M)
        vm_max_hp_1G = ((hp_possible_mib - vs_hp_reqd_mib - vm_hp_2M_reqd_mib)
                        / constants.MIB_1G)

        if new_2M_pages > 0 and new_1G_pages > 0:

            msg = _("For a requested vSwitch hugepage allocation of %s MiB, "
                    "max 1G pages is %s when 2M is %s, or "
                    "max 2M pages is %s when 1G is %s." % (
                        vs_hp_reqd_mib, vm_max_hp_1G, new_2M_pages,
                        vm_max_hp_2M, new_1G_pages
                    ))
        elif new_1G_pages > 0:
            msg = _("For a requested vSwitch hugepage allocation of %s MiB, "
                    "max 1G pages: %s" % (vs_hp_reqd_mib, vm_max_hp_1G))
        elif new_2M_pages > 0:
            msg = _("For a requested vSwitch hugepage allocation of %s MiB, "
                    "max 2M pages: %s" % (vs_hp_reqd_mib, vm_max_hp_2M))
        else:
            msg = _("Max vSwitch hugepage allocation is %s MiB, when 2M is %s "
                    "and 1G is %s" % (hp_requested_mib, new_2M_pages,
                                      new_1G_pages))
        raise wsme.exc.ClientSideError(msg)
    return patch
