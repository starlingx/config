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
# Copyright (c) 2013-2019 Wind River Systems, Inc.
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
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.api.controllers.v1 import cpu_utils
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv import objects

LOG = log.getLogger(__name__)


class CPUPatchType(types.JsonPatchType):

    @staticmethod
    def mandatory_attrs():
        return []


class CPU(base.APIBase):
    """API representation of a host CPU.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of a cpu.
    """

    uuid = types.uuid
    "Unique UUID for this cpu"

    cpu = int
    "Represent the cpu id icpu"

    core = int
    "Represent the core id icpu"

    thread = int
    "Represent the thread id icpu"

    # coprocessors = wtypes.text
    # "Represent the coprocessors of the icpu"

    cpu_family = wtypes.text
    "Represent the cpu family of the icpu"

    cpu_model = wtypes.text
    "Represent the cpu model of the icpu"

    allocated_function = wtypes.text
    "Represent the allocated function of the icpu"

    function = wtypes.text
    "Represent the function of the icpu"

    num_cores_on_processor0 = wtypes.text
    "The number of cores on processors 0"

    num_cores_on_processor1 = wtypes.text
    "The number of cores on processors 1"

    num_cores_on_processor2 = wtypes.text
    "The number of cores on processors 2"

    num_cores_on_processor3 = wtypes.text
    "The number of cores on processors 3"

    numa_node = int
    "The numa node or zone the icpu. API only attribute"

    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                    six.integer_types)}
    "This cpu's meta data"

    forihostid = int
    "The ihostid that this icpu belongs to"

    forinodeid = int
    "The inodeId that this icpu belongs to"

    ihost_uuid = types.uuid
    "The UUID of the ihost this cpu belongs to"

    inode_uuid = types.uuid
    "The UUID of the inode this cpu belongs to"

    links = [link.Link]
    "A list containing a self link and associated cpu links"

    def __init__(self, **kwargs):
        self.fields = list(objects.cpu.fields.keys())
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        # API only attributes
        self.fields.append('function')
        setattr(self, 'function', kwargs.get('function', None))
        self.fields.append('num_cores_on_processor0')
        setattr(self, 'num_cores_on_processor0',
                        kwargs.get('num_cores_on_processor0', None))
        self.fields.append('num_cores_on_processor1')
        setattr(self, 'num_cores_on_processor1',
                        kwargs.get('num_cores_on_processor1', None))
        self.fields.append('num_cores_on_processor2')
        setattr(self, 'num_cores_on_processor2',
                        kwargs.get('num_cores_on_processor2', None))
        self.fields.append('num_cores_on_processor3')
        setattr(self, 'num_cores_on_processor3',
                        kwargs.get('num_cores_on_processor3', None))

    @classmethod
    def convert_with_links(cls, rpc_port, expand=True):
        # fields = ['uuid', 'address'] if not expand else None
        # cpu = icpu.from_rpc_object(rpc_port, fields)

        cpu = CPU(**rpc_port.as_dict())
        if not expand:
            cpu.unset_fields_except(['uuid', 'cpu', 'core',
                               'thread', 'cpu_family',
                               'cpu_model', 'allocated_function',
                               'numa_node', 'ihost_uuid', 'inode_uuid',
                               'forihostid', 'forinodeid',
                               'capabilities',
                               'created_at', 'updated_at'])

        # never expose the id attribute
        cpu.forihostid = wtypes.Unset
        cpu.forinodeid = wtypes.Unset

        cpu.links = [link.Link.make_link('self', pecan.request.host_url,
                                          'icpus', cpu.uuid),
                      link.Link.make_link('bookmark',
                                          pecan.request.host_url,
                                          'icpus', cpu.uuid,
                                          bookmark=True)
                     ]
        return cpu


class CPUCollection(collection.Collection):
    """API representation of a collection of cpus."""

    icpus = [CPU]
    "A list containing cpu objects"

    def __init__(self, **kwargs):
        self._type = 'icpus'

    @classmethod
    def convert_with_links(cls, rpc_ports, limit, url=None,
                           expand=False, **kwargs):
        collection = CPUCollection()
        collection.icpus = [CPU.convert_with_links(
                                      p, expand)
                            for p in rpc_ports]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'CPUController'


class CPUController(rest.RestController):
    """REST controller for icpus."""

    _custom_actions = {
        'detail': ['GET'],
        'vswitch_cpu_list': ['GET'],
        'platform_cpu_list': ['GET'],
    }

    def __init__(self, from_ihosts=False, from_inode=False):
        self._from_ihosts = from_ihosts
        self._from_inode = from_inode

    def _get_cpus_collection(self, i_uuid, inode_uuid, marker,
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
            marker_obj = objects.cpu.get_by_uuid(pecan.request.context,
                                                 marker)

        if self._from_ihosts:
            cpus = pecan.request.dbapi.icpu_get_by_ihost(
                                                    i_uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
        elif self._from_inode:
            cpus = pecan.request.dbapi.icpu_get_by_inode(
                                                    i_uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
        else:
            if i_uuid and not inode_uuid:
                cpus = pecan.request.dbapi.icpu_get_by_ihost(
                                                    i_uuid, limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)
            elif i_uuid and inode_uuid:   # Need ihost_uuid ?
                cpus = pecan.request.dbapi.icpu_get_by_ihost_inode(
                                                    i_uuid,
                                                    inode_uuid,
                                                    limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

            elif inode_uuid:   # Need ihost_uuid ?
                cpus = pecan.request.dbapi.icpu_get_by_ihost_inode(
                                                    i_uuid,  # None
                                                    inode_uuid,
                                                    limit,
                                                    marker_obj,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

            else:
                cpus = pecan.request.dbapi.icpu_get_list(limit, marker_obj,
                                                     sort_key=sort_key,
                                                     sort_dir=sort_dir)

        return CPUCollection.convert_with_links(cpus, limit,
                                                url=resource_url,
                                                expand=expand,
                                                sort_key=sort_key,
                                                sort_dir=sort_dir)

    @wsme_pecan.wsexpose(CPUCollection, types.uuid, types.uuid,
                         types.uuid, int, wtypes.text, wtypes.text)
    def get_all(self, ihost_uuid=None, inode_uuid=None,
                marker=None, limit=None, sort_key='id', sort_dir='asc'):
        """Retrieve a list of cpus."""
        return self._get_cpus_collection(ihost_uuid, inode_uuid,
                                          marker, limit,
                                          sort_key, sort_dir)

    @wsme_pecan.wsexpose(CPUCollection, types.uuid, types.uuid, int,
                         wtypes.text, wtypes.text)
    def detail(self, ihost_uuid=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of cpus with detail."""
        # NOTE(lucasagomes): /detail should only work agaist collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "icpus":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['icpus', 'detail'])
        return self._get_cpus_collection(ihost_uuid, marker, limit, sort_key,
                                          sort_dir, expand, resource_url)

    @wsme_pecan.wsexpose(CPU, types.uuid)
    def get_one(self, cpu_uuid):
        """Retrieve information about the given cpu."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_port = objects.cpu.get_by_uuid(pecan.request.context, cpu_uuid)
        return CPU.convert_with_links(rpc_port)

    @wsme_pecan.wsexpose(wtypes.text, types.uuid)
    def platform_cpu_list(self, host_uuid):
        cpu_list = ''
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "icpus":
            raise exception.HTTPNotFound

        cpus = pecan.request.dbapi.icpu_get_by_ihost(host_uuid)
        cpus_collection = CPUCollection.convert_with_links(cpus, limit=None)
        for i in cpus_collection.icpus:
            if i.allocated_function == constants.PLATFORM_FUNCTION:
                cpu_list = cpu_list + str(i.cpu) + ','
        return cpu_list.rstrip(',')

    @wsme_pecan.wsexpose(wtypes.text, types.uuid)
    def vswitch_cpu_list(self, host_uuid):
        cpu_list = ''
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "icpus":
            raise exception.HTTPNotFound

        cpus = pecan.request.dbapi.icpu_get_by_ihost(host_uuid)
        cpus_collection = CPUCollection.convert_with_links(cpus, limit=None)
        for i in cpus_collection.icpus:
            if i.thread != 0:
                # vswitch only uses the physical cores so there is no need to
                # return any of the hyperthread sibling threads.
                continue
            if i.allocated_function == constants.VSWITCH_FUNCTION:
                cpu_list = cpu_list + str(i.cpu) + ','
        return cpu_list.rstrip(',')

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(CPU, body=CPU)
    def post(self, cpu):
        """Create a new cpu."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        try:
            ihost_uuid = cpu.ihost_uuid
            new_cpu = pecan.request.dbapi.icpu_create(ihost_uuid,
                                                      cpu.as_dict())

        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data"))
        return CPU.convert_with_links(new_cpu)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [CPUPatchType])
    @wsme_pecan.wsexpose(CPU, types.uuid,
                         body=[CPUPatchType])
    # This is a deprecated method.
    # Sysinv api ihosts/<uuid>/state/host_cpus_modify is used for
    # host cpu modification.
    def patch(self, cpu_uuid, patch):
        """Update an existing cpu."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        rpc_port = objects.cpu.get_by_uuid(
                       pecan.request.context, cpu_uuid)

        # only allow patching allocated_function and capabilities
        # replace ihost_uuid and inode_uuid with corresponding
        patch_obj = jsonpatch.JsonPatch(patch)
        from_profile = False
        action = None
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

            if p['path'] == '/allocated_function':
                from_profile = True

            if p['path'] == '/action':
                value = p['value']
                patch.remove(p)
                if value in (constants.APPLY_ACTION, constants.INSTALL_ACTION):
                    action = value

        # Clean up patch
        extra_args = {}
        for p in patch[:]:
            path = p['path']
            if 'num_cores_on_processor' in path:
                extra_args[path.lstrip('/')] = p['value']
                patch.remove(p)
            if path == '/function':
                extra_args[path.lstrip('/')] = p['value']
                patch.remove(p)

        # Apply patch
        try:
            cpu = CPU(**jsonpatch.apply_patch(rpc_port.as_dict(),
                                              patch_obj))
        except utils.JSONPATCH_EXCEPTIONS as e:
            raise exception.PatchError(patch=patch, reason=e)

        for key, val in extra_args.items():
            setattr(cpu, key, val)

        # Semantic checks
        ihost = pecan.request.dbapi.ihost_get(cpu.forihostid)
        _check_host(ihost)
        if not from_profile:
            _check_cpu(cpu, ihost)

        # Update only the fields that have changed
        try:
            for field in objects.cpu.fields:
                if rpc_port[field] != getattr(cpu, field):
                    rpc_port[field] = getattr(cpu, field)

            rpc_port.save()

            if action == constants.APPLY_ACTION:
                # perform rpc to conductor to perform config apply
                pecan.request.rpcapi.update_grub_config(
                    pecan.request.context)

            return CPU.convert_with_links(rpc_port)
        except exception.HTTPNotFound:
            msg = _("Cpu update failed: host %s cpu %s : patch %s"
                    % (ihost.hostname, CPU.uuid, patch))
            raise wsme.exc.ClientSideError(msg)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, types.uuid, status_code=204)
    def delete(self, cpu_uuid):
        """Delete a cpu."""
        if self._from_ihosts:
            raise exception.OperationNotPermitted

        pecan.request.dbapi.icpu_destroy(cpu_uuid)


##############
# UTILS
##############
def _update(cpu_uuid, cpu_values, from_profile=False):
    # Get CPU
    cpu = objects.cpu.get_by_uuid(
                       pecan.request.context, cpu_uuid)

    # Semantic checks
    ihost = pecan.request.dbapi.ihost_get(cpu.forihostid)
    _check_host(ihost)
    if not from_profile:
        _check_cpu(cpu, ihost)

    # Update cpu
    pecan.request.dbapi.icpu_update(cpu_uuid, cpu_values)


def _check_host(ihost):
    if utils.is_aio_simplex_host_unlocked(ihost):
        raise exception.HostMustBeLocked(host=ihost['hostname'])
    elif ihost.administrative != constants.ADMIN_LOCKED and not \
            utils.is_host_simplex_controller(ihost):
        raise wsme.exc.ClientSideError(_('Host must be locked.'))
    if constants.WORKER not in ihost.subfunctions:
        raise wsme.exc.ClientSideError(_('Can only modify worker node cores.'))


def _update_vswitch_cpu_counts(host, cpu, counts, capabilities=None):
    """Update the vswitch counts based on the requested number of cores per
    processor.  This function assumes that the platform cpus are assigned
    first and that all other allocations will be dynamically adjusted based on
    how many cores are remaining.
    """
    vswitch_type = cutils.get_vswitch_type(pecan.request.dbapi)
    for s in range(0, len(host.nodes)):
        if capabilities:
            count = capabilities.get('num_cores_on_processor%d' % s, None)
        else:
            count = getattr(cpu, 'num_cores_on_processor%d' % s, None)

        if count is None:
            continue
        count = int(count)
        if constants.VSWITCH_TYPE_NONE == vswitch_type and count != 0:
            raise wsme.exc.ClientSideError(
                _('vSwitch cpus can only be used with a vswitch_type '
                  'specified.'))
        if count < 0:
            raise wsme.exc.ClientSideError(_('vSwitch cpus must be non-negative.'))
        if host.hyperthreading:
            # the data structures track the number of logical cpus and the
            # API expects the requested count to refer to the number
            # of physical cores requested therefore if HT is enabled then
            # multiply the requested number by 2 so that we always reserve a
            # full physical core
            count *= 2
        counts[s][constants.VSWITCH_FUNCTION] = count
        # let the remaining values grow/shrink dynamically
        counts[s][constants.APPLICATION_FUNCTION] = 0
        counts[s][constants.NO_FUNCTION] = 0
    return counts


def _update_shared_cpu_counts(host, cpu, counts, capabilities=None):
    """Update the shared counts based on the requested number of cores per
    processor.  This function assumes that the platform cpus are assigned
    first and that all other allocations will be dynamically adjusted based on
    how many cores are remaining.
    """
    for s in range(0, len(host.nodes)):
        if capabilities:
            count = capabilities.get('num_cores_on_processor%d' % s, None)
        else:
            count = getattr(cpu, 'num_cores_on_processor%d' % s, None)
        if count is None:
            continue
        count = int(count)
        if count < 0:
            raise wsme.exc.ClientSideError(_('Shared count cannot be < 0.'))
        if count > 1:
            raise wsme.exc.ClientSideError(_('Shared count cannot be > 1.'))
        if host.hyperthreading:
            # the data structures track the number of logical cpus and the
            # API expects the requested count to refer to the number
            # of physical cores requested therefore if HT is enabled then
            # multiply the requested number by 2 so that we always reserve a
            # full physical core
            count *= 2
        counts[s][constants.SHARED_FUNCTION] = count
        # let the remaining values grow/shrink dynamically
        counts[s][constants.APPLICATION_FUNCTION] = 0
        counts[s][constants.NO_FUNCTION] = 0
    return counts


def _update_platform_cpu_counts(host, cpu, counts, capabilities=None):
    """Update the vswitch counts based on the requested number of cores per
    processor.  This function assumes that the platform cpus are assigned
    first and that all other allocations will be dynamically adjusted based on
    how many cores are remaining.
    """
    for s in range(0, len(host.nodes)):
        if capabilities:
            count = capabilities.get('num_cores_on_processor%d' % s, None)
        else:
            count = getattr(cpu, 'num_cores_on_processor%d' % s, None)
        if count is None:
            continue
        count = int(count)
        if count < 0:
            raise wsme.exc.ClientSideError(_('Platform cpus must be non-negative.'))
        if host.hyperthreading:
            # the data structures track the number of logical cpus and the
            # API expects the requested count to refer to the number
            # of physical cores requested therefore if HT is enabled then
            # multiply the requested number by 2 so that we always reserve a
            # full physical core
            count *= 2
        counts[s][constants.PLATFORM_FUNCTION] = count
        # let the remaining values grow/shrink dynamically
        counts[s][constants.APPLICATION_FUNCTION] = 0
        counts[s][constants.NO_FUNCTION] = 0
    return counts


def _update_isolated_cpu_counts(host, cpu, counts, capabilities=None):
    """Update the isolated cpu counts based on the requested number of cores
    per processor.
    """
    for s in range(0, len(host.nodes)):
        if capabilities:
            count = capabilities.get('num_cores_on_processor%d' % s, None)
        else:
            count = getattr(cpu, 'num_cores_on_processor%d' % s, None)
        if count is None:
            continue
        count = int(count)
        if count < 0:
            raise wsme.exc.ClientSideError(
                _('Application-isolated cpus must be non-negative.'))
        if host.hyperthreading:
            # the data structures track the number of logical cpus and the
            # API expects the requested count to refer to the number
            # of physical cores requested therefore if HT is enabled then
            # multiply the requested number by 2 so that we always reserve a
            # full physical core
            count *= 2
        counts[s][constants.ISOLATED_FUNCTION] = count
        # let the remaining values grow/shrink dynamically
        counts[s][constants.APPLICATION_FUNCTION] = 0
        counts[s][constants.NO_FUNCTION] = 0
    return counts


def _check_cpu(cpu, ihost):
    if cpu.function:
        func = cpu_utils.lookup_function(cpu.function)
    else:
        func = cpu_utils.lookup_function(cpu.allocated_function)

    # Check numa nodes
    ihost.nodes = pecan.request.dbapi.inode_get_by_ihost(ihost.uuid)
    num_nodes = len(ihost.nodes)
    if num_nodes < 2 and cpu.num_cores_on_processor1 is not None:
        raise wsme.exc.ClientSideError(_('There is no processor 1 on this host.'))
    if num_nodes < 3 and cpu.num_cores_on_processor2 is not None:
        raise wsme.exc.ClientSideError(_('There is no processor 2 on this host.'))
    if num_nodes < 4 and cpu.num_cores_on_processor3 is not None:
        raise wsme.exc.ClientSideError(_('There is no processor 3 on this host.'))

    # Query the database to get the current set of CPUs and then organize the
    # data by socket and function for convenience.
    ihost.cpus = pecan.request.dbapi.icpu_get_by_ihost(cpu.forihostid)
    cpu_utils.restructure_host_cpu_data(ihost)

    # Get the CPU counts for each socket and function for this host
    cpu_counts = cpu_utils.get_cpu_counts(ihost)

    # Update the CPU counts for each socket and function for this host based
    # on the incoming requested core counts
    if (func.lower() == constants.VSWITCH_FUNCTION.lower()):
        cpu_counts = _update_vswitch_cpu_counts(ihost, cpu, cpu_counts)
    if (func.lower() == constants.SHARED_FUNCTION.lower()):
        cpu_counts = _update_shared_cpu_counts(ihost, cpu, cpu_counts)
    if (func.lower() == constants.PLATFORM_FUNCTION.lower()):
        cpu_counts = _update_platform_cpu_counts(ihost, cpu, cpu_counts)
    if (func.lower() == constants.ISOLATED_FUNCTION.lower()):
        cpu_counts = _update_isolated_cpu_counts(ihost, cpu, cpu_counts)

    # Semantic check to ensure the minimum/maximum values are enforced
    cpu_utils.check_core_allocations(ihost, cpu_counts, func)

    # Update cpu assignments to new values
    cpu_utils.update_core_allocations(ihost, cpu_counts)

    # Find out what function is now assigned to this CPU
    function = cpu_utils.get_cpu_function(ihost, cpu)
    if function == constants.NO_FUNCTION:
        raise wsme.exc.ClientSideError(
            _('Could not determine assigned function for CPU %d' % cpu.cpu))
    cpu.allocated_function = function

    return
