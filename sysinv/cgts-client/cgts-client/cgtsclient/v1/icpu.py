# -*- encoding: utf-8 -*-
#
# Copyright (c) 2013-2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


from cgtsclient._i18n import _
from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['ihost_uuid', 'inode_uuid', 'cpu', 'core', 'thread',
                       'cpu_family', 'cpu_model', 'allocated_function',
                       'numa_node', 'capabilities', 'function',
                       'num_cores_on_processor0', 'num_cores_on_processor1',
                       'num_cores_on_processor2', 'num_cores_on_processor3']

PLATFORM_CPU_TYPE = "Platform"
VSWITCH_CPU_TYPE = "Vswitch"
SHARED_CPU_TYPE = "Shared"
APPLICATION_CPU_TYPE = "Application"
ISOLATED_CPU_TYPE = "Application-isolated"
NONE_CPU_TYPE = "None"

CPU_TYPE_LIST = [PLATFORM_CPU_TYPE, VSWITCH_CPU_TYPE,
                 SHARED_CPU_TYPE, APPLICATION_CPU_TYPE, ISOLATED_CPU_TYPE,
                 NONE_CPU_TYPE]


PLATFORM_CPU_TYPE_FORMAT = _("Platform")
VSWITCH_CPU_TYPE_FORMAT = _("vSwitch")
SHARED_CPU_TYPE_FORMAT = _("Shared")
APPLICATION_CPU_TYPE_FORMAT = _("Application")
ISOLATED_CPU_TYPE_FORMAT = _("Application-isolated")
NONE_CPU_TYPE_FORMAT = _("None")

CPU_TYPE_FORMATS = {PLATFORM_CPU_TYPE: PLATFORM_CPU_TYPE_FORMAT,
                    VSWITCH_CPU_TYPE: VSWITCH_CPU_TYPE_FORMAT,
                    SHARED_CPU_TYPE: SHARED_CPU_TYPE_FORMAT,
                    APPLICATION_CPU_TYPE: APPLICATION_CPU_TYPE_FORMAT,
                    ISOLATED_CPU_TYPE: ISOLATED_CPU_TYPE_FORMAT,
                    NONE_CPU_TYPE: NONE_CPU_TYPE_FORMAT}


def _cpu_function_formatter(allocated_function):
    if allocated_function in CPU_TYPE_FORMATS:
        return CPU_TYPE_FORMATS[allocated_function]
    return "unknown({})".format(allocated_function)


def _cpu_function_tuple_formatter(data):
    return _cpu_function_formatter(data.allocated_function)


class icpu(base.Resource):
    def __repr__(self):
        return "<icpu %s>" % self._info


class icpuManager(base.Manager):
    resource_class = icpu

    def list(self, ihost_id):
        path = '/v1/ihosts/%s/icpus' % ihost_id
        return self._list(path, "icpus")

    def get(self, icpu_id):
        path = '/v1/icpus/%s' % icpu_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        path = '/v1/icpus/'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute(key)
        return self._create(path, new)

    def delete(self, icpu_id):
        path = '/v1/icpus/%s' % icpu_id
        return self._delete(path)

    def update(self, icpu_id, patch):
        path = '/v1/icpus/%s' % icpu_id
        return self._update(path, patch)


class CpuFunction ():
    def __init__(self, function):
        self.allocated_function = function
        self.socket_cores = {}
        self.socket_cores_number = {}


def check_core_functions(personality, icpus):
    platform_cores = 0
    vswitch_cores = 0
    vm_cores = 0
    for cpu in icpus:
        allocated_function = cpu.allocated_function
        if allocated_function == PLATFORM_CPU_TYPE:
            platform_cores += 1
        elif allocated_function == VSWITCH_CPU_TYPE:
            vswitch_cores += 1
        elif allocated_function == APPLICATION_CPU_TYPE:
            vm_cores += 1

    error_string = ""
    if platform_cores == 0:
        error_string = ("There must be at least one core for %s." %
                        PLATFORM_CPU_TYPE_FORMAT)
    elif personality == 'worker' and vswitch_cores == 0:
        error_string = ("There must be at least one core for %s." %
                        VSWITCH_CPU_TYPE_FORMAT)
    elif personality == 'worker' and vm_cores == 0:
        error_string = ("There must be at least one core for %s." %
                        APPLICATION_CPU_TYPE_FORMAT)
    return error_string


def compress_range(c_list):
    c_list.append(999)
    c_list.sort()
    c_sep = ""
    c_item = ""
    c_str = ""
    pn = 0   # pn is not used until second loop anyways
    for n in c_list:
        if not c_item:
            c_item = "%s" % n
        else:
            if n > (pn + 1):
                if int(pn) == int(c_item):
                    c_str = "%s%s%s" % (c_str, c_sep, c_item)
                else:
                    c_str = "%s%s%s-%s" % (c_str, c_sep, c_item, pn)
                c_sep = ","
                c_item = "%s" % n
        pn = n
    return c_str


def restructure_host_cpu_data(host):
    host.core_assignment = []
    if host.cpus:
        host.cpu_model = host.cpus[0].cpu_model
        host.sockets = len(host.nodes)
        host.hyperthreading = "No"
        host.physical_cores = 0

        core_assignment = {}
        number_of_cores = {}
        host.node_min_max_cores = {}

        for cpu in host.cpus:
            if cpu.numa_node == 0 and cpu.thread == 0:
                host.physical_cores += 1
            elif cpu.thread > 0:
                host.hyperthreading = "Yes"

            if cpu.numa_node not in host.node_min_max_cores:
                host.node_min_max_cores[cpu.numa_node] = {'min': 99999, 'max': 0}
            if cpu.cpu < host.node_min_max_cores[cpu.numa_node]['min']:
                host.node_min_max_cores[cpu.numa_node]['min'] = cpu.cpu
            if cpu.cpu > host.node_min_max_cores[cpu.numa_node]['max']:
                host.node_min_max_cores[cpu.numa_node]['max'] = cpu.cpu

            if cpu.allocated_function is None:
                cpu.allocated_function = NONE_CPU_TYPE

            if cpu.allocated_function not in core_assignment:
                core_assignment[cpu.allocated_function] = {}
                number_of_cores[cpu.allocated_function] = {}
            if cpu.numa_node not in core_assignment[cpu.allocated_function]:
                core_assignment[cpu.allocated_function][cpu.numa_node] = [int(cpu.cpu)]
                number_of_cores[cpu.allocated_function][cpu.numa_node] = 1
            else:
                core_assignment[cpu.allocated_function][cpu.numa_node].append(int(cpu.cpu))
                number_of_cores[cpu.allocated_function][cpu.numa_node] = number_of_cores[cpu.allocated_function][cpu.numa_node] + 1

        for f in CPU_TYPE_LIST:
            cpufunction = CpuFunction(f)
            if f in core_assignment:
                host.core_assignment.append(cpufunction)
                for s, cores in core_assignment[f].items():
                    cpufunction.socket_cores[s] = compress_range(cores)
                    cpufunction.socket_cores_number[s] = number_of_cores[f][s]
            else:
                if (f == PLATFORM_CPU_TYPE or (hasattr(host, 'subfunctions')
                                               and 'worker' in host.subfunctions)):
                    if f != NONE_CPU_TYPE:
                        host.core_assignment.append(cpufunction)
                        for s in range(0, len(host.nodes)):
                            cpufunction.socket_cores[s] = ""
                            cpufunction.socket_cores_number[s] = 0
