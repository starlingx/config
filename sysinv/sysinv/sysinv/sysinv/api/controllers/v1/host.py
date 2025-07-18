# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright 2013 Hewlett-Packard Development Company, L.P.
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
# Copyright (c) 2013-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import ast
import cgi
import copy
import datetime
from distutils.version import LooseVersion
import json
import math
import os
import re
import xml.etree.ElementTree as ET
import xml.etree.ElementTree as et
from xml.dom import minidom as dom

import jsonpatch
import netaddr
import pecan
import six
import psutil
import tsconfig.tsconfig as tsc
import wsme
import wsmeext.pecan as wsme_pecan

from wsme import types as wtypes
from fm_api import constants as fm_constants
from pecan import expose
from pecan import rest

from oslo_log import log
from oslo_utils import uuidutils
from sysinv import objects
from sysinv._i18n import _
from sysinv.api.controllers.v1 import ethernet_port
from sysinv.api.controllers.v1 import port
from sysinv.api.controllers.v1 import address as address_api
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import cpu as cpu_api
from sysinv.api.controllers.v1 import cpu_utils
from sysinv.api.controllers.v1 import disk
from sysinv.api.controllers.v1 \
    import kube_rootca_update as kube_rootca_update_api
from sysinv.api.controllers.v1 import partition
from sysinv.api.controllers.v1 import ceph_mon
from sysinv.api.controllers.v1 import interface as interface_api
from sysinv.api.controllers.v1 import lvg as lvg_api
from sysinv.api.controllers.v1 import host_fs as host_fs_api
from sysinv.api.controllers.v1 import memory
from sysinv.api.controllers.v1 import node as node_api
from sysinv.api.controllers.v1 import pv as pv_api
from sysinv.api.controllers.v1 import sensor as sensor_api
from sysinv.api.controllers.v1 import sensorgroup
from sysinv.api.controllers.v1 import storage
from sysinv.api.controllers.v1 import label
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import lldp_agent
from sysinv.api.controllers.v1 import lldp_neighbour
from sysinv.api.controllers.v1 import mtce_api
from sysinv.api.controllers.v1 import pci_device
from sysinv.api.controllers.v1 import route
from sysinv.api.controllers.v1 import sm_api
from sysinv.api.controllers.v1 import state
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils
from sysinv.api.controllers.v1 import interface_network
from sysinv.api.controllers.v1 import interface_datanetwork
from sysinv.api.controllers.v1 import vim_api
from sysinv.api.controllers.v1 import patch_api
from sysinv.api.controllers.v1 import ptp_instance
from sysinv.api.controllers.v1 import ptp_interface
from sysinv.api.controllers.v1 import kernel
from sysinv.api.controllers.v1 import vim
from sysinv.api.policies import ihosts as ihosts_policy
from sysinv.common import ceph
from sysinv.common import constants
from sysinv.common import device
from sysinv.common import exception
from sysinv.common import kubernetes
from sysinv.common import policy
from sysinv.common import usm_service as usm_service
from sysinv.common import utils as cutils
from sysinv.common.storage_backend_conf import StorageBackendConfig
from sysinv.common import health
from sysinv.ipsec_auth.common import constants as ipsec_constants

from sysinv.openstack.common.rpc import common as rpc_common


LOG = log.getLogger(__name__)
KEYRING_BM_SERVICE = "BM"
ERR_CODE_LOCK_SOLE_SERVICE_PROVIDER = "-1003"
HOST_XML_ATTRIBUTES = ['hostname', 'personality', 'subfunctions', 'mgmt_mac',
                       'bm_ip', 'bm_type', 'bm_username',
                       'bm_password', 'boot_device', 'rootfs_device',
                       'hw_settle', 'install_output', 'console',
                       'vsc_controllers', 'power_on', 'location', 'apparmor',
                       'sw_version']


def _get_controller_address(hostname):
    return utils.lookup_static_ip_address(hostname,
                                          constants.NETWORK_TYPE_MGMT)


def _get_storage_address(hostname):
    return utils.lookup_static_ip_address(hostname,
                                          constants.NETWORK_TYPE_MGMT)


class HostProvisionState(state.State):
    @classmethod
    def convert_with_links(cls, rpc_ihost, expand=True):
        provision_state = HostProvisionState()
        provision_state.current = rpc_ihost.provision_state
        url_arg = '%s/state/provision' % rpc_ihost.uuid
        provision_state.links = [link.Link.make_link('self',
                                                     pecan.request.host_url,
                                                     'ihosts', url_arg),
                                 link.Link.make_link('bookmark',
                                                     pecan.request.host_url,
                                                     'ihosts', url_arg,
                                                     bookmark=True)
                                 ]
        if expand:
            provision_state.target = rpc_ihost.target_provision_state
            # TODO(lucasagomes): get_next_provision_available_states
            provision_state.available = []
        return provision_state


class HostProvisionStateController(rest.RestController):
    # GET ihosts/<uuid>/state/provision
    @wsme_pecan.wsexpose(HostProvisionState, six.text_type)
    def get(self, ihost_id):
        ihost = objects.host.get_by_uuid(pecan.request.context,
                                         ihost_id)

        provision_state = HostProvisionState.convert_with_links(ihost)
        return provision_state

    # PUT ihosts/<uuid>/state/provision
    @wsme_pecan.wsexpose(HostProvisionState, six.text_type, six.text_type, status=202)
    def put(self, ihost_id, target):
        """Set the provision state of the machine."""
        # TODO(lucasagomes): Test if target is a valid state and if it's able
        # to transition to the target state from the current one
        # TODO(lucasagomes): rpcapi.start_provision_state_change()
        raise NotImplementedError()


LOCK_NAME_STATE = 'HostStatesController'


class HostStates(base.APIBase):
    """API representation of the states of a ihost."""

    # power = ihostPowerState
    # "The current power state of the ihost"

    provision = HostProvisionState
    "The current provision state of the ihost"

    @classmethod
    def convert_with_links(cls, rpc_ihost):
        states = HostStates()
        # states.power = ihostPowerState.convert_with_links(rpc_ihost,
        #                                                 expand=False)
        states.provision = HostProvisionState.convert_with_links(
            rpc_ihost,
            expand=False)
        return states


class HostStatesController(rest.RestController):
    _custom_actions = {
        'host_cpus_modify': ['PUT'],
        'update_install_uuid': ['PUT'],
    }

    # GET ihosts/<uuid>/state
    @wsme_pecan.wsexpose(HostStates, six.text_type)
    def get(self, ihost_id):
        """List or update the state of a ihost."""
        ihost = objects.host.get_by_uuid(pecan.request.context,
                                         ihost_id)
        ihost['mgmt_ip'] = utils.get_mgmt_ip(ihost.hostname)
        state = HostStates.convert_with_links(ihost)
        return state

    def _get_host_cpus_collection(self, host_uuid):
        cpus = pecan.request.dbapi.icpu_get_by_ihost(host_uuid)
        return cpu_api.CPUCollection.convert_with_links(cpus,
                                                        limit=None,
                                                        url=None,
                                                        expand=None,
                                                        sort_key=None,
                                                        sort_dir=None)

    # PUT ihosts/<uuid>/state/update_install_uuid
    @cutils.synchronized(LOCK_NAME_STATE)
    @wsme_pecan.wsexpose(HostStates, types.uuid, body=six.text_type)
    def update_install_uuid(self, host_uuid, install_uuid):
        """ Update install_uuid in /etc/platform/platform.conf
            on the specified host.
            :param host_uuid: UUID of the host
            :param install_uuid: install_uuid.
        """
        LOG.info("update_install_uuid host_uuid=%s install_uuid=%s" %
                 (host_uuid, install_uuid))

        pecan.request.rpcapi.update_install_uuid(pecan.request.context,
                                                 host_uuid,
                                                 install_uuid)

    # PUT ihosts/<uuid>/state/host_cpus_modify
    @cutils.synchronized(cpu_api.LOCK_NAME)
    @wsme_pecan.wsexpose(cpu_api.CPUCollection, types.uuid, body=[six.text_type])
    def host_cpus_modify(self, host_uuid, capabilities):
        """ Perform bulk host cpus modify.
            :param host_uuid: UUID of the host
            :param capabilities: dictionary of update cpu function and sockets.

        Example:
        capabilities=[{'function': 'platform', 'sockets': [{'0': 1}, {'1': 0}]},
                      {'function': 'vswitch', 'sockets': [{'0': 2}]},
                      {'function': 'shared', 'sockets': [{'0': 1}, {'1': 1}]},
                      {'function': 'application-isolated', 'cpulist': '3-5,6'}]
        """
        LOG.info("host_cpus_modify host_uuid=%s capabilities=%s" %
                 (host_uuid, capabilities))

        ihost = pecan.request.dbapi.ihost_get(host_uuid)
        cpu_api._check_host(ihost)

        ihost.nodes = pecan.request.dbapi.inode_get_by_ihost(ihost.uuid)
        num_nodes = len(ihost.nodes)

        # Query the database to get the current set of CPUs
        ihost.cpus = pecan.request.dbapi.icpu_get_by_ihost(ihost.uuid)

        # Perform basic sanity on the input
        for icap in capabilities:
            specified_function = icap.get('function', None)
            specified_sockets = icap.get('sockets', [])
            specified_cpulist = icap.get('cpulist', None)

            if specified_sockets and specified_cpulist:
                raise wsme.exc.ClientSideError(
                    _('host %s:  socket=%s and cpulist=%s may not both be specified') %
                    (host_uuid, specified_sockets, specified_cpulist))

            if not specified_function or not (specified_sockets or specified_cpulist):
                raise wsme.exc.ClientSideError(
                    _('host %s:  cpu function=%s or (socket=%s and cpulist=%s) '
                      'not specified') % (host_uuid,
                                          specified_function,
                                          specified_sockets,
                                          specified_cpulist))

            for specified_socket in specified_sockets:
                socket, value = list(specified_socket.items())[0]
                if int(socket) >= num_nodes:
                    raise wsme.exc.ClientSideError(
                        _('There is no Processor (Socket) '
                           '%s on this host.') % socket)
                if int(value) < 0:
                    raise wsme.exc.ClientSideError(
                        _('Specified cpu values must be non-negative.'))

            # Ensure that the cpulist is valid if set
            if specified_cpulist:
                # make a list of CPU numbers (which are not necessarily contiguous)
                host_cpus = [ihost_cpu.cpu for ihost_cpu in ihost.cpus]
                cpulist = cutils.parse_range_set(specified_cpulist)
                if max(cpulist) > max(host_cpus):
                    raise wsme.exc.ClientSideError(
                        _('Specified cpulist contains nonexistant CPUs.'))

        # organize the cpus by socket and function for convenience.
        cpu_utils.restructure_host_cpu_data(ihost)

        # Get the CPU counts for each socket and function for this host
        cpu_counts = cpu_utils.get_cpu_counts(ihost)

        cpu_lists = {}

        # Update the CPU counts and cpulists based on the provided values
        for cap in capabilities:
            function = cap.get('function', None)
            # Normalize the function input
            for const_function in constants.CPU_FUNCTIONS:
                if const_function.lower() == function.lower():
                    function = const_function
            sockets = cap.get('sockets', [])
            # If this function is specified via cpulist, reset count to zero.
            if not sockets:
                for numa_node in cpu_counts:
                    cpu_counts[numa_node][function] = 0
            for numa in sockets:
                numa_node, value = list(numa.items())[0]
                numa_node = int(numa_node)
                value = int(value)
                if ihost.hyperthreading:
                    value *= 2
                cpu_counts[numa_node][function] = value

            # Store the cpu ranges per CPU function as well if any exist
            cpu_range = cap.get('cpulist', None)
            cpu_list = cutils.parse_range_set(cpu_range)
            # Uncomment the following line to add any missing HT siblings
            # cpu_list = cpu_utils.append_ht_sibling(ihost, cpu_list)
            cpu_lists[function] = cpu_list

        # Semantic check to ensure the minimum/maximum values are enforced
        cpu_utils.check_core_allocations(ihost, cpu_counts, cpu_lists)

        # Update cpu assignments to new values
        cpu_utils.update_core_allocations(ihost, cpu_counts, cpu_lists)

        # Check drbd limistaion for platform function cpu
        cpu_utils.check_drbd_platform_limitation(ihost)

        for cpu in ihost.cpus:
            function = cpu_utils.get_cpu_function(ihost, cpu)
            if function == constants.NO_FUNCTION:
                raise wsme.exc.ClientSideError(_('Could not determine '
                    'assigned function for CPU %d' % cpu.cpu))
            if (not cpu.allocated_function or
               cpu.allocated_function.lower() != function.lower()):
                values = {'allocated_function': function}
                LOG.info("icpu_update uuid=%s value=%s" %
                         (cpu.uuid, values))
                pecan.request.dbapi.icpu_update(cpu.uuid, values)

        # perform inservice apply
        pecan.request.rpcapi.update_grub_config(pecan.request.context,
                                                host_uuid)

        return self._get_host_cpus_collection(ihost.uuid)


class Host(base.APIBase):
    """API representation of a host.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation
    of an ihost.
    """

    # NOTE: translate 'id' publicly to 'uuid' internally
    id = int

    uuid = wtypes.text
    hostname = wtypes.text

    invprovision = wtypes.text
    "Represent the current (not transition) provision state of the ihost"

    mgmt_mac = wtypes.text
    "Represent the provisioned Boot mgmt MAC address of the ihost."

    mgmt_ip = wtypes.text
    "Represent the provisioned Boot mgmt IP address of the ihost."

    bm_ip = wtypes.text
    "Discovered board management IP address of the ihost."

    bm_type = wtypes.text
    "Represent the board management type of the ihost."

    bm_username = wtypes.text
    "Represent the board management username of the ihost."

    bm_password = wtypes.text
    "Represent the board management password of the ihost."

    personality = wtypes.text
    "Represent the personality of the ihost"

    subfunctions = wtypes.text
    "Represent the subfunctions of the ihost"

    subfunction_oper = wtypes.text
    "Represent the subfunction operational state of the ihost"

    subfunction_avail = wtypes.text
    "Represent the subfunction availability status of the ihost"

    # target_provision_state = wtypes.text
    # "The user modified desired provision state of the ihost."

    # NOTE: allow arbitrary dicts for driver_info and extra so that drivers
    #       and vendors can expand on them without requiring API changes.
    # NOTE: translate 'driver_info' internally to 'management_configuration'
    serialid = wtypes.text

    administrative = wtypes.text
    operational = wtypes.text
    availability = wtypes.text

    # The 'action' field is used for action based administration compared
    # to existing state change administration.
    # Actions like 'reset','reboot', and 'reinstall' are now supported
    # by this new method along with 'lock' and 'unlock'.
    action = wtypes.text

    ihost_action = wtypes.text
    'Represent the current action task in progress'

    inv_state = wtypes.text
    'Represent the inventory state'

    vim_progress_status = wtypes.text
    'Represent the vim progress status'

    task = wtypes.text
    "Represent the mtce task state"

    mtce_info = wtypes.text
    "Represent the mtce info"

    reserved = types.boolean

    config_status = wtypes.text
    "Represent the configuration status of this ihost."

    config_applied = wtypes.text
    "Represent the configuration already applied to this ihost."

    config_target = wtypes.text
    "Represent the configuration which needs to be applied to this ihost."

    clock_synchronization = wtypes.text
    "Represent the clock synchronization type of this ihost."

    # Host uptime
    uptime = int

    # NOTE: properties should use a class to enforce required properties
    #       current list: arch, cpus, disk, ram, image
    location = {wtypes.text: utils.ValidTypes(wtypes.text, six.integer_types)}
    capabilities = {wtypes.text: utils.ValidTypes(wtypes.text,
                                                  six.integer_types)}

    # NOTE: translate 'isystem_id' to a link to the isystem resource
    #       and accept a isystem uuid when creating an ihost.
    #       (Leaf not ihost)

    forisystemid = int

    isystem_uuid = types.uuid
    "The UUID of the system this host belongs to"

    peers = types.MultiType({dict})
    "This peers of this host in the cluster"

    links = [link.Link]
    "A list containing a self link and associated ihost links"

    iinterfaces = [link.Link]
    "Links to the collection of iinterfaces on this ihost"

    ports = [link.Link]
    "Links to the collection of Ports on this ihost"

    ethernet_ports = [link.Link]
    "Links to the collection of EthernetPorts on this ihost"

    inodes = [link.Link]
    "Links to the collection of inodes on this ihost"

    icpus = [link.Link]
    "Links to the collection of icpus on this ihost"

    imemorys = [link.Link]
    "Links to the collection of imemorys on this ihost"

    istors = [link.Link]
    "Links to the collection of istors on this ihost"

    idisks = [link.Link]
    "Links to the collection of idisks on this ihost"

    partitions = [link.Link]
    "Links to the collection of partitions on this ihost"

    ceph_mon = [link.Link]
    "Links to the collection of ceph monitors on this ihost"

    ipvs = [link.Link]
    "Links to the collection of ipvs on this ihost"

    ilvgs = [link.Link]
    "Links to the collection of ilvgs on this ihost"

    host_fs = [link.Link]
    "Links to the collection of host_fs on this ihost"

    kube_update_ca = [link.Link]
    "Links to the collection of kube_update_ca on this ihost"

    isensors = [link.Link]
    "Links to the collection of isensors on this ihost"

    isensorgroups = [link.Link]
    "Links to the collection of isensorgruops on this ihost"

    pci_devices = [link.Link]
    "Links to the collection of pci_devices on this host"

    lldp_agents = [link.Link]
    "Links to the collection of LldpAgents on this ihost"

    lldp_neighbours = [link.Link]
    "Links to the collection of LldpNeighbours on this ihost"

    labels = [link.Link]
    "Links to the collection of labels assigned to this host"

    boot_device = wtypes.text
    rootfs_device = wtypes.text
    hw_settle = wtypes.text
    install_output = wtypes.text
    console = wtypes.text
    tboot = wtypes.text

    vsc_controllers = wtypes.text
    "Represent the VSC controllers used by this ihost."

    ttys_dcd = types.boolean
    "Enable or disable serial console carrier detect"

    apparmor = wtypes.text
    "Enable/Disable apparmor state"

    install_state = wtypes.text
    "Represent the install state"

    install_state_info = wtypes.text
    "Represent install state extra information if there is any"

    max_cpu_mhz_configured = wtypes.text
    "Represent the CPU max frequency"

    min_cpu_mhz_allowed = wtypes.text
    "Represent the default CPU min frequency"

    max_cpu_mhz_allowed = wtypes.text
    "Represent the default CPU max frequency"

    cstates_available = wtypes.text
    "Represent the CStates available to use"

    iscsi_initiator_name = wtypes.text
    "The iscsi initiator name (only used for worker hosts)"

    nvme_host_id = wtypes.text
    "The NVMe Host ID"

    nvme_host_nqn = wtypes.text
    "The NVMe Host NQN"

    device_image_update = wtypes.text
    "Represent the status of device image update of this ihost."

    reboot_needed = types.boolean
    " Represent whether a reboot is needed after device image update"

    sw_version = wtypes.text
    "The host software version."

    def __init__(self, **kwargs):
        self.fields = list(objects.host.fields.keys())
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        self.fields.append('peers')
        setattr(self, 'peers', kwargs.get('peers', None))

    @classmethod
    def convert_with_links(cls, rpc_ihost, expand=True):
        minimum_fields = ['id', 'uuid', 'hostname', 'personality',
                          'subfunctions', 'subfunction_oper',
                          'subfunction_avail', 'administrative', 'operational',
                          'availability', 'invprovision', 'task', 'mtce_info',
                          'action', 'uptime', 'reserved', 'ihost_action',
                          'vim_progress_status', 'mgmt_mac', 'mgmt_ip',
                          'location', 'bm_ip', 'bm_type', 'bm_username',
                          'isystem_uuid', 'capabilities', 'serialid',
                          'config_status', 'config_applied', 'config_target',
                          'created_at', 'updated_at', 'boot_device',
                          'rootfs_device', 'hw_settle', 'install_output',
                          'console', 'tboot', 'vsc_controllers', 'ttys_dcd',
                          'peers', 'peer_id',
                          'install_state', 'install_state_info',
                          'iscsi_initiator_name', 'device_image_update',
                          'reboot_needed', 'inv_state', 'clock_synchronization',
                          'max_cpu_mhz_configured', 'min_cpu_mhz_allowed',
                          'max_cpu_mhz_allowed', 'cstates_available',
                          'apparmor', 'nvme_host_id', 'nvme_host_nqn', 'sw_version']

        fields = minimum_fields if not expand else None
        uhost = Host.from_rpc_object(rpc_ihost, fields)
        uhost.links = [link.Link.make_link('self', pecan.request.host_url,
                                           'ihosts', uhost.uuid),
                       link.Link.make_link('bookmark',
                                           pecan.request.host_url,
                                           'ihosts', uhost.uuid,
                                           bookmark=True)
                       ]
        if expand:
            uhost.iinterfaces = [link.Link.make_link('self',
                                                     pecan.request.host_url,
                                                     'ihosts',
                                                     uhost.uuid + "/iinterfaces"),
                                 link.Link.make_link(
                                     'bookmark',
                                     pecan.request.host_url,
                                     'ihosts',
                                     uhost.uuid + "/iinterfaces",
                                     bookmark=True)
                                 ]
            uhost.ports = [link.Link.make_link('self',
                                               pecan.request.host_url,
                                               'ihosts',
                                               uhost.uuid + "/ports"),
                           link.Link.make_link(
                               'bookmark',
                               pecan.request.host_url,
                               'ihosts',
                               uhost.uuid + "/ports",
                               bookmark=True)
                           ]
            uhost.ethernet_ports = [link.Link.make_link('self',
                                                        pecan.request.host_url,
                                                        'ihosts',
                                                        uhost.uuid + "/ethernet_ports"),
                                    link.Link.make_link(
                                        'bookmark',
                                        pecan.request.host_url,
                                        'ihosts',
                                        uhost.uuid + "/ethernet_ports",
                                        bookmark=True)
                                    ]
            uhost.inodes = [link.Link.make_link('self',
                                                pecan.request.host_url,
                                                'ihosts',
                                                uhost.uuid + "/inodes"),
                            link.Link.make_link(
                                'bookmark',
                                pecan.request.host_url,
                                'ihosts',
                                uhost.uuid + "/inodes",
                                bookmark=True)
                            ]
            uhost.icpus = [link.Link.make_link('self',
                                               pecan.request.host_url,
                                               'ihosts',
                                               uhost.uuid + "/icpus"),
                           link.Link.make_link(
                               'bookmark',
                               pecan.request.host_url,
                               'ihosts',
                               uhost.uuid + "/icpus",
                               bookmark=True)
                           ]

            uhost.imemorys = [link.Link.make_link('self',
                                                  pecan.request.host_url,
                                                  'ihosts',
                                                  uhost.uuid + "/imemorys"),
                              link.Link.make_link(
                                  'bookmark',
                                  pecan.request.host_url,
                                  'ihosts',
                                  uhost.uuid + "/imemorys",
                                  bookmark=True)
                              ]

            uhost.istors = [link.Link.make_link('self',
                                                pecan.request.host_url,
                                                'ihosts',
                                                uhost.uuid + "/istors"),
                            link.Link.make_link(
                                'bookmark',
                                pecan.request.host_url,
                                'ihosts',
                                uhost.uuid + "/istors",
                                bookmark=True)
                            ]

            uhost.idisks = [link.Link.make_link('self',
                                                pecan.request.host_url,
                                                'ihosts',
                                                uhost.uuid + "/idisks"),
                            link.Link.make_link(
                                'bookmark',
                                pecan.request.host_url,
                                'ihosts',
                                uhost.uuid + "/idisks",
                                bookmark=True)
                            ]

            uhost.partitions = [link.Link.make_link('self',
                                                    pecan.request.host_url,
                                                    'ihosts',
                                                    uhost.uuid + "/partitions"),
                                link.Link.make_link(
                                'bookmark',
                                pecan.request.host_url,
                                'ihosts',
                                uhost.uuid + "/partitions",
                                bookmark=True)
                                ]

            uhost.ceph_mon = [link.Link.make_link('self',
                                                  pecan.request.host_url,
                                                  'ihosts',
                                                  uhost.uuid + "/ceph_mon"),
                              link.Link.make_link(
                                  'bookmark',
                                  pecan.request.host_url,
                                  'ihosts',
                                  uhost.uuid + "/ceph_mon",
                                  bookmark=True)
                              ]

            uhost.ipvs = [link.Link.make_link('self',
                                              pecan.request.host_url,
                                              'ihosts',
                                              uhost.uuid + "/ipvs"),
                          link.Link.make_link(
                              'bookmark',
                              pecan.request.host_url,
                              'ihosts',
                              uhost.uuid + "/ipvs",
                              bookmark=True)
                          ]

            uhost.ilvgs = [link.Link.make_link('self',
                                               pecan.request.host_url,
                                               'ihosts',
                                               uhost.uuid + "/ilvgs"),
                           link.Link.make_link(
                               'bookmark',
                               pecan.request.host_url,
                               'ihosts',
                               uhost.uuid + "/ilvgs",
                               bookmark=True)
                           ]

            uhost.host_fs = [link.Link.make_link('self',
                                                 pecan.request.host_url,
                                                 'ihosts',
                                                 uhost.uuid + "/host_fs"),
                             link.Link.make_link(
                                 'bookmark',
                                 pecan.request.host_url,
                                 'ihosts',
                                 uhost.uuid + "/host_fs",
                                 bookmark=True)
                             ]

            uhost.kube_update_ca = [
                             link.Link.make_link('self',
                                 pecan.request.host_url,
                                 'ihosts',
                                 uhost.uuid + "/kube_update_ca"),
                             link.Link.make_link(
                                 'bookmark',
                                 pecan.request.host_url,
                                 'ihosts',
                                 uhost.uuid + "/kube_update_ca",
                                 bookmark=True)
                            ]

            uhost.isensors = [link.Link.make_link('self',
                                                  pecan.request.host_url,
                                                  'ihosts',
                                                  uhost.uuid + "/isensors"),
                              link.Link.make_link('bookmark',
                                                  pecan.request.host_url,
                                                  'ihosts',
                                                  uhost.uuid + "/isensors",
                                                  bookmark=True)
                              ]

            uhost.isensorgroups = [link.Link.make_link('self',
                                                       pecan.request.host_url,
                                                       'ihosts',
                                                       uhost.uuid + "/isensorgroups"),
                                   link.Link.make_link('bookmark',
                                                       pecan.request.host_url,
                                                       'ihosts',
                                                       uhost.uuid + "/isensorgroups",
                                                       bookmark=True)
                                   ]

            uhost.pci_devices = [link.Link.make_link('self',
                                                     pecan.request.host_url,
                                                     'ihosts',
                                                     uhost.uuid + "/pci_devices"),
                                 link.Link.make_link('bookmark',
                                                     pecan.request.host_url,
                                                     'ihosts',
                                                     uhost.uuid + "/pci_devices",
                                                     bookmark=True)
                                 ]

            uhost.lldp_agents = [
                link.Link.make_link('self',
                                    pecan.request.host_url,
                                    'ihosts',
                                    uhost.uuid + "/lldp_agents"),
                link.Link.make_link('bookmark',
                                    pecan.request.host_url,
                                    'ihosts',
                                    uhost.uuid + "/lldp_agents",
                                    bookmark=True)
                                 ]

            uhost.lldp_neighbours = [
                link.Link.make_link('self',
                                    pecan.request.host_url,
                                    'ihosts',
                                    uhost.uuid + "/lldp_neighbours"),
                link.Link.make_link('bookmark',
                                    pecan.request.host_url,
                                    'ihosts',
                                    uhost.uuid + "/lldp_neighbours",
                                    bookmark=True)
                                     ]

            uhost.labels = [link.Link.make_link('self',
                                                pecan.request.host_url,
                                                'ihosts',
                                                uhost.uuid + "/labels"),
                            link.Link.make_link('bookmark',
                                                pecan.request.host_url,
                                                'ihosts',
                                                uhost.uuid + "/labels",
                                                bookmark=True)
                            ]
        # Don't expose the vsc_controllers field if we are not configured with
        # the nuage_vrs vswitch or we are not a worker node.
        vswitch_type = utils.get_vswitch_type()
        if (vswitch_type != constants.VSWITCH_TYPE_NUAGE_VRS or
                uhost.personality != constants.WORKER):
            uhost.vsc_controllers = wtypes.Unset

        uhost.peers = None
        if uhost.peer_id:  # pylint: disable=no-member
            ipeers = pecan.request.dbapi.peer_get(uhost.peer_id)  # pylint: disable=no-member
            uhost.peers = {'name': ipeers.name, 'hosts': ipeers.hosts}

        return uhost


class HostCollection(collection.Collection):
    """API representation of a collection of ihosts."""

    ihosts = [Host]
    "A list containing ihosts objects"

    def __init__(self, **kwargs):
        self._type = 'ihosts'

    @classmethod
    def convert_with_links(cls, ihosts, limit, url=None,
                           expand=False, **kwargs):
        collection = HostCollection()
        collection.ihosts = [
            Host.convert_with_links(n, expand) for n in ihosts]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


class HostUpdate(object):
    """Host update helper class.
    """

    CONTINUE = "continue"
    EXIT_RETURN_HOST = "exit_return_host"
    EXIT_UPDATE_PREVAL = "exit_update_preval"
    FAILED = "failed"
    PASSED = "passed"

    # Allow mtce to do the SWACT and FORCE_SWACT?
    ACTIONS_TO_TASK_DISPLAY_CHOICES = (
        (None, _("")),
        ("", _("")),
        (constants.UNLOCK_ACTION, _("Unlocking")),
        (constants.FORCE_UNLOCK_ACTION, _("Force Unlocking")),
        (constants.LOCK_ACTION, _("Locking")),
        (constants.FORCE_LOCK_ACTION, _("Force Locking")),
        (constants.FORCE_UNSAFE_LOCK_ACTION, _("Unsafely Force Locking")),
        (constants.RESET_ACTION, _("Resetting")),
        (constants.REBOOT_ACTION, _("Rebooting")),
        (constants.REINSTALL_ACTION, _("Reinstalling")),
        (constants.POWERON_ACTION, _("Powering-on")),
        (constants.POWEROFF_ACTION, _("Powering-off")),
        (constants.SWACT_ACTION, _("Swacting")),
        (constants.FORCE_SWACT_ACTION, _("Force-Swacting")),
    )

    def __init__(self, ihost_orig, ihost_patch, delta):

        self.ihost_orig = dict(ihost_orig)
        self.ihost_patch = dict(ihost_patch)
        self._delta = list(delta)
        self._ihost_val_prenotify = {}
        self._ihost_val = {}

        self._configure_required = False
        self._notify_vim = False
        self._notify_mtce = False
        self._notify_availability = None
        self._notify_vim_add_host = False
        self._notify_action_lock = False
        self._notify_action_lock_force = False
        self._notify_action_lock_force_unsafe = False
        self._skip_notify_mtce = False
        self._bm_type_changed_to_none = False
        self._nextstep = self.CONTINUE

        self._action = None
        self.displayid = ihost_patch.get('hostname')
        if not self.displayid:
            self.displayid = ihost_patch.get('uuid')

        LOG.debug("ihost_orig=%s, ihost_patch=%s, delta=%s" %
                  (self.ihost_orig, self.ihost_patch, self.delta))

    @property
    def action(self):
        return self._action

    @action.setter
    def action(self, val):
        self._action = val

    @property
    def delta(self):
        return self._delta

    @property
    def nextstep(self):
        return self._nextstep

    @nextstep.setter
    def nextstep(self, val):
        self._nextstep = val

    @property
    def configure_required(self):
        return self._configure_required

    @configure_required.setter
    def configure_required(self, val):
        self._configure_required = val

    @property
    def bm_type_changed_to_none(self):
        return self._bm_type_changed_to_none

    @bm_type_changed_to_none.setter
    def bm_type_changed_to_none(self, val):
        self._bm_type_changed_to_none = val

    @property
    def notify_vim_add_host(self):
        return self._notify_vim_add_host

    @notify_vim_add_host.setter
    def notify_vim_add_host(self, val):
        self._notify_vim_add_host = val

    @property
    def skip_notify_mtce(self):
        return self._skip_notify_mtce

    @skip_notify_mtce.setter
    def skip_notify_mtce(self, val):
        self._skip_notify_mtce = val

    @property
    def notify_action_lock(self):
        return self._notify_action_lock

    @notify_action_lock.setter
    def notify_action_lock(self, val):
        self._notify_action_lock = val

    @property
    def notify_action_lock_force(self):
        return self._notify_action_lock_force

    @notify_action_lock_force.setter
    def notify_action_lock_force(self, val):
        self._notify_action_lock_force = val

    @property
    def notify_action_lock_force_unsafe(self):
        return self._notify_action_lock_force_unsafe

    @notify_action_lock_force_unsafe.setter
    def notify_action_lock_force_unsafe(self, val):
        self._notify_action_lock_force_unsafe = val

    @property
    def ihost_val_prenotify(self):
        return self._ihost_val_prenotify

    def ihost_val_prenotify_update(self, val):
        self._ihost_val_prenotify.update(val)

    @property
    def ihost_val(self):
        return self._ihost_val

    def ihost_val_update(self, val):
        self._ihost_val.update(val)

    @property
    def notify_vim(self):
        return self._notify_vim

    @notify_vim.setter
    def notify_vim(self, val):
        self._notify_vim = val

    @property
    def notify_mtce(self):
        return self._notify_mtce

    @notify_mtce.setter
    def notify_mtce(self, val):
        self._notify_mtce = val

    @property
    def notify_availability(self):
        return self._notify_availability

    @notify_availability.setter
    def notify_availability(self, val):
        self._notify_availability = val

    def get_task_from_action(self, action):
        """Lookup the task value in the action to task dictionary."""

        display_choices = self.ACTIONS_TO_TASK_DISPLAY_CHOICES

        display_value = [display for (value, display) in display_choices
                         if value and value.lower() == (action or '').lower()]

        if display_value:
            return display_value[0]
        return None


LOCK_NAME = 'HostController'
LOCK_NAME_SYS = 'HostControllerSys'


class HostController(rest.RestController):
    """REST controller for ihosts."""

    state = HostStatesController()
    "Expose the state controller action as a sub-element of ihosts"

    iinterfaces = interface_api.InterfaceController(
        from_ihosts=True)
    "Expose iinterfaces as a sub-element of ihosts"

    ports = port.PortController(
        from_ihosts=True)
    "Expose ports as a sub-element of ihosts"

    ethernet_ports = ethernet_port.EthernetPortController(
        from_ihosts=True)
    "Expose ethernet_ports as a sub-element of ihosts"

    inodes = node_api.NodeController(from_ihosts=True)
    "Expose inodes as a sub-element of ihosts"

    icpus = cpu_api.CPUController(from_ihosts=True)
    "Expose icpus as a sub-element of ihosts"

    imemorys = memory.MemoryController(from_ihosts=True)
    "Expose imemorys as a sub-element of ihosts"

    istors = storage.StorageController(from_ihosts=True)
    "Expose istors as a sub-element of ihosts"

    idisks = disk.DiskController(from_ihosts=True)
    "Expose idisks as a sub-element of ihosts"

    partitions = partition.PartitionController(from_ihosts=True)
    "Expose partitions as a sub-element of ihosts"

    ceph_mon = ceph_mon.CephMonController(from_ihosts=True)
    "Expose ceph_mon as a sub-element of ihosts"

    ipvs = pv_api.PVController(from_ihosts=True)
    "Expose ipvs as a sub-element of ihosts"

    ilvgs = lvg_api.LVGController(from_ihosts=True)
    "Expose ilvgs as a sub-element of ihosts"

    host_fs = host_fs_api.HostFsController(from_ihosts=True)
    "Expose host_fs as a sub-element of ihosts"

    kube_update_ca = \
        kube_rootca_update_api.KubeRootCAHostUpdateController(from_ihosts=True)
    "Expose kube_update_ca as a sub-element of ihosts"

    addresses = address_api.AddressController(parent="ihosts")
    "Expose addresses as a sub-element of ihosts"

    routes = route.RouteController(parent="ihosts")
    "Expose routes as a sub-element of ihosts"

    isensors = sensor_api.SensorController(from_ihosts=True)
    "Expose isensors as a sub-element of ihosts"

    isensorgroups = sensorgroup.SensorGroupController(from_ihosts=True)
    "Expose isensorgroups as a sub-element of ihosts"

    pci_devices = pci_device.PCIDeviceController(from_ihosts=True)
    "Expose pci_devices as a sub-element of ihosts"

    lldp_agents = lldp_agent.LLDPAgentController(
        from_ihosts=True)
    "Expose lldp_agents as a sub-element of ihosts"

    lldp_neighbours = lldp_neighbour.LLDPNeighbourController(
        from_ihosts=True)
    "Expose lldp_neighbours as a sub-element of ihosts"

    labels = label.LabelController(from_ihosts=True)
    "Expose labels as a sub-element of ihosts"

    interface_networks = interface_network.InterfaceNetworkController(
        parent="ihosts")
    "Expose interface_networks as a sub-element of ihosts"

    interface_datanetworks = interface_datanetwork.InterfaceDataNetworkController(
        parent="ihosts")
    "Expose interface_datanetworks as a sub-element of ihosts"

    ptp_instances = ptp_instance.PtpInstanceController(from_ihosts=True)
    "Expose PTP instances as a sub-element of ihosts"

    ptp_interfaces = ptp_interface.PtpInterfaceController(parent="ihosts")
    "Expose PTP interfaces as a sub-element of ihosts"

    kernel = kernel.KernelController()
    "Expose kernel as a sub-element of ihosts"

    vim = vim.VIMController()
    "Expose vim as a sub-element of ihosts"

    _custom_actions = {
        'detail': ['GET'],
        'bulk_add': ['POST'],
        'bulk_export': ['GET'],
        'upgrade': ['POST'],
        'downgrade': ['POST'],
        'install_progress': ['POST'],
        'wipe_osds': ['GET'],
        'update_mgmt_ipsec_state': ['POST'],
        'mgmt_ip': ['GET'],
        'kube_upgrade_control_plane': ['POST'],
        'kube_upgrade_kubelet': ['POST'],
        'device_image_update': ['POST'],
        'device_image_update_abort': ['POST'],
    }

    def __init__(self, from_isystem=False):
        self._from_isystem = from_isystem
        self._mtc_address = constants.LOCALHOST_HOSTNAME
        self._mtc_port = 2112
        self._ceph = ceph.CephApiOperator()
        self._kube_operator = kubernetes.KubeOperator()

        self._api_token = None
        # self._name = 'api-host'

    @wsme_pecan.wsexpose(six.text_type, wtypes.text, body=six.text_type)
    def update_mgmt_ipsec_state(self, uuid, data):
        # Ensure data has valid value
        if data not in [constants.MGMT_IPSEC_ENABLING,
                constants.MGMT_IPSEC_ENABLED, constants.MGMT_IPSEC_DISABLED]:
            LOG.error(_("Invalid value for %s: %s" % (constants.MGMT_IPSEC_FLAG, data)))
            return False

        try:
            host = objects.host.get_by_uuid(pecan.request.context,
                                            uuid)
            if host:
                capabilities = host.get('capabilities')

                if (data == constants.MGMT_IPSEC_DISABLED and
                        capabilities.get(constants.MGMT_IPSEC_FLAG) is not None):
                    capabilities.pop(constants.MGMT_IPSEC_FLAG)
                else:
                    capabilities.update({constants.MGMT_IPSEC_FLAG: data})

                pecan.request.dbapi.ihost_update(uuid, {'capabilities': capabilities})
        except exception.ServerNotFound:
            LOG.error(_('Failed to retrieve host with specified uuid.'))
            return False
        return True

    def _ihosts_get(self, isystem_id, marker, limit, personality,
                    sort_key, sort_dir):
        if self._from_isystem and not isystem_id:  # TODO: check uuid
            raise exception.InvalidParameterValue(_(
                "System id not specified."))

        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.host.get_by_uuid(pecan.request.context,
                                                  marker)

        if isystem_id:
            ihosts = pecan.request.dbapi.ihost_get_by_isystem(
                isystem_id, limit,
                marker_obj,
                sort_key=sort_key,
                sort_dir=sort_dir)
        else:
            if personality:
                ihosts = pecan.request.dbapi.ihost_get_by_personality(
                    personality, limit, marker_obj,
                    sort_key=sort_key,
                    sort_dir=sort_dir)
            else:
                ihosts = pecan.request.dbapi.ihost_get_list(
                    limit, marker_obj,
                    sort_key=sort_key,
                    sort_dir=sort_dir)

        for h in ihosts:
            self._update_controller_personality(h)
            self._update_host_mgmt_ip(h)

        return ihosts

    @staticmethod
    def _update_subfunctions(ihost):
        subfunctions = ihost.get('subfunctions') or ""
        personality = ihost.get('personality') or ""
        # handle race condition with subfunctions being updated late.
        if not subfunctions:
            LOG.info("update_subfunctions: subfunctions not set. personality=%s" %
                     personality)
            if personality == constants.CONTROLLER:
                subfunctions = ','.join(tsc.subfunctions)
            else:
                subfunctions = personality
            ihost['subfunctions'] = subfunctions

        subfunctions_set = set(subfunctions.split(','))
        if personality not in subfunctions_set:
            # Automatically add it
            subfunctions_list = list(subfunctions_set)
            subfunctions_list.insert(0, personality)
            subfunctions = ','.join(subfunctions_list)
            LOG.info("%s personality=%s update subfunctions=%s" %
                     (ihost.get('hostname'), personality, subfunctions))
        LOG.debug("update_subfunctions:  personality=%s subfunctions=%s" %
                  (personality, subfunctions))
        return subfunctions

    @staticmethod
    def _update_controller_personality(host):
        if host['personality'] == constants.CONTROLLER:
            if utils.is_host_active_controller(host):
                activity = 'Controller-Active'
            else:
                activity = 'Controller-Standby'
            host['capabilities'].update({'Personality': activity})

    @staticmethod
    def _update_host_mgmt_ip(host):
        try:
            host['mgmt_ip'] = utils.get_mgmt_ip(host.hostname)
        except exception.AddressNotFoundByName:
            host['mgmt_ip'] = None

    @wsme_pecan.wsexpose(HostCollection, six.text_type, six.text_type, int, six.text_type,
                         six.text_type, six.text_type)
    def get_all(self, isystem_id=None, marker=None, limit=None,
                personality=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of ihosts."""
        ihosts = self._ihosts_get(
            isystem_id, marker, limit, personality, sort_key, sort_dir)
        return HostCollection.convert_with_links(ihosts, limit,
                                                 sort_key=sort_key,
                                                 sort_dir=sort_dir)

    @wsme_pecan.wsexpose(six.text_type, six.text_type, body=six.text_type)
    def install_progress(self, uuid, install_state,
                         install_state_info=None):
        """ Update the install status for the given host."""
        LOG.debug("Update host uuid %s with install_state=%s "
                  "and install_state_info=%s" %
                  (uuid, install_state, install_state_info))
        if install_state == constants.INSTALL_STATE_INSTALLED:
            # After an install a node will reboot right away. Change the state
            # to refect this.
            install_state = constants.INSTALL_STATE_BOOTING

        host = objects.host.get_by_uuid(pecan.request.context, uuid)
        pecan.request.dbapi.ihost_update(host['uuid'],
                                         {'install_state': install_state,
                                         'install_state_info':
                                          install_state_info})

    @wsme_pecan.wsexpose(wtypes.text)
    def wipe_osds(self):
        LOG.debug("Checking if host OSDs need to be wiped.")
        if (os.path.isfile(tsc.SKIP_CEPH_OSD_WIPING)):
            return False
        return True

    @wsme_pecan.wsexpose(wtypes.text, six.text_type)
    def mgmt_ip(self, mac):

        # validate the mac address format before calling into sysinv
        if cutils.is_valid_mac(mac) is False:
            LOG.debug("invalid mac:%s" % mac)
            return 0

        # get the active controller's floating ip address
        floating_address = utils.get_primary_address_by_name(
            cutils.format_address_name(constants.CONTROLLER_HOSTNAME,
                                       constants.NETWORK_TYPE_MGMT),
            constants.NETWORK_TYPE_MGMT).address
        try:
            # get the management IP for the host that matches this mgmt mac
            ihost_obj = pecan.request.dbapi.ihost_get_by_mgmt_mac(mac)
            if ihost_obj['hostname']:
                hostname = ihost_obj['hostname']
                address_name = cutils.format_address_name(hostname,
                                                constants.NETWORK_TYPE_MGMT)
                address = utils.get_primary_address_by_name(address_name,
                                                constants.NETWORK_TYPE_MGMT, True)
                mgmt_addr = address.address

                if mgmt_addr is not None:
                    # get the management network netmask
                    network = pecan.request.dbapi.network_get_by_type(
                            constants.NETWORK_TYPE_MGMT)
                    address_names = ['%s-%s' % (
                        constants.CONTROLLER_0_HOSTNAME,
                        constants.NETWORK_TYPE_MGMT),
                                     '%s-%s' % (
                        constants.CONTROLLER_1_HOSTNAME,
                        constants.NETWORK_TYPE_MGMT)]
                    addresses = {
                            a['name']: a for a in
                            pecan.request.dbapi.addresses_get_by_pool_uuid(
                                network.pool_uuid)}
                    address_pool = pecan.request.dbapi.address_pool_get(network.pool_uuid)
                    mgmt_subnet = str(address_pool.network) + '/' + str(address_pool.prefix)
                    mgmt_netmask = None
                    for name in address_names:
                        # check for prefix mismatch between controllers
                        _prefix = addresses[name].prefix
                        if mgmt_netmask is None and _prefix is not None:
                            mgmt_netmask = addresses[name].prefix
                        elif mgmt_netmask != _prefix:
                            LOG.info("management netmask delta %s:%s" % (
                                mgmt_netmask, _prefix))
                        else:
                            LOG.debug("management netmasks match %s:%s" % (
                                mgmt_netmask, _prefix))

                    # build the return string
                    mgmt_ip = {}
                    mgmt_ip["hostname"] = hostname
                    mgmt_ip["netmask"] = str(mgmt_netmask)
                    mgmt_ip["subnet"] = mgmt_subnet
                    mgmt_ip["address"] = mgmt_addr
                    mgmt_ip["floating"] = floating_address

                    # avoid logging by default
                    LOG.debug("mac:%s lookup got '%s'" % (mac, mgmt_ip))
                    return mgmt_ip
                else:
                    raise wsme.exc.ClientSideError(_(
                        "Failed to get '%s' mgmt_ip from mac '%s'" % (
                            ihost_obj['hostname'],
                            ihost_obj['mgmt_mac'])))

        except (exception.NodeNotFound, exception.HostNotFound):
            LOG.warn(_("Node with mac:%s is not found" % mac))
            pass

    @wsme_pecan.wsexpose(HostCollection, six.text_type, six.text_type, int, six.text_type,
                         six.text_type, six.text_type)
    def detail(self, isystem_id=None, marker=None, limit=None,
               personality=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of ihosts with detail."""
        # /detail should only work against collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "ihosts":
            raise exception.HTTPNotFound

        ihosts = self._ihosts_get(
            isystem_id, marker, limit, personality, sort_key, sort_dir)
        resource_url = '/'.join(['ihosts', 'detail'])
        return HostCollection.convert_with_links(ihosts, limit,
                                                 url=resource_url,
                                                 expand=True,
                                                 sort_key=sort_key,
                                                 sort_dir=sort_dir)

    @wsme_pecan.wsexpose(Host, six.text_type)
    def get_one(self, uuid):
        """Retrieve information about the given ihost."""
        if self._from_isystem:
            raise exception.OperationNotPermitted

        rpc_ihost = objects.host.get_by_uuid(pecan.request.context,
                                             uuid)
        self._update_controller_personality(rpc_ihost)
        self._update_host_mgmt_ip(rpc_ihost)

        return Host.convert_with_links(rpc_ihost)

    def _block_add_host_semantic_checks(self, ihost_dict):

        if not self._no_controllers_exist() and \
           ihost_dict.get('personality') is None:

            # Semantic Check: Prevent adding any new host(s) until there is
            #                 an unlocked-enabled controller to manage them.
            controller_list = pecan.request.dbapi.ihost_get_by_personality(
                personality=constants.CONTROLLER)
            have_unlocked_enabled_controller = False
            for c in controller_list:
                if (c['administrative'] == constants.ADMIN_UNLOCKED and
                   c['operational'] == constants.OPERATIONAL_ENABLED):
                    have_unlocked_enabled_controller = True
                    break

            if not have_unlocked_enabled_controller:
                raise wsme.exc.ClientSideError(_(
                    "Provisioning request for new host '%s' is not permitted "
                    "while there is no unlocked-enabled controller. Unlock "
                    "controller-0, wait for it to enable and then retry.") %
                    ihost_dict.get('mgmt_mac'))

    def _new_host_semantic_checks(self, ihost_dict):

        if not self._no_controllers_exist():

            self._block_add_host_semantic_checks(ihost_dict)

            # Check whether vsc_controllers is set and perform semantic
            # checking if necessary.
            if ihost_dict['vsc_controllers']:
                self._semantic_check_vsc_controllers(
                    ihost_dict, ihost_dict['vsc_controllers'])

            # Check whether the system mode is simplex
            if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
                raise wsme.exc.ClientSideError(_(
                    "Host-add Rejected: Adding a host on a simplex system "
                    "is not allowed."))

        personality = ihost_dict['personality']
        if not ihost_dict['hostname']:
            if personality not in (constants.CONTROLLER, constants.STORAGE):
                raise wsme.exc.ClientSideError(_(
                    "Host-add Rejected. Must provide a hostname for a node of "
                    "personality %s") % personality)
        else:
            self._validate_hostname(ihost_dict['hostname'], personality)

        mgmt_mac = ihost_dict.get('mgmt_mac')
        if not mgmt_mac:
            raise wsme.exc.ClientSideError(_(
                "Host-add Rejected: Must provide MAC Address of "
                "the host mgmt interface"))
        else:
            if not cutils.is_valid_mac(mgmt_mac):
                raise wsme.exc.ClientSideError(_(
                    "Host-add Rejected: Must provide a valid format "
                    "of a MAC Address"))

        HostController._personality_check(personality)

    def _do_post(self, ihost_dict):
        """Create a new ihost based off a dictionary of attributes """

        log_start = cutils.timestamped("ihost_post_start")
        LOG.info("SYS_I host %s %s add" % (ihost_dict['hostname'],
                                           log_start))

        power_on = ihost_dict.get('power_on', None)

        ihost_obj = None

        # Semantic checks for adding a new node
        if self._from_isystem:
            raise exception.OperationNotPermitted

        self._new_host_semantic_checks(ihost_dict)

        current_ihosts = pecan.request.dbapi.ihost_get_list()
        hostnames = [h['hostname'] for h in current_ihosts]

        # Check for missing/invalid hostname
        # ips/hostnames are automatic for controller & storage nodes
        if ihost_dict['personality'] not in (constants.CONTROLLER,
                                             constants.STORAGE):
            if ihost_dict['hostname'] in hostnames:
                raise wsme.exc.ClientSideError(
                    _("Host-add Rejected: Hostname already exists"))

        try:
            ihost_obj = pecan.request.dbapi.ihost_get_by_mgmt_mac(
                ihost_dict['mgmt_mac'])
            # A host with this MAC already exists. We will allow it to be
            # added if the hostname and personality have not been set.
            if ihost_obj['hostname'] or ihost_obj['personality']:
                raise wsme.exc.ClientSideError(
                    _("Host-add Rejected: Host with mgmt_mac %s already "
                      "exists") % ihost_dict['mgmt_mac'])
            # Check DNSMASQ for ip/mac already existing
            # -> node in use by someone else or has already been booted
            elif (not ihost_obj and self._dnsmasq_mac_exists(
                    ihost_dict['mgmt_mac'])):
                raise wsme.exc.ClientSideError(
                    _("Host-add Rejected: mgmt_mac %s has already been "
                    "active") % ihost_dict['mgmt_mac'])

            # Use the uuid from the existing host
            ihost_dict['uuid'] = ihost_obj['uuid']
        except exception.NodeNotFound:
            # This is a new host
            pass

        if not ihost_dict.get('uuid'):
            ihost_dict['uuid'] = uuidutils.generate_uuid()

        ihost_dict['mgmt_mac'] = cutils.validate_and_normalize_mac(
            ihost_dict['mgmt_mac'])

        # BM handling
        defaults = objects.host.get_defaults()
        ihost_orig = copy.deepcopy(ihost_dict)

        subfunctions = self._update_subfunctions(ihost_dict)
        ihost_dict['subfunctions'] = subfunctions

        changed_paths = []
        delta = set()
        for key in defaults:
            # Internal values that aren't being modified
            if key in ['id', 'updated_at', 'created_at']:
                continue

            # Update only the new fields
            if key in ihost_dict and ihost_dict[key] != defaults[key]:
                delta.add(key)
                ihost_orig[key] = defaults[key]

        bm_list = ['bm_ip', 'bm_username', 'bm_password']
        for bmi in bm_list:
            if bmi in ihost_dict:
                delta.add(bmi)
                changed_paths.append({'path': '/' + str(bmi),
                                      'value': ihost_dict[bmi],
                                      'op': 'replace'})
        if ihost_dict.get('bm_ip') and ihost_dict.get('bm_username'):
            implict_bm_type = constants.HOST_BM_TYPE_DEFAULT
        else:
            implict_bm_type = constants.HOST_BM_TYPE_DEPROVISIONED

        if ihost_dict.get('bm_type') is None:
            ihost_dict['bm_type'] = implict_bm_type
            delta.add('bm_type')
            changed_paths.append({'path': '/bm_type',
                                  'value': ihost_dict['bm_type'],
                                  'op': 'replace'})

        self._bm_semantic_check_and_update(ihost_orig, ihost_dict,
                                           delta, changed_paths,
                                           current_ihosts)

        if ('capabilities' not in ihost_dict or not ihost_dict['capabilities']):
            ihost_dict['capabilities'] = {}

        # If this is the first controller being set up,
        # configure and return
        if ihost_dict['personality'] == constants.CONTROLLER:
            if self._no_controllers_exist():
                pecan.request.rpcapi.create_controller_filesystems(
                    pecan.request.context, ihost_dict['rootfs_device'])
                controller_ihost = pecan.request.rpcapi.create_ihost(
                    pecan.request.context, ihost_dict)
                if 'recordtype' in ihost_dict:
                    pecan.request.rpcapi.configure_ihost(
                        pecan.request.context,
                        controller_ihost)
                # As part of the initial controller host creation during
                # Ansible bootstrap, reconfigure the service endpoints to use
                # the management floating IP instead of the loopback IP.
                if os.path.isfile(constants.ANSIBLE_BOOTSTRAP_FLAG):
                    pecan.request.rpcapi.reconfigure_service_endpoints(
                        pecan.request.context, controller_ihost)

                    # if it is a system controller, config the database and
                    # file system
                    if (utils.get_distributed_cloud_role() ==
                            constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER):
                        pecan.request.rpcapi.configure_system_controller(
                            pecan.request.context, controller_ihost)

                return Host.convert_with_links(controller_ihost)

        if ihost_dict['personality'] in (constants.CONTROLLER, constants.STORAGE):
            self._controller_storage_node_setup(ihost_dict)

        # Set host to reinstalling
        ihost_dict.update({constants.HOST_ACTION_STATE:
                           constants.HAS_REINSTALLING})

        # Creation/Configuration
        if ihost_obj:
            # The host exists - do an update.
            defaults = objects.host.get_defaults()
            for key in defaults:
                # Internal values that shouldn't be updated
                if key in ['id', 'updated_at', 'created_at', 'uuid']:
                    continue

                # Update only the fields that are not empty and have changed
                if (key in ihost_dict and ihost_dict[key] and
                        (ihost_obj[key] != ihost_dict[key])):
                    ihost_obj[key] = ihost_dict[key]
            ihost_obj = pecan.request.rpcapi.update_ihost(pecan.request.context,
                                                          ihost_obj)
        else:
            # The host doesn't exist - do an add.
            LOG.info("create_ihost=%s" % ihost_dict.get('hostname'))
            ihost_obj = pecan.request.rpcapi.create_ihost(pecan.request.context,
                                                          ihost_dict)

        ihost_obj = objects.host.get_by_uuid(pecan.request.context,
                                             ihost_obj.uuid)

        pecan.request.dbapi.network_get_by_type(constants.NETWORK_TYPE_MGMT)

        # Configure the new ihost
        pecan.request.rpcapi.configure_ihost(pecan.request.context, ihost_obj)

        # Notify maintenance about updated mgmt_ip
        address_name = cutils.format_address_name(ihost_obj.hostname,
                                                  constants.NETWORK_TYPE_MGMT)
        address = utils.get_primary_address_by_name(address_name,
                                                    constants.NETWORK_TYPE_MGMT, True)
        ihost_obj['mgmt_ip'] = address.address

        # Add ihost to mtc
        new_ihost_mtc = ihost_obj.as_dict()
        new_ihost_mtc.update({'operation': 'add'})
        new_ihost_mtc['mgmt_ip'] = address.address
        new_ihost_mtc = cutils.removekeys_nonmtce(new_ihost_mtc)

        mtc_response = mtce_api.host_add(
            self._api_token, self._mtc_address, self._mtc_port, new_ihost_mtc,
            constants.MTC_ADD_TIMEOUT_IN_SECS)

        if mtc_response is None:
            mtc_response = {'status': 'fail',
                            'reason': 'no response',
                            'action': 'retry'}

        if mtc_response['status'] != 'pass':
            # Report mtc error
            raise wsme.exc.ClientSideError(_("Maintenance has returned with "
                                             "a status of %s, reason: %s, recommended action: %s") % (
                                               mtc_response.get('status'),
                                               mtc_response.get('reason'),
                                               mtc_response.get('action')))

        # once the ihost is added to mtc, attempt to power it on
        if power_on is not None and ihost_obj['bm_type'] is not None:
            new_ihost_mtc.update({'action': constants.POWERON_ACTION})

            mtc_response = {'status': None}
            mtc_response = mtce_api.host_modify(
                self._api_token, self._mtc_address, self._mtc_port, new_ihost_mtc,
                constants.MTC_ADD_TIMEOUT_IN_SECS)

            if mtc_response is None:
                mtc_response = {'status': 'fail',
                                'reason': 'no response',
                                'action': 'retry'}

            if mtc_response['status'] != 'pass':
                # Report mtc error
                raise wsme.exc.ClientSideError(_("Maintenance has returned with "
                                                 "a status of %s, reason: %s, recommended action: %s") % (
                                                   mtc_response.get('status'),
                                                   mtc_response.get('reason'),
                                                   mtc_response.get('action')))

        # Notify the VIM that the host has been added - must be done after
        # the host has been added to mtc and saved to the DB.
        LOG.info("VIM notify add host add %s subfunctions=%s" % (
            ihost_obj['hostname'], subfunctions))
        try:
            vim_api.vim_host_add(
                self._api_token,
                ihost_obj['uuid'],
                ihost_obj['hostname'],
                subfunctions,
                ihost_obj['administrative'],
                ihost_obj['operational'],
                ihost_obj['availability'],
                ihost_obj['subfunction_oper'],
                ihost_obj['subfunction_avail'],
                constants.VIM_DEFAULT_TIMEOUT_IN_SECS)
        except Exception as e:
            LOG.warn(_("No response from vim_api %s e=%s" %
                       (ihost_obj['hostname'], e)))
            self._api_token = None
            pass  # VIM audit will pickup

        log_end = cutils.timestamped("ihost_post_end")
        LOG.info("SYS_I host %s %s" % (ihost_obj.hostname, log_end))

        return Host.convert_with_links(ihost_obj)

    @cutils.synchronized(LOCK_NAME)
    @expose('json')
    def bulk_add(self):
        pending_creation = []
        success_str = ""
        error_str = ""

        if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
            return dict(
                success="",
                error="Bulk add on a simplex system is not allowed."
            )

        # Semantic Check: Prevent bulk add until there is an unlocked
        #                 and enabled controller to manage them.
        controller_list = pecan.request.dbapi.ihost_get_by_personality(
            personality=constants.CONTROLLER)
        have_unlocked_enabled_controller = False
        for c in controller_list:
            if (c['administrative'] == constants.ADMIN_UNLOCKED and
               c['operational'] == constants.OPERATIONAL_ENABLED):
                have_unlocked_enabled_controller = True
                break

        if not have_unlocked_enabled_controller:
            return dict(
                success="",
                error="Bulk_add requires enabled controller. Please "
                "unlock controller-0, wait for it to enable and then retry."
            )

        LOG.info("Starting ihost bulk_add operation")
        assert isinstance(pecan.request.POST['file'], cgi.FieldStorage)
        fileitem = pecan.request.POST['file']
        if not fileitem.filename:
            return dict(success="", error="Error: No file uploaded")

        try:
            contents = fileitem.file.read()
            # Generate an array of hosts' attributes to be used in creation
            root = ET.fromstring(contents)
        except Exception:
            return dict(
                success="",
                error="No hosts have been added, invalid XML document"
            )

        for idx, xmlhost in enumerate(root.findall('host')):

            new_ihost = {}
            for attr in HOST_XML_ATTRIBUTES:
                elem = xmlhost.find(attr)
                if elem is not None:
                    # If the element is found, set the attribute.
                    # If the text field is empty, set it to the empty string.
                    new_ihost[attr] = elem.text or ""
                else:
                    # If the element is not found, set the attribute to None.
                    new_ihost[attr] = None

            # This is the expected format of the location field
            if new_ihost['location'] is not None:
                new_ihost['location'] = {"locn": new_ihost['location']}

            # Semantic checks
            try:
                LOG.debug(new_ihost)
                self._new_host_semantic_checks(new_ihost)
            except Exception as ex:
                culprit = new_ihost.get('hostname') or "with index " + str(idx)
                return dict(
                    success="",
                    error=" No hosts have been added, error parsing host %s: "
                          "%s" % (culprit, ex)
                )
            pending_creation.append(new_ihost)

        # Find local network adapter MACs
        my_macs = list()
        for liSnics in psutil.net_if_addrs().values():
            for snic in liSnics:
                if snic.family == psutil.AF_LINK:
                    my_macs.append(snic.address)

        # Perform the actual creations
        for new_host in pending_creation:
            try:
                # Configuring for the setup controller, only uses BMC fields
                if new_host['mgmt_mac'].lower() in my_macs:
                    changed_paths = list()

                    bm_list = ['bm_type', 'bm_ip',
                            'bm_username', 'bm_password']
                    for bmi in bm_list:
                        if bmi in new_host:
                            changed_paths.append({
                                'path': '/' + str(bmi),
                                'value': new_host[bmi],
                                'op': 'replace'
                            })

                    ihost_obj = [ihost
                                for ihost in pecan.request.dbapi.ihost_get_list()
                                if ihost['mgmt_mac'] in my_macs]
                    if len(ihost_obj) != 1:
                        raise Exception("Unexpected: no/more_than_one host(s)"
                                        " contain(s) a management mac address"
                                        " from local network adapters")

                    self._patch(ihost_obj[0]['uuid'], changed_paths)
                else:
                    self._do_post(new_host)

                if new_host['power_on'] is not None and new_host['bm_type'] is None:
                    success_str = "%s\n %s Warning: Ignoring <power_on> due" \
                                  " to insufficient board management (bm)" \
                                  " data." % (success_str,
                                              new_host['hostname'])
                else:
                    success_str = "%s\n %s" % (success_str,
                                               new_host['hostname'])
            except Exception as ex:
                LOG.exception(ex)
                error_str += " " + (new_host.get('hostname') or
                                    new_host.get('personality')) + \
                             ": " + str(ex) + "\n"

        return dict(
            success=success_str,
            error=error_str
        )

    @expose('json')
    def bulk_export(self):
        def host_personality_name_sort_key(host):
            if host.personality == constants.CONTROLLER:
                rank = 0
            elif host.personality == constants.STORAGE:
                rank = 1
            elif host.personality == constants.WORKER:
                rank = 2
            else:
                rank = 3
            return rank, host.hostname

        xml_host_node = et.Element('hosts', {'version': cutils.get_sw_version()})
        mgmt_network = pecan.request.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_MGMT)

        host_list = pecan.request.dbapi.ihost_get_list()
        sorted_hosts = sorted(host_list, key=host_personality_name_sort_key)

        for host in sorted_hosts:
            _create_node(host, xml_host_node, host.personality,
                         mgmt_network.dynamic)

        xml_text = dom.parseString(et.tostring(xml_host_node)).toprettyxml()
        result = {'content': xml_text}
        return result

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Host, body=Host)
    def post(self, host):
        """Create a new ihost."""
        ihost_dict = host.as_dict()

        # bm_password is not a part of ihost, so retrieve it from the body
        body = json.loads(pecan.request.body.decode('utf-8'))
        if 'bm_password' in body:
            ihost_dict['bm_password'] = body['bm_password']
        else:
            ihost_dict['bm_password'] = ''

        return self._do_post(ihost_dict)

    @wsme_pecan.wsexpose(Host, six.text_type, body=[six.text_type])
    def patch(self, uuid, patch):
        """ Update an existing ihost.
        """
        utils.validate_patch(patch)

        has_ptp_instances = False
        optimizable = 0
        optimize_list = ['/uptime', '/location', '/serialid', '/task']
        for p in patch:
            path = p['path']
            if path in optimize_list:
                optimizable += 1
            elif path == constants.PTP_INSTANCE_ARRAY_PATH:
                has_ptp_instances = True

        if len(patch) == optimizable:
            return self._patch(uuid, patch)
        elif (pecan.request.user_agent.startswith('mtce') or
              pecan.request.user_agent.startswith('vim') or
              has_ptp_instances):
            return self._patch_sys(uuid, patch)
        else:
            return self._patch_gen(uuid, patch)

    @cutils.synchronized(LOCK_NAME_SYS)
    def _patch_sys(self, uuid, patch):
        return self._patch(uuid, patch)

    @cutils.synchronized(LOCK_NAME)
    def _patch_gen(self, uuid, patch):
        return self._patch(uuid, patch)

    @staticmethod
    def _validate_capability_is_not_set(old, new):
        is_set, __ = new
        return not is_set

    @staticmethod
    def _validate_capability_is_equal(old, new):
        return old == new

    def _validate_capabilities(self, old_caps, new_caps):
        """ Reject updating read-only host capabilities:
            1. stor_function. This field is set to 'monitor' for hosts that are
               running ceph monitor process: controller-0, controller-1, storage-0.
            2. Personality. This field is "virtual": not saved in the database but
               returned via API and displayed via "system host-show".

            :param old_caps: current host capabilities
            :type old_caps: dict
            :param new_caps: updated host capabilies (to  be set)
            :type new_caps: str
            :raises: wsme.exc.ClientSideError when attempting to change read-only
                     capabilities
        """
        if type(new_caps) == str:
            try:
                new_caps = ast.literal_eval(new_caps)
            except SyntaxError:
                pass
        if type(new_caps) != dict:
            raise wsme.exc.ClientSideError(
                _("Changing capabilities type is not allowed: "
                  "old_value={}, new_value={}").format(
                    old_caps, new_caps))
        PROTECTED_CAPABILITIES = [
            ('Personality',
                self._validate_capability_is_not_set),
            (constants.IHOST_STOR_FUNCTION,
                self._validate_capability_is_equal)]
        for capability, validate in PROTECTED_CAPABILITIES:
            old_is_set, old_value = (
                capability in old_caps, old_caps.get(capability))
            new_is_set, new_value = (
                capability in new_caps, new_caps.get(capability))
            if not validate((old_is_set, old_value),
                            (new_is_set, new_value)):
                if old_is_set:
                    raise wsme.exc.ClientSideError(
                        _("Changing capability not allowed: "
                          "name={}, old_value={}, new_value={}. ").format(
                              capability, old_value, new_value))
                else:
                    raise wsme.exc.ClientSideError(
                        _("Setting capability not allowed: "
                          "name={}, value={}. ").format(
                              capability, new_value))

    def _get_mgmt_ip(self, hostname):
        # Notify maintenance about updated mgmt_ip
        # During mgmt network reconfiguration, do not change the mgmt IP
        # in maintencance as it will be updated after the unlock.
        if os.path.isfile(tsc.MGMT_NETWORK_RECONFIGURATION_ONGOING):
            return cutils.gethostbyname(constants.CONTROLLER_0_FQDN)
        else:
            address_name = cutils.format_address_name(hostname,
                                                      constants.NETWORK_TYPE_MGMT)
            address = utils.get_primary_address_by_name(address_name,
                                                        constants.NETWORK_TYPE_MGMT, True)
            return address.address

    def _exists_monitoring_instance_on_host(self, host_uuid):
        ptp_instances = pecan.request.dbapi.ptp_instances_get_list(host_uuid)

        for instance in ptp_instances:
            if instance["service"] == constants.PTP_INSTANCE_TYPE_MONITORING:
                return True

        return False

    def _patch(self, uuid, patch):
        log_start = cutils.timestamped("ihost_patch_start")

        ihost_obj = objects.host.get_by_uuid(pecan.request.context, uuid)
        ihost_dict = ihost_obj.as_dict()
        self._block_add_host_semantic_checks(ihost_dict)

        for p in patch:
            if p['path'] == constants.PTP_INSTANCE_ARRAY_PATH:
                ptp_instance_id = p.get('value')
                try:
                    # Check PTP instance exists
                    ptp_instance = pecan.request.dbapi.ptp_instance_get(ptp_instance_id)
                except exception.PtpInstanceNotFound:
                    raise wsme.exc.ClientSideError(_("No PTP instance object"))
                values = {'host_id': ihost_obj.id,
                          'ptp_instance_id': ptp_instance_id}
                if p.get('op') == constants.PTP_PATCH_OPERATION_ADD:
                    # Check constraint: single monitoring ptp instance on host
                    if ptp_instance[
                        "service"
                    ] == constants.PTP_INSTANCE_TYPE_MONITORING and self._exists_monitoring_instance_on_host(
                        uuid
                    ):
                        raise wsme.exc.ClientSideError(
                            _("Monitoring ptp instance already exists on host")
                        )

                    pecan.request.dbapi.ptp_instance_assign(values)
                else:
                    pecan.request.dbapi.ptp_instance_remove(values)

                # Remove from patch to apply the paths related to assigned PTP
                # instances, since they don't actually patch the host object
                patch.remove(p)
            elif p['path'] == constants.MGMT_MAC_PATH:
                p['value'] = cutils.validate_and_normalize_mac(p.get('value'))

        patch_obj = jsonpatch.JsonPatch(patch)

        # Add transient fields that are not stored in the database
        ihost_dict['bm_password'] = None

        try:
            patched_ihost = jsonpatch.apply_patch(ihost_dict,
                                                  patch_obj)
        except jsonpatch.JsonPatchException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Patching Error: %s") % e)

        if patched_ihost['clock_synchronization'] not in \
                constants.CLOCK_SYNCHRONIZATION:
            msg = _("Host update failed: clock_synchronization: "
                    "invalid choice: '%s', choose from %s" %
                    (patched_ihost['clock_synchronization'],
                     constants.CLOCK_SYNCHRONIZATION))
            raise wsme.exc.ClientSideError(msg)

        self._validate_capabilities(
            ihost_dict['capabilities'], patched_ihost['capabilities'])

        defaults = objects.host.get_defaults()

        ihost_dict_orig = dict(ihost_obj.as_dict())
        for key in defaults:
            # Internal values that shouldn't be part of the patch
            if key in ['id', 'updated_at', 'created_at']:
                continue

            # In case of a remove operation, add the missing fields back
            # to the document with their default value
            if key in ihost_dict and key not in patched_ihost:
                patched_ihost[key] = defaults[key]

            # To compare, first cast the patch value into same datatype
            # using the corresponding parsing function for the field in
            # ihost_obj and then update only the fields that have changed
            parsed_patch_value = ihost_obj.fields[key](patched_ihost[key])
            if ihost_obj[key] != parsed_patch_value:
                ihost_obj[key] = parsed_patch_value

        delta = ihost_obj.obj_what_changed()

        # bm_password is not part of the ihost_obj
        # using bm_username as a kludge
        password_changed = any(p['path'] == '/bm_password' for p in patch_obj)
        if password_changed and not delta:
            delta.add("bm_username")

        delta_handle = list(delta)

        uptime_update = False
        if 'uptime' in delta_handle:
            # There is a log of uptime updates, so just do a debug log
            uptime_update = True
            LOG.debug("%s %s patch" % (ihost_obj.hostname,
                                       log_start))
        else:
            LOG.info("%s %s patch" % (ihost_obj.hostname,
                                      log_start))

        hostupdate = HostUpdate(ihost_dict_orig, patched_ihost, delta)
        if delta_handle:
            self._validate_delta(delta_handle)
            if delta_handle == ['uptime']:
                LOG.debug("%s 1. delta_handle %s" %
                          (hostupdate.displayid, delta_handle))
            else:
                LOG.info("%s 1. delta_handle %s" %
                         (hostupdate.displayid, delta_handle))
        else:
            LOG.info("%s ihost_patch_end.  No changes from %s." %
                     (hostupdate.displayid, pecan.request.user_agent))
            return Host.convert_with_links(ihost_obj)

        myaction = patched_ihost.get('action')
        if self.action_check(myaction, hostupdate):
            LOG.info("%s post action_check hostupdate "
                     "action=%s notify_vim=%s notify_mtc=%s "
                     "skip_notify_mtce=%s" %
                     (hostupdate.displayid,
                      hostupdate.action,
                      hostupdate.notify_vim,
                      hostupdate.notify_mtce,
                      hostupdate.skip_notify_mtce))

            if self.stage_action(myaction, hostupdate):
                LOG.info("%s Action staged: %s" %
                         (hostupdate.displayid, myaction))
            else:
                LOG.info("%s ihost_patch_end stage_action rc %s" %
                        (hostupdate.displayid, hostupdate.nextstep))
                if hostupdate.nextstep == hostupdate.EXIT_RETURN_HOST:
                    return Host.convert_with_links(ihost_obj)
                elif hostupdate.nextstep == hostupdate.EXIT_UPDATE_PREVAL:
                    if hostupdate.ihost_val_prenotify:
                            # update value in db  prior to notifications
                            LOG.info("update ihost_val_prenotify: %s" %
                                hostupdate.ihost_val_prenotify)
                            ihost_obj = pecan.request.dbapi.ihost_update(
                                ihost_obj['uuid'], hostupdate.ihost_val_prenotify)
                    return Host.convert_with_links(ihost_obj)

            if myaction == constants.SUBFUNCTION_CONFIG_ACTION:
                self.perform_action_subfunction_config(ihost_obj)

            if myaction in delta_handle:
                delta_handle.remove(myaction)

            LOG.info("%s post action_stage hostupdate "
                     "action=%s notify_vim=%s notify_mtc=%s "
                     "skip_notify_mtce=%s" %
                     (hostupdate.displayid,
                      hostupdate.action,
                      hostupdate.notify_vim,
                      hostupdate.notify_mtce,
                      hostupdate.skip_notify_mtce))

        self._optimize_delta_handling(delta_handle)

        if 'administrative' in delta or \
                'operational' in delta:
            self.stage_administrative_update(hostupdate)

        if delta_handle:
            LOG.info("%s 2. delta_handle %s" %
                     (hostupdate.displayid, delta_handle))
            self.check_provisioning(hostupdate, patch)
            if (hostupdate.ihost_orig['administrative'] ==
               constants.ADMIN_UNLOCKED):
                self.check_updates_while_unlocked(hostupdate, delta)
                if 'apparmor' in delta:
                    raise wsme.exc.ClientSideError(
                        ("This update is not allowed as host:%s is unlocked." %
                        (hostupdate.displayid)))
            if 'apparmor' in delta and hostupdate.ihost_patch['apparmor'] \
               not in [constants.APPARMOR_STATE_ENABLED, constants.APPARMOR_STATE_DISABLED]:
                raise wsme.exc.ClientSideError(
                    ("Invalid apparmor state. Allowed values:%s, %s." %
                    (constants.APPARMOR_STATE_ENABLED, constants.APPARMOR_STATE_DISABLED)))

            current_ihosts = None
            hostupdate.bm_type_changed_to_none = \
                self._bm_semantic_check_and_update(hostupdate.ihost_orig,
                                                   hostupdate.ihost_patch,
                                                   delta, patch_obj,
                                                   current_ihosts,
                                                   hostupdate)
            LOG.info("%s post delta_handle hostupdate "
                     "action=%s notify_vim=%s notify_mtc=%s "
                     "skip_notify_mtce=%s" %
                     (hostupdate.displayid,
                      hostupdate.action,
                      hostupdate.notify_vim,
                      hostupdate.notify_mtce,
                      hostupdate.skip_notify_mtce))

            if hostupdate.bm_type_changed_to_none:
                hostupdate.ihost_val_update({'bm_ip': None,
                                             'bm_username': None,
                                             'bm_password': None})

            if 'max_cpu_mhz_configured' in delta:
                self._check_max_cpu_mhz_configured(hostupdate)
                max_cpu_mhz_configured = hostupdate.ihost_patch.get('max_cpu_mhz_configured')
                ihost_obj['max_cpu_mhz_configured'] = max_cpu_mhz_configured
                pecan.request.dbapi.ihost_update(
                    ihost_obj['uuid'],
                    {'max_cpu_mhz_configured': max_cpu_mhz_configured})
                if not hostupdate.configure_required:
                    pecan.request.rpcapi.update_host_max_cpu_mhz_configured(
                        pecan.request.context, ihost_obj)

        if hostupdate.ihost_val_prenotify:
            # update value in db  prior to notifications
            LOG.info("update ihost_val_prenotify: %s" %
                     hostupdate.ihost_val_prenotify)
            pecan.request.dbapi.ihost_update(ihost_obj['uuid'],
                                             hostupdate.ihost_val_prenotify)

        if hostupdate.ihost_val:
            # apply the staged updates in preparation for update
            LOG.info("%s apply ihost_val %s" %
                     (hostupdate.displayid, hostupdate.ihost_val))
            for k, v in hostupdate.ihost_val.items():
                ihost_obj[k] = v
            LOG.debug("AFTER Apply ihost_val %s to  iHost %s" %
                      (hostupdate.ihost_val, ihost_obj.as_dict()))

        if 'personality' in delta:
            self._update_subfunctions(ihost_obj)

        if hostupdate.notify_vim:
            action = hostupdate.action
            LOG.info("Notify VIM host action %s action=%s" % (
                ihost_obj['hostname'], action))
            try:
                vim_api.vim_host_action(
                    self._api_token,
                    ihost_obj['uuid'],
                    ihost_obj['hostname'],
                    action,
                    constants.VIM_DEFAULT_TIMEOUT_IN_SECS)
            except Exception as e:
                LOG.warn(_("No response vim_api %s on action=%s e=%s" %
                         (ihost_obj['hostname'], action, e)))
                self._api_token = None
                if (action == constants.FORCE_LOCK_ACTION or
                   action == constants.FORCE_UNSAFE_LOCK_ACTION):
                    pass
                else:
                    # reject continuation if VIM rejects action
                    raise wsme.exc.ClientSideError(_(
                        "VIM API Error or Timeout on action = %s "
                        "Please retry and if problem persists then "
                        "contact your system administrator.") % action)

        if hostupdate.configure_required:
            LOG.info("%s Perform configure_ihost." % hostupdate.displayid)
            if not ((ihost_obj['hostname']) and (ihost_obj['personality'])):
                raise wsme.exc.ClientSideError(
                    _("Please provision 'hostname' and 'personality'."))

            pecan.request.rpcapi.configure_ihost(pecan.request.context, ihost_obj)

            pecan.request.dbapi.ihost_update(
                ihost_obj['uuid'], {'capabilities': ihost_obj['capabilities']})

            hostupdate.notify_mtce = True

        # Evaluate app reapply on lock/unlock/swact/reinstall
        if (not os.path.isfile(tsc.RESTORE_IN_PROGRESS_FLAG) and
                patched_ihost.get('action') in
                [constants.LOCK_ACTION, constants.FORCE_LOCK_ACTION, constants.FORCE_UNSAFE_LOCK_ACTION,
                 constants.UNLOCK_ACTION, constants.FORCE_UNLOCK_ACTION,
                 constants.SWACT_ACTION, constants.FORCE_SWACT_ACTION,
                 constants.REINSTALL_ACTION]):
            pecan.request.rpcapi.evaluate_apps_reapply(
                pecan.request.context,
                trigger={'type': patched_ihost.get('action'),
                         'configure_required': True if hostupdate.configure_required else False})

        pecan.request.dbapi.ihost_update(ihost_obj['uuid'],
                                         {'capabilities': ihost_obj['capabilities']})

        if constants.TASK_REINSTALLING == ihost_obj.task and \
                constants.CONFIG_STATUS_REINSTALL == \
                ihost_obj.config_status:
            # Clear reinstall flag when reinstall starts
            ihost_obj.config_status = None

        mtc_response = {'status': None}
        nonmtc_change_count = 0
        if hostupdate.notify_mtce and not hostupdate.skip_notify_mtce:
            nonmtc_change_count = self.check_notify_mtce(myaction, hostupdate)
            if nonmtc_change_count > 0:
                LOG.info("%s Action %s perform notify_mtce" %
                         (hostupdate.displayid, myaction))

                new_ihost_mtc = ihost_obj.as_dict()
                new_ihost_mtc = cutils.removekeys_nonmtce(new_ihost_mtc)

                if hostupdate.ihost_orig['invprovision'] in [constants.UPGRADING, constants.PROVISIONED]:
                    new_ihost_mtc.update({'operation': 'modify'})
                else:
                    new_ihost_mtc.update({'operation': 'add'})
                new_ihost_mtc.update({"invprovision": ihost_obj['invprovision']})

                if hostupdate.notify_action_lock:
                    new_ihost_mtc['action'] = constants.LOCK_ACTION
                elif hostupdate.notify_action_lock_force:
                    new_ihost_mtc['action'] = constants.FORCE_LOCK_ACTION
                elif hostupdate.notify_action_lock_force_unsafe:
                    new_ihost_mtc['action'] = constants.FORCE_UNSAFE_LOCK_ACTION
                elif myaction == constants.FORCE_UNLOCK_ACTION:
                    new_ihost_mtc['action'] = constants.UNLOCK_ACTION

                # Notify maintenance about updated mgmt_ip
                system = pecan.request.dbapi.isystem_get_one()
                if (system.capabilities.get('simplex_to_duplex_migration') or
                        system.capabilities.get('simplex_to_duplex-direct_migration')) and \
                        ihost_obj.hostname == constants.CONTROLLER_0_HOSTNAME:
                    # during migration, controller-0 is still using the mgmt floating address,
                    # the unit address will be available only after unlock to finish migration to DX
                    new_ihost_mtc['mgmt_ip'] = utils.get_mgmt_ip(constants.CONTROLLER_HOSTNAME)
                else:
                    new_ihost_mtc['mgmt_ip'] = utils.get_mgmt_ip(ihost_obj.hostname)

                if new_ihost_mtc['operation'] == 'add':
                    # Evaluate apps reapply on new host
                    pecan.request.rpcapi.evaluate_apps_reapply(
                        pecan.request.context,
                        trigger={'type': constants.APP_EVALUATE_REAPPLY_TYPE_HOST_ADD})

                    mtc_response = mtce_api.host_add(
                        self._api_token, self._mtc_address, self._mtc_port,
                        new_ihost_mtc,
                        constants.MTC_DEFAULT_TIMEOUT_IN_SECS)
                elif new_ihost_mtc['operation'] == 'modify':
                    mtc_response = mtce_api.host_modify(
                        self._api_token, self._mtc_address, self._mtc_port,
                        new_ihost_mtc,
                        constants.MTC_DEFAULT_TIMEOUT_IN_SECS,
                        3)
                else:
                    LOG.warn("Unsupported Operation: %s" % new_ihost_mtc)
                    mtc_response = None

                if mtc_response is None:
                    mtc_response = {'status': 'fail',
                                    'reason': 'no response',
                                    'action': 'retry'}

        ihost_obj['action'] = constants.NONE_ACTION
        hostupdate.ihost_val_update({'action': constants.NONE_ACTION})

        if ((mtc_response['status'] == 'pass') or
           (nonmtc_change_count == 0) or hostupdate.skip_notify_mtce):

            ihost_obj.save()

            if hostupdate.ihost_patch['operational'] == \
                    constants.OPERATIONAL_ENABLED:
                self._update_add_ceph_state()

            if hostupdate.notify_availability:
                if (hostupdate.notify_availability ==
                   constants.VIM_SERVICES_DISABLED):
                    imsg_dict = {'availability':
                                 constants.AVAILABILITY_OFFLINE}
                else:
                    imsg_dict = {'availability':
                                 constants.VIM_SERVICES_ENABLED}
                    if (hostupdate.notify_availability !=
                       constants.VIM_SERVICES_ENABLED):
                        LOG.error(_("Unexpected notify_availability = %s" %
                                  hostupdate.notify_availability))

                LOG.info(_("%s notify_availability=%s" %
                         (hostupdate.displayid, hostupdate.notify_availability)))

                pecan.request.rpcapi.iplatform_update_by_ihost(
                    pecan.request.context, ihost_obj['uuid'], imsg_dict)

            if hostupdate.bm_type_changed_to_none:
                ibm_msg_dict = {}
                pecan.request.rpcapi.ibm_deprovision_by_ihost(
                    pecan.request.context,
                    ihost_obj['uuid'],
                    ibm_msg_dict)

        elif mtc_response['status'] is None:
            raise wsme.exc.ClientSideError(
                _("Timeout waiting for maintenance response. "
                  "Please retry and if problem persists then "
                  "contact your system administrator."))
        else:
            if hostupdate.configure_required:
                # rollback to unconfigure host as mtce has failed the request
                invprovision_state = hostupdate.ihost_orig.get('invprovision') or ""
                if invprovision_state not in [constants.UPGRADING, constants.PROVISIONED]:
                    LOG.warn("unconfigure ihost %s provision=%s" %
                             (ihost_obj.uuid, invprovision_state))
                    pecan.request.rpcapi.unconfigure_ihost(
                        pecan.request.context,
                        ihost_obj)

            raise wsme.exc.ClientSideError(_("Operation Rejected: %s. %s.") %
                                           (mtc_response['reason'],
                                            mtc_response['action']))

        if hostupdate.notify_vim_add_host:
            # Notify the VIM that the host has been added - must be done after
            # the host has been added to mtc and saved to the DB.
            LOG.info("sysinv notify add host add %s subfunctions=%s" %
                     (ihost_obj['hostname'], ihost_obj['subfunctions']))
            try:
                vim_api.vim_host_add(
                    self._api_token,
                    ihost_obj['uuid'],
                    ihost_obj['hostname'],
                    ihost_obj['subfunctions'],
                    ihost_obj['administrative'],
                    ihost_obj['operational'],
                    ihost_obj['availability'],
                    ihost_obj['subfunction_oper'],
                    ihost_obj['subfunction_avail'],
                    constants.VIM_DEFAULT_TIMEOUT_IN_SECS)
            except Exception as e:
                LOG.warn(_("No response from vim_api %s e=%s" %
                           (ihost_obj['hostname'], e)))
                self._api_token = None
                pass  # VIM audit will pickup

        # check if ttys_dcd is updated and notify the agent via conductor
        # if necessary
        if 'ttys_dcd' in hostupdate.delta:
            self._handle_ttys_dcd_change(hostupdate.ihost_orig,
                                         hostupdate.ihost_patch['ttys_dcd'])

        # check if apparmor is updated and notify the agent via conductor
        if 'apparmor' in hostupdate.delta:
            self._handle_apparmor_change(hostupdate.ihost_orig,
            hostupdate.ihost_patch['apparmor'])

        if 'clock_synchronization' in hostupdate.delta:
            # perform rpc to conductor to perform config apply
            pecan.request.rpcapi.update_clock_synchronization_config(
                pecan.request.context, patched_ihost)

        log_end = cutils.timestamped("ihost_patch_end")
        if uptime_update:
            LOG.debug("host %s %s patch" % (ihost_obj.hostname,
                                            log_end))
        else:
            LOG.info("host %s %s patch" % (ihost_obj.hostname,
                                           log_end))

        if ('administrative' in hostupdate.delta and
                hostupdate.ihost_patch['administrative'] ==
                constants.ADMIN_LOCKED):
            LOG.info("Update host memory for (%s)" % ihost_obj['hostname'])
            pecan.request.rpcapi.update_host_memory(pecan.request.context,
                                                    ihost_obj['uuid'])

        # The restore_in_progress flag file is needed to bypass vim and
        # application re-apply when issuing the first unlock command during
        # restore. Once the command is accepted by mtce, it can be removed.
        if (os.path.isfile(tsc.RESTORE_IN_PROGRESS_FLAG) and
                patched_ihost.get('action') in
                [constants.UNLOCK_ACTION, constants.FORCE_UNLOCK_ACTION]):
            # flag file can only be deleted by root. So
            # have to send a rpc request to sysinv-conductor to do it.
            pecan.request.rpcapi.delete_flag_file(
                pecan.request.context, tsc.RESTORE_IN_PROGRESS_FLAG)

        return Host.convert_with_links(ihost_obj)

    def _vim_host_add(self, ihost):
        LOG.info("sysinv notify vim add host %s personality=%s" % (
            ihost['hostname'], ihost['personality']))

        subfunctions = self._update_subfunctions(ihost)
        try:
            # TODO: if self._api_token is None or \
            #    self._api_token.is_expired():
            #     self._api_token = rest_api.get_token()

            vim_api.vim_host_add(
                self._api_token,
                ihost['uuid'],
                ihost['hostname'],
                subfunctions,
                ihost['administrative'],
                ihost['operational'],
                ihost['availability'],
                ihost['subfunction_oper'],
                ihost['subfunction_avail'],
                constants.VIM_DEFAULT_TIMEOUT_IN_SECS)
        except Exception as e:
            LOG.warn(_("No response from vim_api %s e=%s" %
                       (ihost['hostname'], e)))
            self._api_token = None
            pass  # VIM audit will pickup

    @staticmethod
    def _check_host_delete_during_upgrade():
        """ Determine whether host delete is allowed during upgrade

            returns: boolean False if not allowed
        """

        upgrade = None
        try:
            upgrade = usm_service.get_platform_upgrade(pecan.request.dbapi)
        except exception.NotFound:
            return True

        if upgrade:
            active_controller = utils.HostHelper.get_active_controller()
            host_upgrade = usm_service.UsmHostUpgrade.get_by_hostname(
                pecan.request.dbapi, active_controller.hostname)

            if (host_upgrade is not None and
                    host_upgrade.state not in constants.DEPLOY_HOST_DEPLOYED_STATES):
                LOG.info("_check_host_delete_during_upgrade %s sw=%s target=%s" % (
                    active_controller.hostname,
                    host_upgrade.from_sw_version,
                    host_upgrade.to_sw_version))
                return False

        return True

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, six.text_type, status_code=204)
    def delete(self, ihost_id):
        """Delete an ihost.
        """

        ihost = objects.host.get_by_uuid(pecan.request.context,
                                         ihost_id)

        if (utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX and
                  ihost['hostname'] == constants.CONTROLLER_0_HOSTNAME):
            raise wsme.exc.ClientSideError(_(
                "Deleting controller-0 on a simplex system is not allowed."))

        if ihost['administrative'] == constants.ADMIN_UNLOCKED:
            if ihost.hostname is None:
                host = ihost.uuid
            else:
                host = ihost.hostname

            raise exception.HostLocked(action=constants.DELETE_ACTION, host=host)

        if StorageBackendConfig.has_backend_configured(pecan.request.dbapi,
                                                       constants.SB_TYPE_CEPH_ROOK):
            hostfs_list = pecan.request.dbapi.host_fs_get_by_ihost(ihost.id)
            istors = pecan.request.dbapi.istor_get_by_ihost(ihost.uuid)

            for host_fs in hostfs_list:
                if (host_fs.name == constants.FILESYSTEM_NAME_CEPH and
                        host_fs.state == constants.HOST_FS_STATUS_IN_USE):
                    raise wsme.exc.ClientSideError(_("host-delete rejected: not allowed when "
                                                     "the host has host-fs ceph with in-use state"))

            for stor in istors:
                if (stor.function == constants.STOR_FUNCTION_OSD and
                        (stor.state == constants.SB_STATE_CONFIGURED)):
                    raise wsme.exc.ClientSideError(_("host-delete rejected: not allowed when "
                                                     "the host has OSD with configured state"))

        if not self._check_host_delete_during_upgrade():
            raise wsme.exc.ClientSideError(_(
                "host-delete rejected: not allowed at this upgrade stage"))

        personality = ihost.personality
        # allow deletion of unprovisioned locked disabled & offline storage hosts
        skip_ceph_checks = (
            (not ihost['invprovision'] or
                ihost['invprovision'] == constants.UNPROVISIONED) and
            ihost['administrative'] == constants.ADMIN_LOCKED and
            ihost['operational'] == constants.OPERATIONAL_DISABLED and
            ihost['availability'] == constants.AVAILABILITY_OFFLINE)

        if (personality is not None and
                personality.find(constants.STORAGE_HOSTNAME) != -1 and
                not skip_ceph_checks):
            utils.check_node_lock_ceph_mon(ihost, unsafe=True, ceph_helper=self._ceph)

            # If it is the last storage node to delete, we need to delete
            # ceph osd pools and update additional tier status to "defined"
            # if no backend is attached to the tier.
            storage_nodes = pecan.request.dbapi.ihost_get_by_personality(
                constants.STORAGE)
            if len(storage_nodes) == 1:
                # update tier status
                tier_list = pecan.request.dbapi.storage_tier_get_list()
                for tier in tier_list:
                    if (tier.name != constants.SB_TIER_DEFAULT_NAMES[
                            constants.SB_TIER_TYPE_CEPH] and not tier.forbackendid):
                        pecan.request.dbapi.storage_tier_update(tier.id,
                            {'status': constants.SB_TIER_STATUS_DEFINED})

        LOG.warn("REST API delete host=%s user_agent=%s" %
                 (ihost['uuid'], pecan.request.user_agent))
        if not pecan.request.user_agent.startswith('vim'):
            try:
                # TODO: if self._api_token is None or \
                #   self._api_token.is_expired():
                #    self._api_token = rest_api.get_token()

                vim_api.vim_host_delete(
                    self._api_token,
                    ihost.uuid,
                    ihost.hostname,
                    constants.VIM_DELETE_TIMEOUT_IN_SECS)
            except Exception:
                LOG.warn(_("No response from vim_api %s " % ihost['uuid']))
                raise wsme.exc.ClientSideError(_("System rejected delete "
                                                 "request.  Please retry and if problem persists then "
                                                 "contact your system administrator."))

            if (ihost.hostname and ihost.personality and
               ihost.invprovision and
               ihost.invprovision in [constants.UPGRADING, constants.PROVISIONED] and
               (constants.WORKER in ihost.subfunctions)):
                # wait for VIM signal
                return

        openstack_worker = False
        labels = objects.label.get_by_host_id(pecan.request.context, ihost.uuid)
        for l in labels:
            if (constants.COMPUTE_NODE_LABEL ==
                    str(l.label_key) + '=' + str(l.label_value)):
                openstack_worker = True
                break

        if ihost.hostname and ihost.personality:
            self._notify_mtce_host_delete(ihost)

        pecan.request.rpcapi.unconfigure_ihost(pecan.request.context,
                                               ihost)

        # reset the ceph_mon_dev for the controller node being deleted
        if ihost.personality == constants.CONTROLLER:
            ceph_mons = pecan.request.dbapi.ceph_mon_get_by_ihost(ihost.uuid)
            if ceph_mons and ceph_mons[0].device_path:
                pecan.request.dbapi.ceph_mon_update(
                    ceph_mons[0].uuid, {'device_path': None}
                )

        remove_from_cluster = True if ihost.invprovision in [constants.UPGRADING, constants.PROVISIONED] else False

        # Delete the stor entries associated with this host
        istors = pecan.request.dbapi.istor_get_by_ihost(ihost['uuid'])

        for stor in istors:
            try:
                self.istors.delete_stor(stor.uuid, remove_from_cluster)
            except Exception as e:
                # Do not destroy the ihost if the stor cannot be deleted.
                LOG.exception(e)
                self._vim_host_add(ihost)
                raise wsme.exc.ClientSideError(
                    _("Failed to delete Storage Volumes associated with this "
                      "host. Please retry and if problem persists then contact"
                      " your system administrator."))

        # Delete the lvgs entries associated with this host
        ilvgs = pecan.request.dbapi.ilvg_get_by_ihost(ihost['uuid'])

        for lvg in ilvgs:
            try:
                self.ilvgs.delete(lvg.uuid)
            except Exception as e:
                # Do not destroy the ihost if the lvg cannot be deleted.
                LOG.exception(e)
                self._vim_host_add(ihost)
                raise wsme.exc.ClientSideError(
                    _("Failed to delete Local Volume Group(s). Please retry and "
                      "if problem persists then contact your system "
                      "administrator."))

        # Delete the pvs entries associated with this host
        # Note: pvs should have been deleted via cascade with it's lvg.
        # This should be unnecessary
        ipvs = pecan.request.dbapi.ipv_get_by_ihost(ihost['uuid'])

        for pv in ipvs:
            try:
                self.ipvs.delete(pv.uuid)
            except Exception as e:
                # Do not destroy the ihost if the stor cannot be deleted.
                self._vim_host_add(ihost)
                LOG.exception(e)
                raise wsme.exc.ClientSideError(
                    _("Failed to delete Physical Volume(s). Please retry and if "
                      "problem persists then contact your system "
                      "administrator."))

        # tell conductor to delete the barbican entry associated with this host (if present)
        pecan.request.rpcapi.delete_barbican_secret(pecan.request.context,
                                                    ihost.uuid)

        # Notify patching to drop the host
        if ihost.hostname is not None:
            try:
                # TODO: if self._api_token is None or \
                #   self._api_token.is_expired():
                #    self._api_token = rest_api.get_token()
                system = pecan.request.dbapi.isystem_get_one()
                patch_api.patch_drop_host(
                    token=self._api_token,
                    timeout=constants.PATCH_DEFAULT_TIMEOUT_IN_SECS,
                    hostname=ihost.hostname,
                    region_name=system.region_name)
            except Exception as e:
                LOG.warn(_("No response from drop-host patch api %s e=%s" %
                           (ihost.hostname, e)))
                pass

        personality = ihost.personality
        if (personality is not None and
                personality.find(constants.STORAGE_HOSTNAME) != -1 and
                ihost.hostname not in [constants.STORAGE_0_HOSTNAME,
                constants.STORAGE_1_HOSTNAME] and
                ihost.invprovision in [constants.UPGRADING, constants.PROVISIONED,
                constants.PROVISIONING]):
            self._ceph.host_crush_remove(ihost.hostname)

        pecan.request.dbapi.ihost_destroy(ihost_id)

        # Check if platform apps need to be reapplied after host delete
        pecan.request.rpcapi.evaluate_apps_reapply(
            pecan.request.context,
            trigger={'type': constants.APP_EVALUATE_REAPPLY_TYPE_HOST_DELETE,
                     'openstack_worker': True if openstack_worker else False,
                     'personality': personality})

        # Delete the certificate request related to the host
        cert_name = ipsec_constants.CERT_NAME_PREFIX + str(ihost['hostname'])
        if cutils.is_certificate_request_created(cert_name):
            cutils.delete_certificate_request(cert_name)

    def _notify_mtce_host_delete(self, ihost):

        mtce_request_dict = {'operation': constants.DELETE_ACTION,
                             'uuid': ihost.uuid,
                             'invprovision': ihost.invprovision}

        mtc_response_dict = mtce_api.host_delete(
            self._api_token, self._mtc_address, self._mtc_port,
            mtce_request_dict, constants.MTC_DELETE_TIMEOUT_IN_SECS)

        LOG.info("Mtce Delete Response: %s", mtc_response_dict)

        if mtc_response_dict is None:
            mtc_response_dict = {'status': 'fail',
                                 'reason': 'no response',
                                 'action': 'retry'}

        # Check mtce response prior to attempting delete
        if mtc_response_dict.get('status') != 'pass':
            self._vim_host_add(ihost)
            if mtc_response_dict.get('reason') != 'no response':
                raise wsme.exc.ClientSideError(
                    _("Mtce rejected host-delete request."
                      "Please retry and if problem persists then contact "
                      "your system administrator."))
            else:
                raise wsme.exc.ClientSideError(
                    _("Timeout waiting for system response. Please wait "
                      "for a few moments. If the host is not deleted, "
                      "please retry. If problem persists then contact "
                      "your system administrator."))

    def _check_upgrade_provision_order(self, personality, hostname):
        LOG.info("_check_upgrade_provision_order personality=%s, hostname=%s" %
                  (personality, hostname))

        # If this is a simplex system skip this check; there's no other nodes
        simplex = (utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX)
        if simplex:
            return

        try:
            usm_service.get_platform_upgrade(pecan.request.dbapi)
        except exception.NotFound:
            return

        if personality == constants.STORAGE:
            if hostname == constants.STORAGE_0_HOSTNAME:
                LOG.warn("Allow storage-0 add during upgrade")
            else:
                LOG.info("Adding storage, ensure controllers upgraded")

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Host, six.text_type, body=six.text_type)
    def upgrade(self, uuid, body):
        """Upgrade the host to the specified load"""

        raise NotImplementedError("This API is deprecated.")

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Host, six.text_type, body=six.text_type)
    def downgrade(self, uuid, body):
        """Downgrade the host to the specified load"""

        raise NotImplementedError("This API is deprecated.")

    def _semantic_check_rollback(self):
        hosts = pecan.request.dbapi.ihost_get_list()
        for host in hosts:
            if host.personality not in [constants.WORKER, constants.STORAGE]:
                continue
            ceph_mon = pecan.request.dbapi.ceph_mon_get_by_ihost(host.uuid)
            if ceph_mon:
                continue
            if host.administrative != constants.ADMIN_LOCKED or \
                    host.availability != constants.AVAILABILITY_OFFLINE:
                raise wsme.exc.ClientSideError(
                    _("All worker and storage hosts not running a Ceph monitor "
                      "must be locked and offline before this operation can proceed"))

    def _check_max_cpu_mhz_configured(self, host):
        cpu_utils.check_power_manager(host.ihost_patch.get('uuid'))

        # Max CPU frequency requested by the user and the maximum frequency
        # allowed by the CPU.
        max_cpu_mhz_configured = str(host.ihost_patch.get('max_cpu_mhz_configured', ''))
        max_cpu_mhz_allowed = host.ihost_orig.get('max_cpu_mhz_allowed', 0)

        if (constants.WORKER in host.ihost_orig[constants.SUBFUNCTIONS] and
            host.ihost_orig.get('capabilities').get(constants.IHOST_IS_MAX_CPU_MHZ_CONFIGURABLE) ==
                constants.CONFIGURABLE and max_cpu_mhz_allowed):
            max_cpu_mhz_allowed = int(max_cpu_mhz_allowed)

            # The service parameter is used to constrain the max_cpu_mhz_configured
            # into a range defined as a percentage of the max frequency allowed
            # by the CPU and the max CPU frequency allowed itself.
            max_cpu_percentage = pecan.request.dbapi.service_parameter_get_one(
                service=constants.SERVICE_TYPE_PLATFORM,
                section=constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
                name=constants.SERVICE_PARAM_NAME_PLATFORM_MAX_CPU_PERCENTAGE
            ).value
            max_cpu_floor = (int(max_cpu_percentage) * max_cpu_mhz_allowed) // 100

            #  Restore the max_cpu_mhz_configured to default if user set max_cpu_mhz_configured
            # to max_cpu_mhz_allowed.
            if max_cpu_mhz_configured == constants.IHOST_MAX_CPU_MHZ_ALLOWED:
                host.ihost_patch['max_cpu_mhz_configured'] = max_cpu_mhz_allowed
                return

            if not max_cpu_mhz_configured.lstrip('-+').isdigit():
                raise wsme.exc.ClientSideError(
                    _("Max CPU frequency %s must be an integer.")
                    % (max_cpu_mhz_configured))

            if not (max_cpu_floor <= int(max_cpu_mhz_configured) <= max_cpu_mhz_allowed):
                raise wsme.exc.ClientSideError(
                    _("Max CPU Frequency must be between (%d, %d).")
                    % (max_cpu_floor, max_cpu_mhz_allowed))
        else:
            raise wsme.exc.ClientSideError(
                _("Host does not support configuration of Max CPU Frequency."))

    @staticmethod
    def _validate_ip_in_mgmt_network(ip):
        network = pecan.request.dbapi.network_get_by_type(
            constants.NETWORK_TYPE_MGMT)
        utils.validate_address_within_nework(ip, network)

    @staticmethod
    def _validate_address_not_allocated(name, ip_address, net_type):
        """Validate that address isn't allocated

        :param name: Address name to check isn't allocated.
        :param ip_address: IP address to check isn't allocated.
        """
        if name and ip_address:
            try:
                address = \
                    pecan.request.dbapi.address_get_by_address(ip_address)
                if address.name != name and utils.is_address_assigned(address):
                    raise exception.AddressAlreadyAllocated(address=ip_address)
            except exception.AddressNotFoundByAddress:
                pass
            try:
                address = utils.get_primary_address_by_name(name, net_type, True)
                if address.address != ip_address:
                    raise exception.AddressAlreadyAllocated(address=name)
            except exception.AddressNotFoundByName:
                pass

    @staticmethod
    def _dnsmasq_mac_exists(mac_addr):
        """Check the dnsmasq.hosts file for an existing mac.

        :param mac_addr: mac address to check for.
        """

        dnsmasq_hosts_file = tsc.CONFIG_PATH + 'dnsmasq.hosts'
        with open(dnsmasq_hosts_file, 'r') as f_in:
            for line in f_in:
                if mac_addr in line:
                    return True
        return False

    @staticmethod
    def _no_controllers_exist():
        current_ihosts = pecan.request.dbapi.ihost_get_list()
        hostnames = [h['hostname'] for h in current_ihosts]
        return constants.CONTROLLER_0_HOSTNAME not in hostnames and \
               constants.CONTROLLER_1_HOSTNAME not in hostnames

    @staticmethod
    def _validate_delta(delta):
        restricted_updates = ['uuid', 'id', 'created_at', 'updated_at',
                              'cstatus',
                              'mgmt_mac', 'mgmt_ip',
                              'invprovision', 'recordtype',
                              'ihost_action',
                              'action_state',
                              'inv_state',
                              'iconfig_applied',
                              'iconfig_target']

        if not pecan.request.user_agent.startswith('mtce'):
            # Allow mtc to modify these through sysinv-api.
            mtce_only_updates = ['administrative',
                                 'availability',
                                 'operational',
                                 'subfunction_oper',
                                 'subfunction_avail',
                                 'reserved',
                                 'mtce_info',
                                 'task',
                                 'uptime']
            restricted_updates.extend(mtce_only_updates)

        if not pecan.request.user_agent.startswith('vim'):
            vim_only_updates = ['vim_progress_status']
            restricted_updates.extend(vim_only_updates)

        intersection = set.intersection(set(delta), set(restricted_updates))
        if intersection:
            raise wsme.exc.ClientSideError(
                _("Change %s contains restricted %s." % (delta, intersection)))
        else:
            LOG.debug("PASS deltaset=%s restricted_updates %s" %
                      (delta, intersection))

    @staticmethod
    def _valid_storage_hostname(hostname):
        return bool(re.match('^%s-[0-9]+$' % constants.STORAGE_HOSTNAME,
                             hostname))

    def _validate_hostname(self, hostname, personality):

        if personality and \
                (personality == constants.WORKER or
                 personality == constants.EDGEWORKER):
            # Fix of invalid hostnames
            err_tl = 'Name restricted to at most 255 characters.'
            err_ic = 'Name may only contain letters, ' \
                     'numbers, underscores, periods and hyphens.'
            myexpression = re.compile("^[\w\.\-]+$")
            if not myexpression.match(hostname):
                raise wsme.exc.ClientSideError(_(err_ic))
            if len(hostname) > 255:
                raise wsme.exc.ClientSideError(_(err_tl))
            non_worker_hosts = ([constants.CONTROLLER_0_HOSTNAME,
                                  constants.CONTROLLER_1_HOSTNAME])
            if (hostname and (hostname in non_worker_hosts) or
                    hostname.startswith(constants.STORAGE_HOSTNAME)):

                raise wsme.exc.ClientSideError(
                        _("%s Reject attempt to configure "
                        "invalid hostname for personality %s." %
                        (hostname, personality)))
        else:
            if personality and personality == constants.CONTROLLER:
                valid_hostnames = [constants.CONTROLLER_0_HOSTNAME,
                                   constants.CONTROLLER_1_HOSTNAME]
                if hostname not in valid_hostnames:
                    raise wsme.exc.ClientSideError(
                        _("Host with personality=%s can only have a hostname "
                          "from %s" % (personality, valid_hostnames)))
            elif personality and personality == constants.STORAGE:
                if not self._valid_storage_hostname(hostname):
                    raise wsme.exc.ClientSideError(
                        _("Host with personality=%s can only have a hostname "
                          "starting with %s-(number)" %
                          (personality, constants.STORAGE_HOSTNAME)))

            else:
                raise wsme.exc.ClientSideError(
                    _("%s: Reject attempt to configure with "
                      "invalid personality=%s " %
                      (hostname, personality)))

    @staticmethod
    def _check_worker(patched_ihost, hostupdate=None):
        # Check for valid worker node setup
        hostname = patched_ihost.get('hostname') or ""

        if not hostname:
            raise wsme.exc.ClientSideError(
                _("Host %s of personality %s, must be provisioned with a hostname."
                  % (patched_ihost.get('uuid'), patched_ihost.get('personality'))))

        non_worker_hosts = ([constants.CONTROLLER_0_HOSTNAME,
                              constants.CONTROLLER_1_HOSTNAME])
        if (hostname in non_worker_hosts or
           hostname.startswith(constants.STORAGE_HOSTNAME)):
            raise wsme.exc.ClientSideError(
                _("Hostname %s is not allowed for personality 'worker'. "
                  "Please check hostname and personality." % hostname))

    def _controller_storage_node_setup(self, patched_ihost, hostupdate=None):
        # Initially set the subfunction of the host to it's personality

        if hostupdate:
            patched_ihost = hostupdate.ihost_patch

        patched_ihost['subfunctions'] = patched_ihost['personality']

        if patched_ihost['personality'] == constants.CONTROLLER:
            controller_0_exists = False
            controller_1_exists = False
            current_ihosts = \
                pecan.request.dbapi.ihost_get_by_personality(constants.CONTROLLER)
            for h in current_ihosts:
                if h['hostname'] == constants.CONTROLLER_0_HOSTNAME:
                    controller_0_exists = True
                elif h['hostname'] == constants.CONTROLLER_1_HOSTNAME:
                        controller_1_exists = True
            if controller_0_exists and controller_1_exists:
                raise wsme.exc.ClientSideError(
                    _("Two controller nodes have already been configured. "
                      "This host can not be configured as a controller."))

            # Look up the IP address to use for this controller and set
            # the hostname.
            if controller_0_exists:
                hostname = constants.CONTROLLER_1_HOSTNAME
                if hostupdate:
                    hostupdate.ihost_val_update({'hostname': hostname})
                else:
                    patched_ihost['hostname'] = hostname
            elif controller_1_exists:
                hostname = constants.CONTROLLER_0_HOSTNAME
                if hostupdate:
                    hostupdate.ihost_val_update({'hostname': hostname})
                else:
                    patched_ihost['hostname'] = hostname
            else:
                raise wsme.exc.ClientSideError(
                    _("Attempting to provision a controller when none "
                      "exists. This is impossible."))

            # Subfunctions can be set directly via the config file
            subfunctions = ','.join(tsc.subfunctions)
            if hostupdate:
                hostupdate.ihost_val_update({'subfunctions': subfunctions})
            else:
                patched_ihost['subfunctions'] = subfunctions

        elif patched_ihost['personality'] == constants.STORAGE:
            # Storage nodes are only allowed if we are configured to use ceph.
            if not StorageBackendConfig.has_backend_configured(
                pecan.request.dbapi,
                constants.SB_TYPE_CEPH
            ):
                raise wsme.exc.ClientSideError(
                    _("Storage nodes can only be configured if storage "
                      "cluster is configured for the Ceph backend."))

            # Storage nodes are allowed when using the CEPH_STORAGE_MODEL model
            stor_model = ceph.get_ceph_storage_model()
            if stor_model not in [constants.CEPH_STORAGE_MODEL, constants.CEPH_UNDEFINED_MODEL]:
                # Adding storage-0 when storage model is CEPH_UNDEFINED_MODEL will
                # set it to CEPH_STORAGE_MODEL.
                raise wsme.exc.ClientSideError(
                    _("Storage nodes can not be configured for "
                      "the '%s' storage model." % stor_model))

            current_storage_ihosts = \
                pecan.request.dbapi.ihost_get_by_personality(constants.STORAGE)

            current_storage = []
            for h in current_storage_ihosts:
                if self._valid_storage_hostname(h['hostname']):
                    current_storage.append(h['hostname'])

            max_storage_hostnames = ["storage-%s" % x for x in
                                     range(len(current_storage_ihosts) + 1)]

            # Look up IP address to use storage hostname
            for h in reversed(max_storage_hostnames):
                if h not in current_storage:
                    hostname = h
                    LOG.info("Found new hostname=%s"
                             "current_storage=%s" %
                             (hostname, current_storage))
                    break

            if patched_ihost['hostname']:
                if patched_ihost['hostname'] != hostname:
                    raise wsme.exc.ClientSideError(
                        _("Storage name %s not allowed.  Expected %s. "
                          "Storage nodes can be one of: "
                          "storage-#." %
                          (patched_ihost['hostname'], hostname)))

            if hostupdate:
                hostupdate.ihost_val_update({'hostname': hostname})
            else:
                patched_ihost['hostname'] = hostname

    @staticmethod
    def _optimize_delta_handling(delta_handle):
        """Optimize specific patch operations.
           Updates delta_handle to identify remaining patch semantics to check.
        """
        optimizable = ['location', 'serialid']
        if pecan.request.user_agent.startswith('mtce'):
            mtc_optimizable = ['operational', 'availability', 'task', 'uptime',
                               'subfunction_oper', 'subfunction_avail']
            optimizable.extend(mtc_optimizable)

        for k in optimizable:
            if k in delta_handle:
                delta_handle.remove(k)

    @staticmethod
    def _semantic_check_interface_addresses(ihost, interface, min_count=0):
        """
        Perform IP address semantic checks on a specific interface.
        """
        count = 0

        if not any(nt in address_api.ALLOWED_NETWORK_TYPES for nt in interface.networktypelist):
                return
        # Check IPv4 address presence
        addresses = pecan.request.dbapi.addresses_get_by_interface(
            interface['id'], family=constants.IPV4_FAMILY)
        count += len(addresses)
        if interface.ipv4_mode == constants.IPV4_STATIC:
            if not addresses:
                msg = (_("Interface %(ifname)s on host %(host)s is configured "
                         "for IPv4 static address but has no configured "
                         "IPv4 address") %
                       {'host': ihost['hostname'],
                        'ifname': interface.ifname})
                raise wsme.exc.ClientSideError(msg)
        # Check IPv6 address presence
        addresses = pecan.request.dbapi.addresses_get_by_interface(
            interface['id'], family=constants.IPV6_FAMILY)
        count += len(addresses)
        if interface.ipv6_mode == constants.IPV6_STATIC:
            if not addresses:
                msg = (_("Interface %(ifname)s on host %(host)s is configured "
                         "for IPv6 static address but has no configured "
                         "IPv6 address") %
                       {'host': ihost['hostname'],
                        'ifname': interface.ifname})
                raise wsme.exc.ClientSideError(msg)
        if min_count and (count < min_count):
            msg = (_("Expecting at least %(min)s IP address(es) on "
                     "%(ifclass)s interface %(ifname)s; found %(count)s") %
                   {'min': min_count,
                    'ifclass': interface.ifclass,
                    'ifname': interface.ifname,
                    'count': count})
            raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _check_sriovdp_interface_datanets(iface):
        """
        Perform SR-IOV device plugin semantic checks on a specific interface.
        """
        ihost_uuid = iface.ihost_uuid
        dbapi = pecan.request.dbapi

        host_labels = dbapi.label_get_by_host(ihost_uuid)
        if not cutils.has_sriovdp_enabled(host_labels):
            return

        if (iface.ifclass != constants.INTERFACE_CLASS_PCI_SRIOV and
                iface.ifclass != constants.INTERFACE_CLASS_PCI_PASSTHROUGH):
            return

        iface_dn, x = interface_api._datanetworks_get_by_interface(
            iface.uuid)

        # Collect all datanets and interfaces for the host to ensure
        # they are compatible with the interface being checked
        host_ifaces = dbapi.iinterface_get_by_ihost(ihost_uuid)
        for host_iface in host_ifaces:
            if host_iface.ifclass != iface.ifclass:
                # Only interfaces of the same class need to be checked
                # for compatibility
                continue
            if host_iface.uuid == iface.uuid:
                # Ignore the current interface
                continue

            host_iface_dn, x = interface_api._datanetworks_get_by_interface(
                host_iface.uuid)

            shared_dn = [dn for dn in host_iface_dn if dn in iface_dn]
            if not shared_dn:
                continue

            # SR-IOV interfaces on the same data network must not have a
            # mix of vfio / netdevice devices
            if iface.ifclass == constants.INTERFACE_CLASS_PCI_SRIOV:
                netdevice_driver = constants.SRIOV_DRIVER_TYPE_NETDEVICE
                driver1 = iface.sriov_vf_driver or netdevice_driver
                driver2 = host_iface.sriov_vf_driver or netdevice_driver
                if driver1 != driver2:
                    msg = (_("VF driver (%s) for interface (%s) conflicts "
                             "with VF driver (%s) for interface (%s) "
                             "on data network(s) (%s). "
                             "Consider choosing another data network" %
                             (driver1, iface.ifname, driver2,
                              host_iface.ifname, shared_dn)))
                    raise wsme.exc.ClientSideError(msg)

            # SR-IOV interfaces on the same data network must not have a
            # mix of Mellanox / Intel devices
            iports = dbapi.ethernet_port_get_by_interface(iface.uuid)
            hports = dbapi.ethernet_port_get_by_interface(host_iface.uuid)
            hport_drivers = [h['driver'] for h in hports]
            iport_drivers = [i['driver'] for i in iports]
            mlx_drivers = constants.MELLANOX_DRIVERS

            if (len(set(hport_drivers) & set(mlx_drivers)) !=
                    len(set(iport_drivers) & set(mlx_drivers))):
                msg = (_("PF driver(s) (%s) for interface (%s) conflict with "
                         "PF driver(s) (%s) for interface (%s) "
                         "on data network(s) (%s). "
                         "Consider choosing another data network" %
                         (iport_drivers, iface.ifname, hport_drivers,
                          host_iface.ifname, shared_dn)))
                raise wsme.exc.ClientSideError(msg)

    def _semantic_check_sriov_interface(self, host, interface, force_unlock=False):
        """
        Perform semantic checks on an SRIOV interface.
        """
        if (force_unlock or
                interface.ifclass != constants.INTERFACE_CLASS_PCI_SRIOV):
            return

        if interface.iftype == constants.INTERFACE_TYPE_ETHERNET:
            if_configured_sriov_numvfs = interface.sriov_numvfs
            if not if_configured_sriov_numvfs:
                return

            # we might be preventing the configuration needed to have valid
            # SRIOV port data related to the interface
            check_sriov_port_data = True
            if (not utils.is_host_active_controller(host)
                    and host['config_status'] == constants.CONFIG_STATUS_OUT_OF_DATE
                    and host['administrative'] == constants.ADMIN_LOCKED):
                flip = utils.config_flip_reboot_required(host['config_target'])
                if (utils.config_is_reboot_required(host['config_target'])
                        and flip == host['config_applied']):
                    check_sriov_port_data = False

            if check_sriov_port_data:
                ports = pecan.request.dbapi.port_get_by_host_interface(
                    host['id'], interface.id)
                for p in ports:
                    if (p.sriov_vfs_pci_address and
                            if_configured_sriov_numvfs ==
                            len(p.sriov_vfs_pci_address.split(','))):
                        LOG.info("check sriov_numvfs=%s sriov_vfs_pci_address=%s" %
                                (if_configured_sriov_numvfs, p.sriov_vfs_pci_address))
                        break
                else:
                    msg = (_("Expecting number of interface sriov_numvfs=%s. "
                            "Please wait a few minutes for inventory update and "
                            "retry host-unlock." %
                            if_configured_sriov_numvfs))
                    LOG.info(msg)
                    pecan.request.rpcapi.update_sriov_config(
                        pecan.request.context,
                        host['uuid'])
                    raise wsme.exc.ClientSideError(msg)

                for p in ports:
                    if (interface.sriov_vf_driver == constants.SRIOV_DRIVER_TYPE_NETDEVICE and
                            p.sriov_vf_driver is None):
                        msg = (_("Value for SR-IOV VF driver is %s, but "
                                "corresponding port has an invalid driver" %
                                constants.SRIOV_DRIVER_TYPE_NETDEVICE))
                        LOG.info(msg)
                        raise wsme.exc.ClientSideError(msg)

        self._check_sriovdp_interface_datanets(interface)

    def _semantic_check_pcipt_interface(self, host, interface, force_unlock=False):
        """
        Perform semantic checks on an PCI-PASSTHROUGH interface.
        """
        if (force_unlock or
                interface.ifclass != constants.INTERFACE_CLASS_PCI_PASSTHROUGH):
            return

        self._check_sriovdp_interface_datanets(interface)

    def _semantic_check_acclr_fec_device(self, host, dev, force_unlock=False):
        """
        Perform semantic checks on an FEC device.
        """
        if (force_unlock or
           dev.pdevice_id not in device.SRIOV_ENABLED_FEC_DEVICE_IDS):
            return

        try:
            sriov_numvfs = int(dev.sriov_numvfs)
        except TypeError:
            sriov_numvfs = 0

        # Get the custom resource of the SRIOV fec operator app.
        # If fec operator is managing the device of the host,
        # it updates the sriov parameters in sysfs.
        # The expected_numvfs is not used. The checks below are skipped.
        sriovfec_list = self._kube_operator.list_namespaced_custom_resources(
            "sriovfec.intel.com",
            "v2",
            "sriov-fec-system",
            "sriovfecclusterconfigs")
        if sriovfec_list:
            for sriovfec_crd in sriovfec_list:
                if sriovfec_crd:
                    LOG.debug("sriovfec custom resource={}".format(sriovfec_crd))
                    spec = sriovfec_crd.get('spec', None)
                    if spec:
                        nodeselector = spec.get('nodeSelector', None)
                        hostname = nodeselector.get('kubernetes.io/hostname', None)
                        if hostname and hostname == host['hostname']:
                            accelerator_selector = spec.get('acceleratorSelector', None)
                            pci_address = accelerator_selector.get('pciAddress', None)
                            if pci_address == dev.pciaddr:
                                LOG.debug("Found device %s on host %s managed by "
                                          "FEC operator" %
                                          (dev.pciaddr, host['hostname']))
                                return
                    LOG.debug("Device %s on host %s not managed by FEC operator" %
                              (dev.pciaddr, host['hostname']))
                else:
                    LOG.debug("No sriovfec custom resource found, continue")

        if dev.extra_info:
            extra_info = ast.literal_eval(dev.extra_info)
            expected_numvfs = int(extra_info['expected_numvfs'])
            if sriov_numvfs != expected_numvfs:
                msg = (_("Expecting sriov_numvfs=%d for FEC device pciaddr=%s. "
                         "Please wait a few minutes for inventory update and "
                         "retry host-unlock." % (expected_numvfs, dev.pciaddr)))
                LOG.info(msg)
                pecan.request.rpcapi.update_sriov_config(
                    pecan.request.context,
                    host['uuid'])
                raise wsme.exc.ClientSideError(msg)

        if not dev.sriov_vfs_pci_address or len(dev.sriov_vfs_pci_address) == 0:
            sriov_vfs_pci_address = []
        else:
            sriov_vfs_pci_address = dev.sriov_vfs_pci_address.split(',')

        if sriov_numvfs == len(sriov_vfs_pci_address):
            if sriov_numvfs > 0:
                LOG.info("check sriov_numvfs=%s sriov_vfs_pci_address=%s" %
                         (sriov_numvfs, dev.sriov_vfs_pci_address))
        else:
            msg = (_("Expecting sriov_vfs_pci_address length=%d for FEC "
                     "device pciaddr=%s. Please wait a few minutes for "
                     "inventory update and retry host-unlock." %
                     (sriov_numvfs, dev.pciaddr)))
            LOG.info(msg)
            pecan.request.rpcapi.update_sriov_config(
                pecan.request.context,
                host['uuid'])
            raise wsme.exc.ClientSideError(msg)

    def _semantic_check_acclr_device(self, host, dev, force_unlock=False):
        """
        Perform semantic checks on an FEC device.
        """
        if dev.pclass_id != device.PCI_DEVICE_CLASS_FPGA:
            return

        if dev.pdevice_id in device.SRIOV_ENABLED_FEC_DEVICE_IDS:
            self._semantic_check_acclr_fec_device(host, dev, force_unlock)

    def _semantic_check_devices(self, host, force_unlock=False):
        """
        Perform semantic checks on pci devices.
        """
        devices = (
            pecan.request.dbapi.pci_device_get_by_host(host['uuid']))
        for dev in devices:
            if dev.pclass_id == device.PCI_DEVICE_CLASS_FPGA:
                self._semantic_check_acclr_device(host, dev, force_unlock)

    def _semantic_check_unlock_kube_upgrade(self, ihost, force_unlock=False):
        """
        Perform semantic checks related to kubernetes upgrades prior to unlocking host.
        """
        if force_unlock:
            LOG.warning("Host %s force unlock while kubelet upgrade "
                        "in progress." % ihost['hostname'])
            return

        kube_host_upgrade = \
            pecan.request.dbapi.kube_host_upgrade_get_by_host(ihost['uuid'])
        if kube_host_upgrade.status == kubernetes.KUBE_HOST_UPGRADING_KUBELET:
            msg = _("Can not unlock %s while upgrading kubelet. "
                    "Wait for kubelet upgrade to complete." % ihost['hostname'])
            raise wsme.exc.ClientSideError(msg)

    def _semantic_check_unlock_kube_rootca_update(self, ihost, force_unlock=False):
        """
        Perform semantic checks related to kubernetes rootca update
        prior to unlocking host.
        """

        if force_unlock:
            LOG.warning("Host %s force unlock while kubernetes "
                        "rootca update in progress." % ihost['hostname'])
            return

        try:
            kube_rootca_update = \
                pecan.request.dbapi.kube_rootca_update_get_one()

            if kube_rootca_update.state in [kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTBOTHCAS,
                                            kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTNEWCA]:
                msg = _("Can not unlock %s while kubernetes root ca "
                        "update phase in progress. Wait for update "
                        "phase to complete." % ihost['hostname'])
                raise wsme.exc.ClientSideError(msg)
        except exception.NotFound:
            LOG.debug("No kubernetes rootca update was found")
            return

        try:
            kube_host_rootca_update = \
                pecan.request.dbapi.kube_rootca_host_update_get_by_host(ihost['uuid'])
            if kube_host_rootca_update.state in [kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS,
                                                 kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS,
                                                 kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTNEWCA]:
                msg = _("Can not unlock %s while kubernetes root ca "
                        "update phase in progress. Wait for update "
                        "phase to complete on host." % ihost['hostname'])
                raise wsme.exc.ClientSideError(msg)
        except exception.NotFound:
            LOG.debug("No kubernetes rootca update on host %s "
                      "was found" % ihost['hostname'])
            return

    @staticmethod
    def _semantic_check_duplex_oam_config(ihost):
        system = pecan.request.dbapi.isystem_get_one()
        system_mode = system.system_mode
        if system.capabilities.get('simplex_to_duplex_migration') or \
           system.capabilities.get('simplex_to_duplex-direct_migration'):
            network = pecan.request.dbapi.network_get_by_type(constants.NETWORK_TYPE_OAM)
            address_names = {'oam_c0_ip': '%s-%s' % (constants.CONTROLLER_0_HOSTNAME,
                                                     constants.NETWORK_TYPE_OAM),
                             'oam_c1_ip': '%s-%s' % (constants.CONTROLLER_1_HOSTNAME,
                                                     constants.NETWORK_TYPE_OAM)}
            addresses = {a['name']: a for a in
                         pecan.request.dbapi.addresses_get_by_pool_uuid(network.pool_uuid)}

            # check if controller-0-oam and controller-1-oam entries exist
            for key, name in address_names.items():
                if addresses.get(name) is None:
                    msg = _("Can not unlock controller on a %s without "
                            "configuring %s." % (system_mode, key))
                    raise wsme.exc.ClientSideError(msg)
                if addresses[name].address is None:
                    msg = _("Can not unlock controller on a %s without "
                            "configuring a unit IP for %s." % (system_mode, key))
                    raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _semantic_check_oam_interface(ihost):
        """
        Perform semantic checks against oam interface to ensure validity of
        the node configuration prior to unlocking it.
        """
        interfaces = (
            pecan.request.dbapi.iinterface_get_by_ihost(ihost['uuid']))
        for interface in interfaces:
            if constants.NETWORK_TYPE_OAM in interface.networktypelist:
                break
        else:
            msg = _("Can not unlock a controller host without an oam "
                    "interface. "
                    "Add an oam interface before re-attempting this command.")
            raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _semantic_check_interface_datanets(interface):
        """
        Perform data network semantics on a specific interface to ensure
        that any data networks that have special requirements on the
        interface have been satisfied.
        """

        if interface.ifclass != constants.NETWORK_TYPE_DATA:
            return

        ifdatanets = \
            pecan.request.dbapi.interface_datanetwork_get_by_interface(
                interface.uuid)

        # Check for VXLAN data networks that require IP addresses
        for ifdn in ifdatanets:
            if ifdn.datanetwork_network_type != \
                    constants.DATANETWORK_TYPE_VXLAN:
                continue

            dn = pecan.request.dbapi.datanetwork_get(ifdn.datanetwork_uuid)
            if not dn.multicast_group:
                # static range; fallback to generic check
                continue

            # Check for address family specific ranges
            address = netaddr.IPAddress(dn.multicast_group)
            if ((address.version == constants.IPV4_FAMILY) and
                    (interface.ipv4_mode == constants.IPV4_DISABLED or not
                     interface.ipv4_mode)):
                msg = (_("Interface %(ifname)s is associated to VXLAN "
                         "data network %(name)s which requires an "
                         "IPv4 address") %
                       {'ifname': interface.ifname,
                        'name': ifdn.datanetwork_name})
                raise wsme.exc.ClientSideError(msg)
            if ((address.version == constants.IPV6_FAMILY) and
                    (interface.ipv6_mode == constants.IPV6_DISABLED or not
                     interface.ipv6_mode)):
                msg = (_("Interface %(ifname)s is associated to VXLAN "
                         "data network %(name)s which requires an "
                         "IPv6 address") %
                       {'ifname': interface.ifname,
                        'name': ifdn.datanetwork_name})
                raise wsme.exc.ClientSideError(msg)

            # Check for at least 1 address if no ranges exist yet
            if ((interface.ipv4_mode == constants.IPV4_DISABLED) and
                    (interface.ipv6_mode == constants.IPV6_DISABLED) or
                     (not interface.ipv4_mode and not interface.ipv6_mode)):
                msg = (_("Interface %(ifname)s is associated to VXLAN "
                         "data network %(name)s which requires an IP "
                         "address") %
                       {'ifname': interface.ifname,
                        'name': ifdn.datanetwork_name})
                raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _semantic_check_non_accelerated_interface_support(interface):
        """
        Perform semantics checks against interfaces to ensure they are
        supported in vswitch as native DPDK interfaces.
        """
        ports = pecan.request.dbapi.ethernet_port_get_by_interface(interface.uuid)
        for p in ports:
            if not p.dpdksupport:
                msg = _("%s is non-accelerated interface which "
                        "is not supported by current vswitch" % p.name)
                raise wsme.exc.ClientSideError(msg)

    def _semantic_check_data_interfaces(
            self, ihost, force_unlock=False):
        """
        Perform semantic checks against data interfaces to ensure validity of
        the node configuration prior to unlocking it.
        """
        ihost_iinterfaces = (
            pecan.request.dbapi.iinterface_get_by_ihost(ihost['uuid']))
        vswitch_type = utils.get_vswitch_type()
        for iif in ihost_iinterfaces:
            if ((vswitch_type == constants.VSWITCH_TYPE_OVS_DPDK) and
                    (iif.ifclass == constants.INTERFACE_CLASS_DATA)):
                self._semantic_check_non_accelerated_interface_support(iif)
            self._semantic_check_interface_datanets(iif)
            self._semantic_check_interface_addresses(ihost, iif)
            if not iif.ifclass:
                continue
            self._semantic_check_sriov_interface(ihost, iif, force_unlock)
            self._semantic_check_pcipt_interface(ihost, iif, force_unlock)

    @staticmethod
    def _auto_adjust_memory_for_node(ihost, node):
        """
        Detect whether required reserved memory has changed (eg., due to patch
        that changes common/constants.py).  If reserved memory is larger than
        the current setting, push that change to the database.  Automatically
        adjust pending 2M and 1G memory based on the delta of required reserve
        and previous setting.
        """

        # Determine required platform reserved memory for this numa node
        low_core = cutils.is_low_core_system(ihost, pecan.request.dbapi)
        reserved = cutils.get_required_platform_reserved_memory(
                pecan.request.dbapi, ihost, node['numa_node'], low_core)

        # Determine configured memory for this numa node
        mems = pecan.request.dbapi.imemory_get_by_inode(node['id'])

        # Make adjustment to 2M and 1G hugepages to accomodate an
        # increase in platform reserved memory.
        # Also, consider the available memory on the calculation
        # hupeages shall not be decreased if there is memory available
        for m in mems:
            # ignore updates when no change required
            if m.platform_reserved_mib is None or \
                            m.platform_reserved_mib == reserved:
                continue
            if m.platform_reserved_mib > reserved:
                LOG.info("%s auto_adjust_memory numa_node=%d, "
                         "keep platform_reserved=%d > required=%d"
                         % (ihost['hostname'], node['numa_node'],
                            m.platform_reserved_mib, reserved))
                continue

            # start with current measured hugepage
            n_total_hp_size = 0
            if m.vswitch_hugepages_reqd is not None:
                n_total_hp_size += m.vswitch_hugepages_reqd \
                    * m.vswitch_hugepages_size_mib
            else:
                n_total_hp_size += m.vswitch_hugepages_nr \
                    * m.vswitch_hugepages_size_mib
            if m.vm_hugepages_nr_2M is not None:
                n_2M = m.vm_hugepages_nr_2M
                n_total_hp_size += n_2M * constants.MIB_2M
            else:
                n_2M = None
            if m.vm_hugepages_nr_1G is not None:
                n_1G = m.vm_hugepages_nr_1G
                n_total_hp_size += n_1G * constants.MIB_1G
            else:
                n_1G = None

            # adjust current hugepage measurements based on the available
            # memory
            hp_mem_avail_mib = m.node_memtotal_mib - reserved \
                - int(n_total_hp_size)
            values = {}
            values.update({'platform_reserved_mib': reserved})

            # Only adjust the number of hugepages if the memory available is
            # less than 50% of the total memory
            if (hp_mem_avail_mib < int(0.5 * m.node_memtotal_mib)):
                d_MiB = reserved - m.platform_reserved_mib
                d_2M = int(d_MiB // constants.MIB_2M)
                d_1G = int((d_MiB + 512) // constants.MIB_1G)
                if n_2M is not None and n_2M - d_2M > 0:
                    d_1G = 0
                    n_2M -= d_2M
                else:
                    d_2M = 0
                    if n_1G is not None and n_1G - d_1G > 0:
                        n_1G -= d_1G
                    else:
                        d_1G = 0

                # override with pending values
                if m.vm_hugepages_nr_2M_pending is not None:
                    n_2M = m.vm_hugepages_nr_2M_pending
                if m.vm_hugepages_nr_1G_pending is not None:
                    n_1G = m.vm_hugepages_nr_1G_pending

                if n_2M is not None:
                    values.update({'vm_hugepages_nr_2M_pending': n_2M})
                if n_1G is not None:
                    values.update({'vm_hugepages_nr_1G_pending': n_1G})
                LOG.info("%s auto_adjust_memory numa_node=%d, "
                        "+2M=%d, +1G=%d, values=%s"
                        % (ihost['hostname'], node['numa_node'],
                            -d_2M, -d_1G, values))
            else:
                LOG.info("%s auto_adjust_memory numa_node=%d, "
                        "number of app hugepages preserved: "
                        "2M=%d, 1G=%d, values=%s, "
                        "available memory (MB): %d"
                        % (ihost['hostname'], node['numa_node'],
                            n_2M, n_1G, values, hp_mem_avail_mib))
            pecan.request.dbapi.imemory_update(m.uuid, values)

        return None

    @staticmethod
    def _check_vswitch_memory(inodes):
        """
        Perform vswitch memory semantic checks on inodes.
        """
        vswitch_hp_size = None
        for node in inodes:
            mems = pecan.request.dbapi.imemory_get_by_inode(node['id'])
            for m in mems:
                if not vswitch_hp_size:
                    vswitch_hp_size = m.vswitch_hugepages_size_mib
                else:
                    if m.vswitch_hugepages_size_mib != vswitch_hp_size:
                        raise wsme.exc.ClientSideError(_(
                            "Mismatched vSwitch socket memory hugepage size."))
                if (m.vswitch_hugepages_nr == 0 and
                            m.vswitch_hugepages_reqd is None):
                    raise wsme.exc.ClientSideError(_(
                        "vSwitch socket memory must be allocated for numa node"
                        " (%s).") % node['numa_node'])

    @staticmethod
    def _semantic_check_memory_for_node(ihost, node):
        """
        Perform memory semantic checks on a specific numa node.
        """

        # Determine the allocated memory for this numa node
        total_allocated_platform_reserved_mib = 0
        mems = pecan.request.dbapi.imemory_get_by_inode(node['id'])

        pending_2M_memory = False
        pending_1G_memory = False

        for m in mems:
            memtotal = m.node_memtotal_mib
            allocated = m.platform_reserved_mib
            if m.hugepages_configured is True:
                if m.vswitch_hugepages_reqd is not None:
                    allocated += m.vswitch_hugepages_reqd * m.vswitch_hugepages_size_mib
                else:
                    allocated += m.vswitch_hugepages_nr * m.vswitch_hugepages_size_mib
            if m.vm_pending_as_percentage is True:
                if m.vm_hugepages_nr_2M_pending is not None:
                    allocated += (memtotal - allocated) \
                        * m.vm_hugepages_nr_2M_pending // 100
                    pending_2M_memory = True
                elif m.vm_hugepages_2M_percentage:
                    allocated += (memtotal - allocated) \
                        * m.vm_hugepages_2M_percentage // 100
                    pending_2M_memory = True

                if m.vm_hugepages_nr_1G_pending is not None:
                    allocated += (memtotal - allocated) \
                        * m.vm_hugepages_nr_1G_pending // 100
                    pending_1G_memory = True
                elif m.vm_hugepages_1G_percentage:
                    allocated += (memtotal - allocated) \
                        * m.vm_hugepages_1G_percentage // 100
                    pending_1G_memory = True
            else:
                if m.vm_hugepages_nr_2M_pending is not None:
                    allocated += constants.MIB_2M * m.vm_hugepages_nr_2M_pending
                    pending_2M_memory = True
                elif m.vm_hugepages_nr_2M:
                    allocated += constants.MIB_2M * m.vm_hugepages_nr_2M
                if m.vm_hugepages_nr_1G_pending is not None:
                    allocated += constants.MIB_1G * m.vm_hugepages_nr_1G_pending
                    pending_1G_memory = True
                elif m.vm_hugepages_nr_1G:
                    allocated += constants.MIB_1G * m.vm_hugepages_nr_1G

            LOG.info("Memory: Total=%s MiB, Allocated=%s MiB, "
                    "2M: %s pages %s pages pending, "
                    "1G: %s pages %s pages pending"
                    % (memtotal, allocated,
                        m.vm_hugepages_possible_2M, m.vm_hugepages_nr_2M_pending,
                        m.vm_hugepages_possible_1G, m.vm_hugepages_nr_1G_pending))
            if memtotal < allocated:
                msg = (_("Rejected: Total allocated memory exceeds the total memory of "
                         "%(host)s numa node %(node)s "
                         ) %
                       {'host': ihost['hostname'],
                        'node': node['numa_node']})
                raise wsme.exc.ClientSideError(msg)
            total_allocated_platform_reserved_mib += m.platform_reserved_mib
        return (total_allocated_platform_reserved_mib,
                pending_2M_memory, pending_1G_memory)

    @staticmethod
    def _check_memory_for_single_size(ihost):
        """
        Perform memory semantic checks on a worker node.
        It restricts the huge page allocation to either a 2M or 1G
        pool.
        """

        allocate_2m = False
        allocate_1g = False
        vs_mem = False
        if utils.get_vswitch_type() != constants.VSWITCH_TYPE_NONE:
            vs_mem = True
        ihost_inodes = pecan.request.dbapi.inode_get_by_ihost(ihost['uuid'])
        for node in ihost_inodes:
            mems = pecan.request.dbapi.imemory_get_by_inode(node['id'])
            for m in mems:
                request_2m = (True if m.vm_hugepages_nr_2M_pending and
                              m.vm_hugepages_nr_2M_pending != 0
                              else False)
                request_1g = (True if m.vm_hugepages_nr_1G_pending and
                              m.vm_hugepages_nr_1G_pending != 0
                              else False)
                # if vswitch is used, we go with the vswitch huge page size
                if vs_mem:
                    if (m.vswitch_hugepages_size_mib ==
                            constants.VSWITCH_MEMORY_MB):
                        allocate_1g = True
                    else:
                        allocate_2m = True
                if request_2m and allocate_1g:
                    msg = (_(
                        "Rejected: Only 1G huge page allocation is supported"))
                    raise wsme.exc.ClientSideError(msg)
                elif request_1g and allocate_2m:
                    msg = (_(
                        "Rejected: Only 2M huge page allocation is supported"))
                    raise wsme.exc.ClientSideError(msg)
                elif request_2m and request_1g:
                    msg = (_(
                        "Rejected: Only one huge page size can be modified"))
                    raise wsme.exc.ClientSideError(msg)
                elif request_2m and not allocate_2m:
                    allocate_2m = True
                elif request_1g and not allocate_1g:
                    allocate_1g = True

    @staticmethod
    def _align_pending_memory(ihost, align_2M_memory, align_1G_memory):
        """
        Update pending fields as required without clearing other settings.
        """

        ihost_inodes = pecan.request.dbapi.inode_get_by_ihost(ihost['uuid'])

        for node in ihost_inodes:
            mems = pecan.request.dbapi.imemory_get_by_inode(node['id'])
            for m in mems:
                values = {}
                if (m.vm_hugepages_nr_2M_pending is None and
                   m.vm_hugepages_nr_2M and align_2M_memory):
                    values.update({'vm_hugepages_nr_2M_pending':
                                  m.vm_hugepages_nr_2M})
                if (m.vm_hugepages_nr_1G_pending is None and
                   m.vm_hugepages_nr_1G and align_1G_memory):
                    values.update({'vm_hugepages_nr_1G_pending':
                                  m.vm_hugepages_nr_1G})
                if values:
                    LOG.info("%s align_pending_memory uuid=%s" %
                             (ihost['hostname'], values))
                    pecan.request.dbapi.imemory_update(m.uuid, values)

    @staticmethod
    def _update_huge_pages(ihost):
        """
        Update the host huge pages.
        """
        ihost_inodes = pecan.request.dbapi.inode_get_by_ihost(ihost['uuid'])

        for node in ihost_inodes:
            mems = pecan.request.dbapi.imemory_get_by_inode(node['id'])
            for m in mems:
                if m.hugepages_configured is True:
                    value = {}
                    vs_hugepages_nr = m.vswitch_hugepages_nr

                    if m.vm_hugepages_nr_2M_pending is not None:
                        vm_hugepages_nr_2M = m.vm_hugepages_nr_2M_pending
                    elif m.vm_hugepages_2M_percentage is not None and m.vm_pending_as_percentage is True:
                        vm_hugepages_nr_2M = m.vm_hugepages_2M_percentage
                    else:
                        vm_hugepages_nr_2M = m.vm_hugepages_nr_2M

                    if m.vm_hugepages_nr_1G_pending is not None:
                        vm_hugepages_nr_1G = m.vm_hugepages_nr_1G_pending
                    elif m.vm_hugepages_1G_percentage is not None and m.vm_pending_as_percentage is True:
                        vm_hugepages_nr_1G = m.vm_hugepages_1G_percentage
                    else:
                        vm_hugepages_nr_1G = m.vm_hugepages_nr_1G

                    hp_possible_mib = (m.node_memtotal_mib -
                                       m.platform_reserved_mib)
                    vs_mem_mib = (vs_hugepages_nr *
                                  m.vswitch_hugepages_size_mib)
                    vm_mem_mib = hp_possible_mib - vs_mem_mib

                    LOG.info("host(%s) node(%d): vm_mem_mib=%d,"
                            % (ihost['hostname'], node['id'], vm_mem_mib))

                    # vm_mem_mib should not be negative
                    if vm_mem_mib < constants.MIB_2M:
                        vm_mem_mib = 0

                    # Current value might not be suitable after upgrading or
                    # patching
                    if m.vm_pending_as_percentage is False and vm_hugepages_nr_2M > int((vm_mem_mib * 0.9) //
                            constants.MIB_2M):
                        vm_hugepages_nr_2M = int((vm_mem_mib * 0.9) //
                                                 constants.MIB_2M)
                        value.update({'vm_hugepages_nr_2M': vm_hugepages_nr_2M})

                    vm_hugepages_4K = vm_mem_mib
                    vm_hugepages_4K -= \
                        (constants.MIB_2M * vm_hugepages_nr_2M)
                    vm_hugepages_4K -=  \
                        (constants.MIB_1G * vm_hugepages_nr_1G)
                    vm_hugepages_4K = \
                        (constants.NUM_4K_PER_MiB * vm_hugepages_4K)

                    # Clip 4K pages
                    min_4K = 32 * constants.Ki // 4
                    if vm_hugepages_4K < min_4K:
                        vm_hugepages_4K = 0

                    value.update({'vm_hugepages_nr_4K': vm_hugepages_4K})
                    LOG.info("Updating mem values of host(%s) node(%d): %s" %
                             (ihost['hostname'], node['id'], str(value)))
                    pecan.request.dbapi.imemory_update(m.uuid, value)

    @staticmethod
    def _semantic_mtc_check_action(hostupdate, action):
        """
        Perform semantic checks with patch action vs current state

        returns:  notify_mtc_check_action
        """
        notify_mtc_check_action = True
        ihost = hostupdate.ihost_orig
        patched_ihost = hostupdate.ihost_patch

        if action in [constants.VIM_SERVICES_DISABLED,
                      constants.VIM_SERVICES_DISABLE_FAILED,
                      constants.VIM_SERVICES_DISABLE_EXTEND,
                      constants.VIM_SERVICES_ENABLED,
                      constants.VIM_SERVICES_DELETE_FAILED]:
            # These are not mtce actions
            return notify_mtc_check_action

        LOG.info("%s _semantic_mtc_check_action %s" %
                 (hostupdate.displayid, action))

        # Semantic Check: Auto-Provision: Reset, Reboot or Power-On case
        if ((cutils.host_has_function(ihost, constants.WORKER)) and
                (ihost['administrative'] == constants.ADMIN_LOCKED) and
                ((patched_ihost['action'] == constants.RESET_ACTION) or
                 (patched_ihost['action'] == constants.REBOOT_ACTION) or
                 (patched_ihost['action'] == constants.POWERON_ACTION) or
                 (patched_ihost['action'] == constants.POWEROFF_ACTION))):
            notify_mtc_check_action = True

        return notify_mtc_check_action

    def _bm_username_semantic_check(self, phost, patch_obj):
        """ Parameters:
            phost:         mutable dictionary patched host
            patch_obj:     all changed paths
            return patch_bm_username or None
        """
        hostname = phost.get('hostname', "unknown")
        patch_bm_username = None
        for p in patch_obj:
            if p['path'] == '/bm_username':
                patch_bm_username = p['value']
                break
        """
        Snippet from ipmi v2 spec
        -------------------------
        User Name String in ASCII. 16 bytes max. Strings with fewer than
        16 characters are terminated with a null (00h) character and 00h padded
        to 16 bytes.
        """
        # bm_username - 16 characters no whitespace
        if patch_bm_username:
            if len(patch_bm_username) > 16:
                raise wsme.exc.ClientSideError(
                    _("%s: Rejected: Board management controller username "
                    "is not valid. Cannot be longer than 16 characters." %
                    (hostname)))

            if re.search(r"\s", patch_bm_username):
                raise wsme.exc.ClientSideError(
                    _("%s: Rejected: Board management controller username "
                    "is not valid. Whitespace characters are not permitted." %
                    (hostname)))

        return patch_bm_username

    def _bm_password_semantic_check(self, phost, patch_obj,
                                   patch_bm_username=None):
        """ Parameters:
            phost:         mutable dictionary patched host
            patch_obj:     all changed paths
            patch_bm_username: bmc username
            returns patch_bm_password or None
        """
        hostname = phost.get('hostname', "unknown")
        patch_bm_password = None
        for p in patch_obj:
            if p['path'] == '/bm_password':
                patch_bm_password = p['value']
                break
        """
        Snippet from ipmi v2 spec
        -------------------------
        The password is stored as a 16-byte or 20-byte (for IPMI v2.0/RCMP+)
        'octet string'. All the values (0-255) are allowed for every byte.
        """
        # bm_password - 20 characters no whitespace
        if patch_bm_password:
            if not patch_bm_username:
                raise wsme.exc.ClientSideError(
                    _("%s Rejected: Board management controller password "
                      "change attempt without corresponding username." %
                      (hostname)))

            if len(patch_bm_password) > 20:
                LOG.warn(
                    _("%s: Board management controller password is not valid. "
                    "Cannot be longer than 20 characters." %
                    (hostname)))

            if re.search(r"\s", patch_bm_password):
                raise wsme.exc.ClientSideError(
                    _("%s: Rejected: Board management controller password "
                    "is not valid. Whitespace characters are not permitted." %
                    (hostname)))

        return patch_bm_password

    def _bm_ip_version_semantic_check(self, bm_ip):
        networks = pecan.request.dbapi.networks_get_by_type(constants.NETWORK_TYPE_OAM)
        if not networks:
            raise wsme.exc.ClientSideError(_("Rejected: OAM network does not exist."))
        bm_ip_version = "IPv%d" % netaddr.IPAddress(bm_ip).version
        if bm_ip_version != networks[0].primary_pool_family:
            raise wsme.exc.ClientSideError(_("Rejected: Board management controller IP address "
                                             "must be the same version as OAM primary address."))

    def _bm_semantic_check_and_update(self, ohost, phost, delta, patch_obj,
                                      current_ihosts=None, hostupdate=None):
        """ Parameters:
            ohost:         object original host
            phost:         mutable dictionary patch host
            delta:         default keys changed
            patch_obj:     all changed paths
            returns bm_type_changed_to_none
        """

        # NOTE: since the bm_mac is still in the DB; this is just to disallow user to modify it.
        if 'bm_mac' in delta:
            raise wsme.exc.ClientSideError(
                        _("Patching Error: can't replace non-existent object 'bm_mac' "))

        bm_type_changed_to_none = False

        bm_set = {'bm_type',
                  'bm_ip',
                  'bm_username',
                  'bm_password'}

        # Semantic Check: Validate bm_username
        patch_bm_username = self._bm_username_semantic_check(phost, patch_obj)

        # Semantic Check: Validate bm_password
        patch_bm_password = self._bm_password_semantic_check(phost, patch_obj,
                                                            patch_bm_username)

        password_exists = (patch_bm_password is not None)
        if not (delta.intersection(bm_set) or password_exists):
            return bm_type_changed_to_none

        if hostupdate:
            hostupdate.notify_mtce = True

        bm_type_patch = phost.get('bm_type')
        # Semantic Check: Validate BM type against supported list
        if bm_type_patch not in constants.HOST_BM_VALID_TYPE_LIST:
            raise wsme.exc.ClientSideError(
                _("%s: Rejected: '%s' is not a supported board management "
                  "type. Must be one of %s" %
                  (phost['hostname'],
                   phost['bm_type'],
                   constants.HOST_BM_VALID_TYPE_LIST)))

        bm_type_orig = ohost.get('bm_type')
        if bm_type_orig != bm_type_patch:
            if bm_type_patch == constants.HOST_BM_TYPE_DEPROVISIONED:
                LOG.info("BM is to be deprovisioned")
                bm_type_changed_to_none = True
            else:
                LOG.info("BM type %s is changed to %s" %
                         (bm_type_orig, bm_type_patch))

        if 'bm_ip' in delta:
            obm_ip = ohost['bm_ip'] or ""
            nbm_ip = phost['bm_ip'] or ""
            LOG.info("bm_ip in delta=%s obm_ip=%s nbm_ip=%s" %
                     (delta, obm_ip, nbm_ip))
            if obm_ip != nbm_ip:
                if (pecan.request.user_agent.startswith('mtce') and
                  not bm_type_changed_to_none):
                    raise wsme.exc.ClientSideError(
                        _("%s: Rejected: %s Board Management "
                          "controller IP Address is not user-modifiable." %
                          (constants.REGION_PRIMARY, phost['hostname'])))

        if phost['bm_ip'] or phost['bm_type'] or phost['bm_username']:
            if bm_type_patch == constants.HOST_BM_TYPE_DEPROVISIONED:
                if not bm_type_changed_to_none:
                    raise wsme.exc.ClientSideError(
                        _("%s: Rejected: Board Management controller Type "
                          "is not provisioned.  Provisionable values: '%s'." %
                          (phost['hostname'],
                           constants.HOST_BM_VALID_PROVISIONED_TYPE_LIST)))
            elif not phost['bm_username']:
                raise wsme.exc.ClientSideError(
                    _("%s: Rejected: Board Management controller username "
                      "is not configured." % phost['hostname']))

        if (phost['bm_type'] and phost['bm_ip'] and
                (ohost['bm_ip'] != phost['bm_ip'])):
            if not cutils.is_valid_ip(phost['bm_ip']):
                raise wsme.exc.ClientSideError(
                    _("%s: Rejected: Board Management controller IP Address "
                      "is not valid." % phost['hostname']))
            self._bm_ip_version_semantic_check(phost['bm_ip'])

        if current_ihosts and ('bm_ip' in phost):
            bm_ips = [h['bm_ip'] for h in current_ihosts]

            if phost['bm_ip'] and (phost['bm_ip'] in bm_ips):
                raise wsme.exc.ClientSideError(
                    _("Host-add Rejected: bm_ip %s already exists") % phost['bm_ip'])

        # Update barbican with updated board management credentials (if supplied)
        if (ohost['bm_username'] and phost['bm_username'] and
                (ohost['bm_username'] != phost['bm_username'])):
            if not password_exists:
                raise wsme.exc.ClientSideError(
                    _("%s Rejected: username change attempt from %s to %s "
                      "without corresponding password." %
                      (phost['hostname'],
                       ohost['bm_username'],
                       phost['bm_username'])))

        if password_exists and patch_bm_password:
            if not pecan.request.rpcapi.create_barbican_secret(pecan.request.context,
                                                               phost['uuid'],
                                                               patch_bm_password):
                raise wsme.exc.ClientSideError(
                    _("%s Rejected: failed to create barbican secret " % phost['hostname']))

        LOG.info("%s bm semantic checks for user_agent %s passed" %
                 (phost['hostname'], pecan.request.user_agent))

        return bm_type_changed_to_none

    @staticmethod
    def _semantic_check_vsc_controllers(ihost, vsc_controllers):
        """
        Perform semantic checking for vsc_controllers attribute.
        :param ihost: unpatched ihost dictionary
        :param vsc_controllers: attribute supplied in patch
        """

        # Don't expose the vsc_controllers field if we are not configured with
        # the nuage_vrs vswitch or we are not a worker node.
        vswitch_type = utils.get_vswitch_type()
        if (vswitch_type != constants.VSWITCH_TYPE_NUAGE_VRS or
                ihost['personality'] != constants.WORKER):
            raise wsme.exc.ClientSideError(
                _("The vsc_controllers property is not applicable to this "
                  "host."))

        # When semantic checking a new host the administrative key will not
        # be in the dictionary.
        if 'administrative' in ihost and ihost['administrative'] != constants.ADMIN_LOCKED:
            raise wsme.exc.ClientSideError(
                _("Host must be locked before updating vsc_controllers."))

        if vsc_controllers:
            vsc_list = vsc_controllers.split(',')
            if len(vsc_list) != 2:
                raise wsme.exc.ClientSideError(
                    _("Rejected: two VSC controllers (active and standby) "
                      "must be specified (comma separated)."))
            for vsc_ip_str in vsc_list:
                try:
                    vsc_ip = netaddr.IPAddress(vsc_ip_str)
                    if vsc_ip.version != 4:
                        raise wsme.exc.ClientSideError(
                            _("Invalid vsc_controller IP version - only IPv4 "
                              "supported"))
                except netaddr.AddrFormatError:
                    raise wsme.exc.ClientSideError(
                        _("Rejected: invalid VSC controller IP address: %s" %
                          vsc_ip_str))

    @staticmethod
    def _semantic_check_cinder_volumes(ihost):
        """
        Perform semantic checking for cinder volumes storage
        :param ihost_uuid: uuid of host with controller functionality
        """
        # deny unlock if cinder-volumes is not configured on a controller host
        if StorageBackendConfig.has_backend(pecan.request.dbapi,
                                            constants.CINDER_BACKEND_LVM):
            msg = _("Cinder's LVM backend is enabled. "
                    "A configured cinder-volumes PV is required "
                    "on host %s prior to unlock.") % ihost['hostname']

            host_pvs = pecan.request.dbapi.ipv_get_by_ihost(ihost['uuid'])
            for pv in host_pvs:
                if pv.lvm_vg_name == constants.LVG_CINDER_VOLUMES:
                    if pv.pv_state not in [constants.PV_ADD, constants.PROVISIONED]:
                        raise wsme.exc.ClientSideError(msg)
                    break
            else:
                raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _semantic_check_filesystem_sizes(ihost):
        """
        Perform checks for filesystem consistency across controllers
        :param ihost: host information of host with controller functionality
        """
        # Unlocking the active controller happens only after running
        # config_controller or on a one-node system, so this check isn't
        # needed in such scenarios
        if (utils.is_host_active_controller(ihost) or
                utils.is_host_simplex_controller(ihost)):
            return

        # The check should only happen the first time the standby controller
        # is unlocked, so we check if the node has already been provisioned
        # or is in a provisioning state (meaning the unlock is in progress)
        # After the second controller is provisioned, the filesystem resize
        # consistency checks prevent any inconsistencies between nodes
        if (ihost['invprovision'] and
                ihost['invprovision'] != constants.UNPROVISIONED):
            LOG.info("Controller host %s provisioning or already provisioned. "
                     "Skipping filesystem checks." % ihost['hostname'])
            return

        active_controller = utils.HostHelper.get_active_controller()
        ihost_ilvgs = pecan.request.dbapi.ilvg_get_by_ihost(active_controller.uuid)

        for lvg in ihost_ilvgs:
            if lvg.lvm_vg_name == constants.LVG_CGTS_VG:
                if (not lvg.lvm_vg_size or not lvg.lvm_vg_total_pe):
                    # Should not happen for active controller, but we should check
                    # this anyway.
                    raise wsme.exc.ClientSideError(
                        _("Active controller %s volume group not yet inventoried.") %
                        constants.LVG_CGTS_VG)
                lvm_vg_used_pe = int(lvg.lvm_vg_total_pe) - int(lvg.lvm_vg_free_pe)
                active_controller_used = (
                    int(lvg.lvm_vg_size) * lvm_vg_used_pe // int(lvg.lvm_vg_total_pe))

        # For the standby controller the PVs are not yet allocated to the volume
        # group, so we can't get the size directly from volume-group info
        # For the standby controller the allocated space is the sum between:
        # - cgts-vg space allocated by kickstarts
        # - partition PVs assigned to cgts-vg
        # - disk PVs assigned to cgts-vg
        standby_controller_allocated_space = 0
        standby_pvs = pecan.request.dbapi.ipv_get_by_ihost(ihost['uuid'])
        for pv in standby_pvs:
            if pv.lvm_vg_name == constants.LVG_CGTS_VG:
                if pv.lvm_pv_size:
                    standby_controller_allocated_space += int(
                        pv.lvm_pv_size)
                elif pv.pv_type == constants.PV_TYPE_PARTITION:
                    part_info = pecan.request.dbapi.partition_get_by_ipv(pv['uuid'])
                    standby_controller_allocated_space += int(
                        part_info[0].size_mib) * (1024 ** 2)
                elif pv.pv_type == constants.PV_TYPE_DISK:
                    disk_info = pecan.request.dbapi.idisk_get_by_ipv(pv['uuid'])
                    standby_controller_allocated_space += int(
                        disk_info[0].size_mib) * (1024 ** 2)

        LOG.info("Active controller filesystem space used: %s" %
                 str(active_controller_used))
        LOG.info("Standby controller filesystem allocated space: %s" %
                 str(standby_controller_allocated_space))

        if (active_controller_used > standby_controller_allocated_space):
            # Round up the needed space from float to integer
            needed_space = math.ceil(float(  # pylint: disable=W1619
                active_controller_used -
                standby_controller_allocated_space) / (1024 ** 3))
            msg = _("Standby controller does not have enough space allocated to "
                    "%(vg_name)s volume-group in order to create all filesystems. "
                    "Please assign an extra %(needed)d GB to the volume group.") % {
                    'vg_name': constants.LVG_CGTS_VG, 'needed': needed_space}
            raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _semantic_check_storage_backend(ihost):
        """
        Perform semantic checking for storage backends
        :param ihost_uuid: uuid of host with controller functionality
        """
        # deny operation if any storage backend is either configuring or in error
        backends = pecan.request.dbapi.storage_backend_get_list()
        for bk in backends:
            # TODO(rchurch): revisit. Do nothing for now
            if bk['backend'] == constants.SB_TYPE_CEPH_ROOK:
                continue

            if bk['state'] != constants.SB_STATE_CONFIGURED:
                # TODO(oponcea): Remove once sm supports in-service configuration
                if (bk['backend'] != constants.SB_TYPE_CEPH or
                        bk['task'] != constants.SB_TASK_PROVISION_STORAGE or
                        ihost['personality'] != constants.CONTROLLER):
                    msg = _("%(backend)s is %(notok)s. All storage backends must "
                            "be %(ok)s before operation "
                            "is allowed.") % {'backend': bk['backend'].title(),
                                              'notok': bk['state'],
                                              'ok': constants.SB_STATE_CONFIGURED}
                    raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def _semantic_check_nova_local_storage(ihost_uuid, personality, required=False):
        """
        Perform semantic checking for nova local storage
        :param ihost_uuid: uuid of host with worker functionality
        :param personality: personality of host with worker functionality
        :param required: set to True if nova storage is required and not defined
        """

        required_msg = ("A host with worker functionality requires a cgts-vg/instances-lv "
                        "or a nova-local volume group prior to being enabled. ")

        # query volume groups
        nova_local_storage_lvg = None
        ihost_ilvgs = pecan.request.dbapi.ilvg_get_by_ihost(ihost_uuid)
        for lvg in ihost_ilvgs:
            if lvg.lvm_vg_name == constants.LVG_NOVA_LOCAL:
                nova_local_storage_lvg = lvg
                break

        # Prevent unlock if nova-local volume group has: invalid state
        # (e.g., removing), no physical volumes allocated.
        if nova_local_storage_lvg:
            if nova_local_storage_lvg.vg_state != constants.LVG_DEL:
                # Make sure that we have physical volumes allocated to the
                # volume group
                ihost_ipvs = pecan.request.dbapi.ipv_get_by_ihost(ihost_uuid)
                lvg_has_pvs = False
                for pv in ihost_ipvs:
                    if ((pv.lvm_vg_name == nova_local_storage_lvg.lvm_vg_name) and
                            (pv.pv_state != constants.PV_DEL)):

                        lvg_has_pvs = True

                if not lvg_has_pvs:
                    raise wsme.exc.ClientSideError(
                        _("%sThe nova-local volume group does not "
                          "contain any physical volumes in the adding or provisioned "
                          "state.") % (required_msg if required else ""))

        else:
            if required:
                # This method is only called with hosts that have a worker
                # subfunction and is locked or if subfunction_config action is
                # being called. Without a nova-local volume group, prevent
                # unlocking.
                if personality == constants.CONTROLLER:
                    host_description = 'controller with worker functionality'
                else:
                    host_description = 'worker'

                msg = _('A %s requires a cgts-vg/instances-lv or a nova-local volume '
                        'group prior to being enabled. Please update the storage '
                        'settings for the host.') % host_description

                raise wsme.exc.ClientSideError('%s' % msg)

    @staticmethod
    def _semantic_check_cgts_vg(hostname, ihost_uuid):
        """
        Perform semantic checking for cgts-vg volume group
        :param ihost_uuid: ihost uuid unique id
        """
        # Prevent unlock if cgts-vg volume group has no physical volumes allocated
        ihost_ipvs = pecan.request.dbapi.ipv_get_by_ihost(ihost_uuid)
        for pv in ihost_ipvs:
            # Make sure that we have physical volumes allocated to the volume group
            if pv.lvm_vg_name == constants.LVG_CGTS_VG:
                break
        else:
            raise wsme.exc.ClientSideError(
                _("The cgts-vg volume group on %s does not "
                  "contain any physical volumes.") % hostname)

    @staticmethod
    def _semantic_check_restore_complete(ihost):
        """
        During a restore procedure, checks worker nodes can be unlocked
        only after running "config_controller --restore-complete"
        """
        if os.path.isfile(tsc.RESTORE_SYSTEM_FLAG):
            raise wsme.exc.ClientSideError(
                _("Cannot unlock host %s. Please restore any volumes "
                  "and then complete the restore procedure by running "
                  "'config_controller --restore-complete' first. "
                  "Please refer to system admin guide for more details.") %
                (ihost['hostname']))

    def _semantic_check_worker_cpu_assignments(self, host):
        """
        Perform semantic checks that cpu assignments are valid. Changes in
        vswitch_type may alter vswitch core requirements.
        """
        # If vswitch_type is none, enforce 0 vswitch cpu cores
        vswitch_type = cutils.get_vswitch_type(pecan.request.dbapi)
        host_cpus = pecan.request.dbapi.icpu_get_by_ihost(host['uuid'])
        if vswitch_type == constants.VSWITCH_TYPE_NONE:
            for cpu in host_cpus:
                if cpu.allocated_function == constants.VSWITCH_FUNCTION:
                    raise wsme.exc.ClientSideError(
                        _('vSwitch cpus can only be used with a vswitch_type '
                          'specified.'))
        elif vswitch_type == constants.VSWITCH_TYPE_OVS_DPDK:
            has_vswitch_cpus = False
            for cpu in host_cpus:
                if cpu.allocated_function == constants.VSWITCH_FUNCTION:
                    has_vswitch_cpus = True
                    break
            if not has_vswitch_cpus:
                raise wsme.exc.ClientSideError(
                    _('vSwitch cpus must be enabled on this host for ovs-dpdk '
                      'to function.'))

    @staticmethod
    def _handle_ttys_dcd_change(ihost, ttys_dcd):
        """
        Handle serial line carrier detection enable or disable request.
        :param ihost: unpatched ihost dictionary
        :param ttys_dcd: attribute supplied in patch
        """
        LOG.info("%s _handle_ttys_dcd_change from %s to %s" %
                 (ihost['hostname'], ihost['ttys_dcd'], ttys_dcd))

        # check if the flag is changed
        if ttys_dcd is not None:
            if ihost['ttys_dcd'] is None or ihost['ttys_dcd'] != ttys_dcd:
                if ((ihost['administrative'] == constants.ADMIN_LOCKED and
                    ihost['availability'] == constants.AVAILABILITY_ONLINE) or
                    (ihost['administrative'] == constants.ADMIN_UNLOCKED and
                     ihost['operational'] == constants.OPERATIONAL_ENABLED)):
                    LOG.info("Notify conductor ttys_dcd change: (%s) (%s)" %
                             (ihost['uuid'], ttys_dcd))
                    pecan.request.rpcapi.update_ttys_dcd(
                        pecan.request.context, ihost['uuid'])

    @staticmethod
    def _handle_apparmor_change(ihost, apparmor):
        """
        Update GRUB CMDLINE to enable or disable apparmor.
        :param ihost: unpatched ihost dictionary
        :param apparmor: attribute supplied in patch
        """
        LOG.info("%s _handle_apparmor_change from %s to %s" %
                 (ihost['hostname'], ihost['apparmor'], apparmor))

        # check if the flag is changed
        if apparmor is not None:
            if ihost['apparmor'] is None or ihost['apparmor'] != apparmor:
                if (ihost['administrative'] == constants.ADMIN_LOCKED and
                     ihost['availability'] == constants.AVAILABILITY_ONLINE):
                    LOG.info("Notify conductor apparmor change: (%s) (%s)" %
                             (ihost['uuid'], apparmor))
                    updates = \
                        {
                            'apparmor_config_status': constants.APPARMOR_CONFIG_STATUS_PENDING
                        }
                    host_obj = objects.host.get_by_uuid(pecan.request.context,
                                             ihost['uuid'])
                    host_obj.save_changes(pecan.request.context, updates)
                    pecan.request.rpcapi.update_apparmor(
                        pecan.request.context, ihost['uuid'])

    def mtc_action_apps_semantic_checks(self, action):
        """ Enhance semantic checks from this class.
        Let apps run semantic checks.

        :param action: maintenance action

        """
        try:
            pecan.request.rpcapi.mtc_action_apps_semantic_checks(
                pecan.request.context, action)
        except rpc_common.RemoteError as e:
            raise wsme.exc.ClientSideError(_(
                "{} action semantic check failed by app: {}"
                "".format(action.capitalize(), str(e.value))))

        return True

    def action_check(self, action, hostupdate):
        """Performs semantic checks related to action"""

        if not action or (action.lower() == constants.NONE_ACTION):
            rc = False
            return rc

        valid_actions = [constants.UNLOCK_ACTION,
                         constants.FORCE_UNLOCK_ACTION,
                         constants.LOCK_ACTION,
                         constants.FORCE_LOCK_ACTION,
                         constants.FORCE_UNSAFE_LOCK_ACTION,
                         constants.SWACT_ACTION,
                         constants.FORCE_SWACT_ACTION,
                         constants.RESET_ACTION,
                         constants.REBOOT_ACTION,
                         constants.REINSTALL_ACTION,
                         constants.POWERON_ACTION,
                         constants.POWEROFF_ACTION,
                         constants.VIM_SERVICES_ENABLED,
                         constants.VIM_SERVICES_DISABLED,
                         constants.VIM_SERVICES_DISABLE_FAILED,
                         constants.VIM_SERVICES_DISABLE_EXTEND,
                         constants.VIM_SERVICES_DELETE_FAILED,
                         constants.SUBFUNCTION_CONFIG_ACTION]

        if action not in valid_actions:
            raise wsme.exc.ClientSideError(
                _("'%s' is not a supported maintenance action") % action)

        force_unlock = False
        if action == constants.FORCE_UNLOCK_ACTION:
            # set force_unlock for semantic check and update action
            # for compatability with vim and mtce
            action = constants.UNLOCK_ACTION
            force_unlock = True
        hostupdate.action = action
        rc = True

        if action == constants.UNLOCK_ACTION:
            # Set ihost_action in DB as early as possible as we need
            # it as a synchronization point for things like lvg/pv
            # deletion which is not allowed when host is unlocked
            # or in the process of unlocking.
            rc = self.update_ihost_action(action, hostupdate)
            if rc:
                pecan.request.dbapi.ihost_update(hostupdate.ihost_orig['uuid'],
                                                 hostupdate.ihost_val_prenotify)
                host_action_orig = \
                    hostupdate.ihost_orig.get('ihost_action', "")
                try:
                    self.check_unlock(hostupdate, force_unlock)
                except exception.HostLocking:
                    msg = _("Host unlock rejected due to in progress action %s"
                            % host_action_orig.strip('-'))
                    self.update_ihost_action(host_action_orig, hostupdate)
                    pecan.request.dbapi.ihost_update(
                        hostupdate.ihost_orig['uuid'],
                        hostupdate.ihost_val_prenotify)
                    # raise as a Client side exception
                    raise wsme.exc.ClientSideError(msg)
                except Exception:
                    LOG.info("host unlock check didn't pass, "
                             "so set the ihost_action (%s) back to None "
                             "and re-raise the exception" %
                             host_action_orig)
                    self.update_ihost_action(None, hostupdate)
                    pecan.request.dbapi.ihost_update(hostupdate.ihost_orig['uuid'],
                                                     hostupdate.ihost_val_prenotify)
                    raise

                if not force_unlock:
                    self.mtc_action_apps_semantic_checks(action)

        elif action == constants.LOCK_ACTION:
            if self.check_lock(hostupdate) and \
                    self.mtc_action_apps_semantic_checks(action):
                rc = self.update_ihost_action(action, hostupdate)
        elif action == constants.FORCE_LOCK_ACTION:
            if self.check_force_lock(hostupdate):
                rc = self.update_ihost_action(action, hostupdate)
        elif action == constants.FORCE_UNSAFE_LOCK_ACTION:
            if self.check_force_unsafe_lock(hostupdate):
                rc = self.update_ihost_action(action, hostupdate)
        elif action == constants.SWACT_ACTION:
            self.check_swact(hostupdate)
        elif action == constants.FORCE_SWACT_ACTION:
            self.check_force_swact(hostupdate)
        elif action == constants.REBOOT_ACTION:
            self.check_reboot(hostupdate)
        elif action == constants.RESET_ACTION:
            self.check_reset(hostupdate)
        elif action == constants.REINSTALL_ACTION:
            self.check_reinstall(hostupdate)
        elif action == constants.POWERON_ACTION:
            self.check_poweron(hostupdate)
        elif action == constants.POWEROFF_ACTION:
            self.check_poweroff(hostupdate)
        elif action == constants.VIM_SERVICES_ENABLED:
            # hostupdate.notify_availability = constants.VIM_SERVICES_ENABLED
            # self.update_ihost_action(action, hostupdate)
            self.update_vim_progress_status(action, hostupdate)
        elif action == constants.VIM_SERVICES_DISABLED:
            # self.notify_availability = constants.VIM_SERVICES_DISABLED
            self.update_vim_progress_status(action, hostupdate)
            # rc = self.update_ihost_action(action, hostupdate)
        elif action == constants.VIM_SERVICES_DISABLE_FAILED:
            self.update_vim_progress_status(action, hostupdate)
        elif action == constants.VIM_SERVICES_DISABLE_EXTEND:
            self.update_vim_progress_status(action, hostupdate)
        elif action == constants.VIM_SERVICES_DELETE_FAILED:
            self.update_vim_progress_status(action, hostupdate)
        elif action == constants.SUBFUNCTION_CONFIG_ACTION:
            self._check_subfunction_config(hostupdate)

            # openstack local storage
            labels = pecan.request.dbapi.label_get_by_host(hostupdate.ihost_orig['uuid'])
            if cutils.has_openstack_compute(labels):
                # Required: make sure present
                if not cutils.is_host_filesystem_enabled(pecan.request.dbapi,
                                                         hostupdate.ihost_orig['uuid'],
                                                         constants.FILESYSTEM_NAME_INSTANCES):
                    self._semantic_check_nova_local_storage(
                        hostupdate.ihost_orig['uuid'],
                        hostupdate.ihost_orig['personality'],
                        required=True)
            else:
                # Optional: Check if partially added
                self._semantic_check_nova_local_storage(
                    hostupdate.ihost_orig['uuid'],
                    hostupdate.ihost_orig['personality'],
                    required=False)

        else:
            raise wsme.exc.ClientSideError(_(
                "action_check unrecognized action: %s" % action))

        if action in constants.MTCE_ACTIONS:
            if self._semantic_mtc_check_action(hostupdate, action):
                hostupdate.notify_mtce = True
                task_val = hostupdate.get_task_from_action(action)
                if task_val:
                    hostupdate.ihost_val_update({'task': task_val})

        elif 'administrative' in hostupdate.delta:
            # administrative state changed, update task, ihost_action in case
            hostupdate.ihost_val_update({'task': "",
                                         'ihost_action': ""})

        LOG.info("%s action=%s ihost_val_prenotify: %s ihost_val: %s" %
                 (hostupdate.displayid,
                  hostupdate.action,
                  hostupdate.ihost_val_prenotify,
                  hostupdate.ihost_val))

        if hostupdate.ihost_val_prenotify:
            LOG.info("%s host.update.ihost_val_prenotify %s" %
                     (hostupdate.displayid, hostupdate.ihost_val_prenotify))

        if self.check_notify_vim(action):
            hostupdate.notify_vim = True

        if self.check_notify_mtce(action, hostupdate) > 0:
            hostupdate.notify_mtce = True

        LOG.info("%s action_check action=%s, notify_vim=%s "
                 "notify_mtce=%s rc=%s" %
                 (hostupdate.displayid,
                  action,
                  hostupdate.notify_vim,
                  hostupdate.notify_mtce,
                  rc))

        return rc

    @staticmethod
    def check_notify_vim(action):
        if action in constants.VIM_ACTIONS:
            return True
        else:
            return False

    @staticmethod
    def check_notify_mtce(action, hostupdate):
        """Determine whether mtce should be notified of this patch request
           returns: Integer (nonmtc_change_count)
        """

        nonmtc_change_count = 0
        if action in constants.VIM_ACTIONS:
            return nonmtc_change_count
        elif action in constants.CONFIG_ACTIONS:
            return nonmtc_change_count
        elif action in constants.VIM_SERVICES_ENABLED:
            return nonmtc_change_count

        mtc_ignore_list = ['administrative', 'availability', 'operational',
                           'task', 'config_status', 'uptime', 'capabilities',
                           'ihost_action',
                           'subfunction_oper', 'subfunction_avail',
                           'vim_progress_status'
                           'location', 'serialid', 'invprovision']

        if pecan.request.user_agent.startswith('mtce'):
            mtc_ignore_list.append('bm_ip')

        nonmtc_change_count = len(set(hostupdate.delta) - set(mtc_ignore_list))

        return nonmtc_change_count

    @staticmethod
    def stage_administrative_update(hostupdate):
        # Always configure when the host is unlocked - this will set the
        # hostname and allow the node to boot and configure itself.
        # NOTE: This is being hit the second time through this function on
        # the unlock. The first time through, the "action" is set to unlock
        # on the patched_iHost, but the "administrative" is still locked.
        # Once maintenance processes the unlock, they do another patch and
        # set the "administrative" to unlocked.
        if 'administrative' in hostupdate.delta and \
                hostupdate.ihost_patch['administrative'] == \
                constants.ADMIN_UNLOCKED:
            if hostupdate.ihost_orig['invprovision'] == \
                    constants.UNPROVISIONED or \
                    hostupdate.ihost_orig['invprovision'] is None:
                LOG.info("stage_administrative_update: provisioning")
                hostupdate.ihost_val_update({'invprovision':
                                                 constants.PROVISIONING})

        if 'operational' in hostupdate.delta and \
                hostupdate.ihost_patch['operational'] == \
                constants.OPERATIONAL_ENABLED:
            if hostupdate.ihost_orig['invprovision'] in [constants.UPGRADING,
                                                         constants.PROVISIONING,
                                                         constants.UNPROVISIONED]:
                # first time unlocked successfully
                local_hostname = cutils.get_local_controller_hostname()
                if (hostupdate.ihost_patch['hostname'] ==
                        constants.CONTROLLER_0_HOSTNAME) and \
                                local_hostname == constants.CONTROLLER_0_HOSTNAME:
                    # first time controller-0 unlock, copy sysinv.conf
                    # to drbd storage
                    pecan.request.rpcapi.store_default_config(
                        pecan.request.context)

                hostupdate.ihost_val_update(
                    {'invprovision': constants.PROVISIONED}
                )
                LOG.info("stage_administrative_update: provisioned successfully")

    @staticmethod
    def _check_provisioned_storage_hosts():
        # Get provisioned storage hosts
        ihosts = pecan.request.dbapi.ihost_get_by_personality(
            constants.STORAGE
        )
        host_names = []
        for ihost in ihosts:
            if ihost.invprovision in [constants.UPGRADING, constants.PROVISIONED]:
                host_names.append(ihost.hostname)
        LOG.info("Provisioned storage node(s) %s" % host_names)

        # Get replication
        replication, __ = StorageBackendConfig.get_ceph_max_replication(pecan.request.dbapi)

        expected_hosts = \
            constants.CEPH_REPLICATION_GROUP0_HOSTS[int(replication)]
        current_exp_hosts = set(expected_hosts) & set(host_names)

        # Check expected versus provisioned
        if len(current_exp_hosts) == replication:
            return True
        else:
            return False

    def _update_add_ceph_state(self):
        api = pecan.request.dbapi

        backend = StorageBackendConfig.get_configuring_backend(api)
        if backend and backend.backend == constants.SB_TYPE_CEPH:
            ihosts = api.ihost_get_by_personality(
                constants.CONTROLLER
            )

            for ihost in ihosts:
                if ihost.config_status == constants.CONFIG_STATUS_OUT_OF_DATE:
                    return

            # check if customer needs to install storage nodes
            if backend.task == constants.SB_TASK_PROVISION_STORAGE:
                stor_model = ceph.get_ceph_storage_model()
                if (HostController._check_provisioned_storage_hosts() or
                        stor_model == constants.CEPH_CONTROLLER_MODEL):
                    # This means that either:
                    # 1. Storage nodes are already provisioned (this is not
                    #    the first time Ceph is configured) or
                    # 2. We are on a standard config and we don't need to
                    #    configure storage nodes at all.
                    api.storage_backend_update(backend.uuid, {
                        'state': constants.SB_STATE_CONFIGURED,
                        'task': None
                    })
                else:
                    # Storage nodes are not yet provisioned
                    api.storage_backend_update(backend.uuid, {
                        'state': constants.SB_STATE_CONFIGURED,
                        'task': constants.SB_TASK_PROVISION_STORAGE
                    })
                return

        backend = StorageBackendConfig.get_configured_backend(
            api,
            constants.CINDER_BACKEND_CEPH
        )
        if not backend:
            return

        if backend.task == constants.SB_TASK_PROVISION_STORAGE:
            if HostController._check_provisioned_storage_hosts():
                api.storage_backend_update(backend.uuid, {
                    'task': constants.SB_TASK_RECONFIG_WORKER
                })
                # update manifest for all online/enabled worker nodes
                # live apply new ceph manifest for all worker nodes that
                # are online/enabled. The rest will pickup when unlock
                LOG.info(
                    'Apply new Ceph manifest to provisioned worker nodes.'
                )
                pecan.request.rpcapi.update_ceph_base_config(
                    pecan.request.context, personalities=[constants.WORKER]
                )
                # mark all tasks completed after updating the manifests for
                # all worker nodes.
                api.storage_backend_update(backend.uuid, {'task': None})

        elif backend.task == constants.SB_TASK_RESIZE_CEPH_MON_LV:
            ihosts = pecan.request.dbapi.ihost_get_list()
            personalities = [constants.CONTROLLER, constants.STORAGE]
            for ihost in ihosts:
                if ihost.config_status == constants.CONFIG_STATUS_OUT_OF_DATE \
                        and ihost.personality in personalities:
                    break
            else:
                # all storage controller nodes are up to date
                api.storage_backend_update(backend.uuid, {'task': None})

        # workflow of installing object gateway is completed
        elif backend.task == constants.SB_TASK_ADD_OBJECT_GATEWAY:
            ihosts = api.ihost_get_by_personality(
                constants.CONTROLLER
            )
            for ihost in ihosts:
                if ihost.config_status == constants.CONFIG_STATUS_OUT_OF_DATE:
                    return
            api.storage_backend_update(backend.uuid, {
                'state': constants.SB_STATE_CONFIGURED,
                'task': None
            })

        elif backend.task == constants.SB_TASK_RESTORE:
            ihosts = api.ihost_get_by_personality(constants.STORAGE)

            if ihosts:
                LOG.info("This is a configuration with dedicated storage nodes. "
                         "Backend task is RESTORE.")
                # Check if ceph quorum is formed. If yes, we can clear the restore
                # task, so that when storage nodes are unlocked, ceph crushmap will
                # be loaded and osds will be created.
                active_mons, required_mons, __ = \
                    self._ceph.get_monitors_status(pecan.request.dbapi)
                if required_mons > active_mons:
                    LOG.info("Not enough monitors yet to restore ceph config.")
                else:
                    # By clearing ceph backend task to None osds will be
                    # created by applying runtime manifests when unlocking
                    # the storage nodes.
                    LOG.info("Clear ceph backend task to None as part of "
                             "storage backend restore.")
                    api.storage_backend_update(backend.uuid, {'task': None})
            elif cutils.is_aio_simplex_system(pecan.request.dbapi):
                # For AIO-SX, ceph config restore is done in puppet when ceph
                # manifest is applied on first unlock. The
                # initial_config_complete flag is set after first unlock.
                # Once one controller is up, ceph cluster should be fully
                # operational.
                LOG.info("This is an all-in-one simplex configuration. "
                         "Ceph backend task is RESTORE.")
                if cutils.is_initial_config_complete():
                    LOG.info("Clear ceph backend task to None as part of "
                             "storage backend restore.")
                    api.storage_backend_update(backend.uuid, {'task': None})
            elif cutils.is_aio_duplex_system(pecan.request.dbapi):
                # For AIO-DX, ceph config restore is done in puppet when ceph
                # manifest is applied on first unlock. The 2nd osd is created
                # in puppet when controller-1 is unlocked. Once both
                # controllers are up, Ceph cluster should be fully operational.
                LOG.info("This is an all-in-one duplex configuration. "
                         "Ceph backend task is RESTORE.")
                c_hosts = api.ihost_get_by_personality(constants.CONTROLLER)

                ctlr_enabled = 0
                for c_host in c_hosts:
                    if c_host.operational == constants.OPERATIONAL_ENABLED:
                        ctlr_enabled = ctlr_enabled + 1

                if ctlr_enabled == len(c_hosts):
                    LOG.info("Clear ceph backend task to None as part of "
                             "storage backend restore.")
                    api.storage_backend_update(backend.uuid, {'task': None})
            else:
                # This is ceph restore for standard non-storage configuration.
                # Ceph config restore is done via sysinv after both ceph
                # monitors are available.
                LOG.info("This is a standard configuration without dedicated "
                         "storage nodes. Ceph backend task is RESTORE.")
                active_mons, required_mons, __ = \
                        self._ceph.get_monitors_status(pecan.request.dbapi)
                if required_mons > active_mons:
                    LOG.info("Not enough monitors yet to restore ceph config.")
                else:
                    # By clearing ceph backend task to None osds will be
                    # created thru applying runtime manifests.
                    LOG.info("Clear ceph backend task to None as part of "
                             "storage backend restore.")
                    api.storage_backend_update(backend.uuid, {'task': None})

                    # Apply runtime manifests to create OSDs on two controller
                    # nodes.
                    c_hosts = api.ihost_get_by_personality(
                        constants.CONTROLLER)

                    runtime_manifests = True
                    for c_host in c_hosts:
                        istors = pecan.request.dbapi.istor_get_by_ihost(c_host.uuid)
                        for stor in istors:
                            pecan.request.rpcapi.update_ceph_osd_config(
                                pecan.request.context,
                                c_host,
                                stor.uuid,
                                runtime_manifests)

    @staticmethod
    def update_ihost_action(action, hostupdate):
        if action is None:
            preval = {'ihost_action': ''}
        elif action == constants.FORCE_LOCK_ACTION:
            preval = {'ihost_action': constants.FORCE_LOCK_ACTION}
        elif action == constants.FORCE_UNSAFE_LOCK_ACTION:
            preval = {'ihost_action': constants.FORCE_UNSAFE_LOCK_ACTION}
        elif action == constants.LOCK_ACTION:
            preval = {'ihost_action': constants.LOCK_ACTION}
        elif (action == constants.UNLOCK_ACTION or
           action == constants.FORCE_UNLOCK_ACTION):
            preval = {'ihost_action': constants.UNLOCK_ACTION}
        else:
            LOG.error("update_ihost_action unsupported action: %s" % action)
            return False
        hostupdate.ihost_val_prenotify.update(preval)
        hostupdate.ihost_val.update(preval)

        task_val = hostupdate.get_task_from_action(action)
        if task_val:
            hostupdate.ihost_val_update({'task': task_val})
        return True

    @staticmethod
    def update_vim_progress_status(action, hostupdate):
        LOG.info("%s Pending update_vim_progress_status %s" %
            (hostupdate.displayid, action))
        return True

    def check_provisioning(self, hostupdate, patch):
        # Once the host has been provisioned lock down additional fields

        ihost = hostupdate.ihost_patch
        delta = hostupdate.delta

        provision_state = [constants.UPGRADING, constants.PROVISIONED, constants.PROVISIONING]
        if hostupdate.ihost_orig['invprovision'] in provision_state:
            state_rel_path = ['hostname', 'personality', 'subfunctions']
            if any(p in state_rel_path for p in delta):
                    raise wsme.exc.ClientSideError(
                        _("The following fields can not be modified because "
                          "this host %s has been configured: "
                          "hostname, personality, subfunctions" %
                          hostupdate.ihost_orig['hostname']))

        # Check whether any configurable installation parameters are updated
        install_parms = ['boot_device', 'rootfs_device', 'hw_settle',
                         'install_output', 'console', 'tboot']
        if any(p in install_parms for p in delta):
            # Disallow changes if the node is not locked
            if ihost['administrative'] != constants.ADMIN_LOCKED:
                raise wsme.exc.ClientSideError(
                    _("Host must be locked before updating "
                      "installation parameters."))

            # An update to PXE boot information is required
            hostupdate.configure_required = True

        # Check whether vsc_controllers semantic checks are needed
        if 'vsc_controllers' in hostupdate.delta:
            self._semantic_check_vsc_controllers(
                hostupdate.ihost_orig,
                hostupdate.ihost_patch['vsc_controllers'])

        if 'personality' in delta:
            LOG.info("iHost['personality']=%s" %
                     hostupdate.ihost_orig['personality'])

            if hostupdate.ihost_orig['personality']:
                raise wsme.exc.ClientSideError(
                    _("Can not change personality after it has been set. "
                      "Host %s must be deleted and re-added in order to change "
                      "the personality." % hostupdate.ihost_orig['hostname']))

            if (hostupdate.ihost_patch['personality'] in
               (constants.CONTROLLER, constants.STORAGE)):
                self._controller_storage_node_setup(hostupdate.ihost_patch,
                                                    hostupdate)
                # check the subfunctions are updated properly
                LOG.info("hostupdate.ihost_patch.subfunctions %s" %
                         hostupdate.ihost_patch['subfunctions'])
            elif hostupdate.ihost_patch['personality'] == constants.WORKER:
                self._check_worker(hostupdate.ihost_patch, hostupdate)
            else:
                LOG.error("Unexpected personality: %s" %
                          hostupdate.ihost_patch['personality'])

            hostname = (hostupdate.ihost_val.get('hostname') or
                        hostupdate.ihost_patch['hostname'])
            # Check host personality provisioning order during upgrades
            self._check_upgrade_provision_order(
                hostupdate.ihost_patch['personality'],
                hostname)

            # Always configure when the personality has been set - this will
            # set up the PXE boot information so the software can be installed
            hostupdate.configure_required = True

            # Notify VIM when the personality is set.
            hostupdate.notify_vim_add_host = True

        if constants.SUBFUNCTIONS in delta:
            if hostupdate.ihost_orig[constants.SUBFUNCTIONS]:
                raise wsme.exc.ClientSideError(
                    _("Can not change subfunctions after it has been set. "
                      "Host %s must be deleted and re-added in order to change "
                      "the subfunctions." % hostupdate.ihost_orig['hostname']))

            if hostupdate.ihost_patch['personality'] == constants.WORKER:
                valid_subfunctions = (constants.WORKER,
                                      constants.LOWLATENCY)
            elif hostupdate.ihost_patch['personality'] == constants.CONTROLLER:
                valid_subfunctions = (constants.CONTROLLER,
                                      constants.WORKER,
                                      constants.LOWLATENCY)
            elif hostupdate.ihost_patch['personality'] == constants.STORAGE:
                # Comparison is expecting a list
                valid_subfunctions = (constants.STORAGE, constants.STORAGE)

            subfunctions_set = \
                set(hostupdate.ihost_patch[constants.SUBFUNCTIONS].split(','))

            if not subfunctions_set.issubset(valid_subfunctions):
                raise wsme.exc.ClientSideError(
                    ("%s subfunctions %s contains unsupported values.  Allowable: %s." %
                     (hostupdate.displayid, subfunctions_set, valid_subfunctions)))

            if hostupdate.ihost_patch['personality'] == constants.WORKER:
                if constants.WORKER not in subfunctions_set:
                    # Automatically add it
                    subfunctions_list = list(subfunctions_set)
                    subfunctions_list.insert(0, constants.WORKER)
                    subfunctions = ','.join(subfunctions_list)

                    LOG.info("%s update subfunctions=%s" %
                             (hostupdate.displayid, subfunctions))
                    hostupdate.ihost_val_prenotify.update({'subfunctions': subfunctions})
                    hostupdate.ihost_val.update({'subfunctions': subfunctions})

        # The hostname for a controller or storage node cannot be modified

        # Disallow hostname changes
        if 'hostname' in delta:
            if hostupdate.ihost_orig['hostname']:
                if (hostupdate.ihost_patch['hostname'] !=
                   hostupdate.ihost_orig['hostname']):
                    raise wsme.exc.ClientSideError(
                        _("The hostname field can not be modified because "
                          "the hostname %s has already been configured. "
                          "If changing hostname is required, please delete "
                          "this host, then readd." %
                          hostupdate.ihost_orig['hostname']))

        # TODO: evaluate for efficiency
        for attribute in patch:
            # check for duplicate attributes
            for attribute2 in patch:
                if attribute['path'] == attribute2['path']:
                    if attribute['value'] != attribute2['value']:
                        err_dp = 'Illegal duplicate parameters passed.'
                        raise wsme.exc.ClientSideError(_(err_dp))

        if 'personality' in delta or 'hostname' in delta:
            personality = hostupdate.ihost_patch.get('personality') or ""
            hostname = hostupdate.ihost_patch.get('hostname') or ""
            if personality and hostname:
                self._validate_hostname(hostname, personality)

        if 'personality' in delta:
            HostController._personality_check(
                hostupdate.ihost_patch['personality'])

    @staticmethod
    def _personality_check(personality):
        """
        Verify if a specified personality is suitable to the system configuration.
         controller is suitable in any systems
         additionally AIO-DX can have nothing but worker nodes
         defer the check if personality is not specified
        :param personality:
        :return: nothing if check pass, exception will be raised otherwise
        """

        if personality == constants.CONTROLLER:
            return

        if not personality:
            return

        if personality == constants.WORKER and \
                cutils.is_aio_duplex_system(pecan.request.dbapi):
            return

        if personality == constants.EDGEWORKER:
            return

        if (utils.SystemHelper.get_product_build() ==
                    constants.TIS_AIO_BUILD):
            msg = _("Personality [%s] for host is not compatible "
                    "with installed software. ") % personality

            raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def check_reset(hostupdate):
        """Check semantics on  host-reset."""
        if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
            raise wsme.exc.ClientSideError(
                _("Can not 'Reset' a simplex system"))

        if hostupdate.ihost_orig['administrative'] == constants.ADMIN_UNLOCKED:
            raise wsme.exc.ClientSideError(
                _("Can not 'Reset' an 'unlocked' host %s; "
                  "Please 'Lock' first" % hostupdate.displayid))

        return True

    @staticmethod
    def check_poweron(hostupdate):
        # Semantic Check: State Dependency: Power-On case
        if (hostupdate.ihost_orig['administrative'] ==
           constants.ADMIN_UNLOCKED):
            raise wsme.exc.ClientSideError(
                _("Can not 'Power-On' an already Powered-on "
                  "and 'unlocked' host %s" % hostupdate.displayid))

        if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
            raise wsme.exc.ClientSideError(
                _("Can not 'Power-On' an already Powered-on "
                  "simplex system"))

    @staticmethod
    def check_poweroff(hostupdate):
        # Semantic Check: State Dependency: Power-Off case
        if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
            raise wsme.exc.ClientSideError(
                _("Can not 'Power-Off' a simplex system via "
                  "system commands"))

        if (hostupdate.ihost_orig['administrative'] ==
           constants.ADMIN_UNLOCKED):
            raise wsme.exc.ClientSideError(
                _("Can not 'Power-Off' an 'unlocked' host %s; "
                  "Please 'Lock' first" % hostupdate.displayid))

    @staticmethod
    def check_reinstall(hostupdate):
        """ Semantic Check: State Dependency: Reinstall case"""
        if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
            raise wsme.exc.ClientSideError(_(
                "Reinstalling a simplex system is not allowed."))

        ihost = hostupdate.ihost_orig
        if ihost['administrative'] == constants.ADMIN_UNLOCKED:
            raise wsme.exc.ClientSideError(
                _("Can not 'Reinstall' an 'unlocked' host %s; "
                  "Please 'Lock' first" % hostupdate.displayid))
        elif ((ihost['administrative'] == constants.ADMIN_LOCKED) and
                (ihost['availability'] != "online") and
                (ihost['bm_type'] is None)):
            raise wsme.exc.ClientSideError(
                _("Can not 'Reinstall' %s while it is 'offline' "
                  "and a board management controller is not provisioned. "
                  "Please provision a board management controller "
                  "or wait for this host's availability state "
                  "to be 'online' and then re-issue the reinstall "
                  "command." % hostupdate.displayid))
        hostupdate.configure_required = True

    def check_unlock(self, hostupdate, force_unlock=False):
        """Check semantics on  host-unlock."""
        if (hostupdate.action != constants.UNLOCK_ACTION and
           hostupdate.action != constants.FORCE_UNLOCK_ACTION):
            LOG.error("check_unlock unexpected action: %s" % hostupdate.action)
            return False

        # Semantic Check: Don't unlock if installation failed
        if (hostupdate.ihost_orig['install_state'] ==
           constants.INSTALL_STATE_FAILED):
            raise wsme.exc.ClientSideError(
                _("Cannot unlock host %s due to installation failure" %
                  hostupdate.displayid))

        # Semantic Check: Avoid Unlock of Unlocked Host
        if hostupdate.ihost_orig['administrative'] == constants.ADMIN_UNLOCKED:
            host_action = hostupdate.ihost_orig['ihost_action'] or ""
            if (host_action.startswith(constants.LOCK_ACTION) or
                    host_action.startswith(constants.FORCE_LOCK_ACTION) or
                        host_action.startswith(constants.FORCE_UNSAFE_LOCK_ACTION)):
                raise exception.HostLocking(
                    host=hostupdate.ihost_orig['hostname'],
                    action=host_action.strip('-'))
            else:
                raise wsme.exc.ClientSideError(
                    _("Avoiding 'unlock' action on already "
                      "'unlocked' host %s" % hostupdate.ihost_orig['hostname']))

        # Semantic Check: Action Dependency: Power-Off / Unlock case
        if (hostupdate.ihost_orig['availability'] ==
           constants.POWEROFF_ACTION):
            raise wsme.exc.ClientSideError(
                _("Can not 'Unlock a Powered-Off' host %s; Power-on, "
                  "wait for 'online' status and then 'unlock'" %
                  hostupdate.displayid))

        # Semantic Check: Action Dependency: Online / Unlock case
        if (not force_unlock and hostupdate.ihost_orig['availability'] !=
           constants.AVAILABILITY_ONLINE):
            raise wsme.exc.ClientSideError(
                _("Host %s is not online. "
                  "Wait for 'online' availability status and then 'unlock'" %
                  hostupdate.displayid))

        # To unlock, we need the following additional fields
        if not (hostupdate.ihost_patch['mgmt_mac'] and
                hostupdate.ihost_patch['hostname'] and
                hostupdate.ihost_patch['personality'] and
                hostupdate.ihost_patch['subfunctions']):
            raise wsme.exc.ClientSideError(
                _("Can not unlock an unprovisioned host %s. "
                  "Please perform 'Edit Host' to provision host."
                  % hostupdate.displayid))

        # To unlock, ensure reinstall has completed
        action_state = hostupdate.ihost_orig[constants.HOST_ACTION_STATE]
        if (action_state and
           action_state == constants.HAS_REINSTALLING):
            if not force_unlock:
                raise wsme.exc.ClientSideError(
                    _("Can not unlock host %s undergoing reinstall. "
                      "Please ensure host has completed reinstall prior to unlock."
                      % hostupdate.displayid))
            else:
                LOG.warn("Allowing force-unlock of host %s "
                         "undergoing reinstall." % hostupdate.displayid)

        # Ensure inventory has completed prior to allowing unlock
        host = pecan.request.dbapi.ihost_get(hostupdate.ihost_orig['uuid'])
        if host.inv_state != constants.INV_STATE_INITIAL_INVENTORIED:
            raise wsme.exc.ClientSideError(
                _("Can not unlock host %s that has not yet been "
                    "inventoried. Please wait for host to complete "
                    "initial inventory prior to unlock."
                    % hostupdate.displayid))

        # To unlock, ensure no app is being applied/reapplied, updated or recovered
        # as this could at best delay the in-progress app operation or at worst result
        # in failure due to timeout waiting for the host and its pods to recover from
        # the unlock.
        self.check_unlock_application(hostupdate, force_unlock)

        # Ensure there is no k8s rootca update phase in progress
        self._semantic_check_unlock_kube_rootca_update(hostupdate.ihost_orig,
                                                       force_unlock)

        # Ensure that we have physical volumes allocated to the cgts-vg volume group
        self._semantic_check_cgts_vg(hostupdate.ihost_orig['hostname'], hostupdate.ihost_orig['uuid'])

        personality = hostupdate.ihost_patch.get('personality')
        if personality == constants.CONTROLLER:
            self.check_unlock_controller(hostupdate, force_unlock)

        if cutils.host_has_function(hostupdate.ihost_patch, constants.WORKER):
            self.check_unlock_worker(hostupdate, force_unlock)
        elif personality == constants.STORAGE:
            self.check_unlock_storage(hostupdate)

        self.check_unlock_interfaces(hostupdate)
        self.unlock_update_mgmt_interface(hostupdate.ihost_patch)
        self.check_unlock_partitions(hostupdate)
        self.check_unlock_patching(hostupdate, force_unlock)
        self.check_unlock_kernel_config_status(hostupdate, force_unlock)
        self.check_unlock_apparmor_config_status(hostupdate, force_unlock)

        hostupdate.configure_required = True
        if ((os.path.isfile(constants.ANSIBLE_BOOTSTRAP_FLAG) or
             os.path.isfile(tsc.RESTORE_IN_PROGRESS_FLAG)) and
                hostupdate.ihost_patch['hostname'] ==
                    constants.CONTROLLER_0_HOSTNAME):
            # For the first unlock of the initial controller bootstrapped by
            # Ansible or the first unlock during restore, don't notify vim.
            hostupdate.notify_vim = False
        else:
            hostupdate.notify_vim = True

        return True

    def check_unlock_apparmor_config_status(self, hostupdate, force_unlock):
        """ Check whether apparmor configuration is in progress.
            Force unlock will bypass check
        """

        if force_unlock:
            return

        hostname = hostupdate.ihost_patch.get('hostname')
        apparmor_config_status = hostupdate.ihost_patch.get('apparmor_config_status')

        if apparmor_config_status == constants.APPARMOR_CONFIG_STATUS_PENDING:
            msg = (f'Can not unlock {hostname} '
                    'apparmor configuration in progress.')
            raise wsme.exc.ClientSideError(_(msg))

    def check_unlock_kernel_config_status(self, hostupdate, force_unlock):
        """ Check whether kernel configuration is in progress.
            The time kernel config was initiated is stored in host db
            If the time period hasn't expired we block unlock
            Force unlock will bypass check
        """

        if force_unlock:
            return

        hostname = hostupdate.ihost_patch.get('hostname')
        subfunctions = hostupdate.ihost_patch.get('subfunctions')
        kernel_config_time = hostupdate.ihost_patch.get('kernel_config_status')

        if constants.WORKER not in subfunctions:
            return

        try:
            config_time = datetime.datetime.strptime(
                kernel_config_time,
                constants.KERNEL_CONFIG_STATUS_FORMAT
            )
        except ValueError:
            # string is not a valid datetime - no kernel config in progress
            return

        current_time = datetime.datetime.now()
        interval = current_time - config_time

        if interval < datetime.timedelta():
            # negative time should not happen unlock clock was tampered with
            return

        if interval < constants.KERNEL_CONFIG_STATUS_EXPIRY:
            msg = (f'Can not unlock {hostname} '
                    'kernel configuration in progress.')
            raise wsme.exc.ClientSideError(_(msg))

    def check_unlock_patching(self, hostupdate, force_unlock):
        """Check whether the host is patch current.
        """

        if force_unlock:
            return

        hostname = hostupdate.ihost_patch.get('hostname')
        host_upgrade = usm_service.UsmHostUpgrade.get_by_hostname(pecan.request.dbapi, hostname)
        if host_upgrade is not None:
            if host_upgrade.state in constants.DEPLOY_HOST_DEPLOYED_STATES:
                return
            is_next_host = usm_service.is_host_next_to_be_deployed(pecan.request.dbapi, hostname)
            if not is_next_host:
                return
            else:
                raise wsme.exc.ClientSideError(
                    _("host-unlock rejected: software deploy to %s has not completed" % hostname))

    def check_lock(self, hostupdate):
        """Check semantics on  host-lock."""
        LOG.info("%s ihost check_lock" % hostupdate.displayid)
        if hostupdate.action != constants.LOCK_ACTION:
            LOG.error("%s check_lock unexpected action: %s" %
                      (hostupdate.displayid, hostupdate.action))
            return False

        # Semantic Check: Avoid Lock of Locked Host
        if hostupdate.ihost_orig['administrative'] == constants.ADMIN_LOCKED:
            # TOCHECK: previously resetting vals
            raise wsme.exc.ClientSideError(
                _("Avoiding %s action on already "
                  "'locked' host %s" % (hostupdate.ihost_patch['action'],
                                        hostupdate.ihost_orig['hostname'])))

        # Semantic Check: Avoid Lock when a backup is in progress
        if os.path.isfile(tsc.BACKUP_IN_PROGRESS_FLAG):
            raise wsme.exc.ClientSideError(
                _("Avoiding lock action during 'backup in progress' on host %s. "
                  "If lock is required, please use \"force lock\" command." %
                  (hostupdate.ihost_orig['hostname'])))

        # personality specific lock checks
        personality = hostupdate.ihost_patch.get('personality')

        # Semantic Check: Bare-Metal Ceph
        if StorageBackendConfig.has_backend_configured(
                pecan.request.dbapi,
                constants.SB_TYPE_CEPH
        ):
            # Semantic Check: Avoid Lock of Host with recovering OSDs
            # First ignore: workers, simplex, hosts without OSDs configured
            if personality != constants.WORKER and \
                   not cutils.is_aio_simplex_system(pecan.request.dbapi) and \
                   pecan.request.dbapi.istor_get_by_ihost(hostupdate.ihost_orig['uuid']) and \
                   self._ceph.check_recovery_in_progress(hostupdate.ihost_orig['hostname']):
                raise wsme.exc.ClientSideError(
                    _("PGs in recovery state, rejecting %s action on %s as OSDs "
                      "of this host are getting up to date data from its peer "
                      "host. Retry once recovery completes." % (
                          hostupdate.ihost_patch['action'],
                          hostupdate.ihost_orig['hostname'])))

        if personality == constants.CONTROLLER:
            self.check_lock_controller(hostupdate)

        elif personality == constants.STORAGE:
            self.check_lock_storage(hostupdate)

        subfunctions_set = \
            set(hostupdate.ihost_patch[constants.SUBFUNCTIONS].split(','))
        if (personality == constants.WORKER or
                constants.WORKER in subfunctions_set):
            self.check_lock_worker(hostupdate)

        hostupdate.notify_vim = True
        hostupdate.notify_mtce = True

        return True

    def check_force_unsafe_lock(self, hostupdate):
        # personality specific lock checks
        personality = hostupdate.ihost_patch.get('personality')
        if personality == constants.CONTROLLER:
            self.check_lock_controller(hostupdate, force=True, unsafe=True)

        elif personality == constants.STORAGE:
            self.check_lock_storage(hostupdate, force=True, unsafe=True)
        return True

    def check_force_lock(self, hostupdate):
        # personality specific lock checks
        personality = hostupdate.ihost_patch.get('personality')
        if personality == constants.CONTROLLER:
            self.check_lock_controller(hostupdate, force=True)

        elif personality == constants.STORAGE:
            self.check_lock_storage(hostupdate, force=True)
        return True

    def check_lock_controller(self, hostupdate, force=False, unsafe=False):
        """Pre lock semantic checks for controller"""

        LOG.info("%s ihost check_lock_controller" % hostupdate.displayid)

        # Prevent locking active controller, but allow it when it is in a
        # simplex state.
        if (utils.get_system_mode() != constants.SYSTEM_MODE_SIMPLEX and
                not utils.is_host_simplex_controller(hostupdate.ihost_orig)):
            active = utils.is_host_active_controller(hostupdate.ihost_orig)
            if active:
                raise wsme.exc.ClientSideError(
                    _("%s : Rejected: Can not lock an active "
                      "controller.") % hostupdate.ihost_orig['hostname'])

        ceph_rook_backend = StorageBackendConfig.get_backend_conf(
            pecan.request.dbapi,
            target=constants.SB_TYPE_CEPH_ROOK
        )

        # Reject lock while the rook-ceph app is any progress state
        if (ceph_rook_backend and ceph_rook_backend['task'] in
                         [constants.APP_UPLOAD_IN_PROGRESS,
                          constants.APP_APPLY_IN_PROGRESS,
                          constants.APP_REMOVE_IN_PROGRESS,
                          constants.APP_UPDATE_IN_PROGRESS,
                          constants.APP_RECOVER_IN_PROGRESS]):
                    msg = _("Rejected: The application %s is in transition, please "
                            "wait for the current operation to complete "
                            "before host-lock action.") % constants.SB_APP_MAP[
                                ceph_rook_backend['backend']]
                    raise wsme.exc.ClientSideError(msg)

        # Reject lock while Ceph OSD storage devices are configuring
        if not force:
            stors = pecan.request.dbapi.istor_get_by_ihost(
                hostupdate.ihost_orig['uuid']
            )

            for stor in stors:
                if (stor.state == constants.SB_STATE_CONFIGURING):
                    raise wsme.exc.ClientSideError(
                        _("%s : Rejected: Can not lock a controller "
                          "with storage devices in '%s' state.") %
                         (hostupdate.ihost_orig['hostname'],
                          constants.SB_STATE_CONFIGURING))

        if StorageBackendConfig.has_backend_configured(
                    pecan.request.dbapi,
                    constants.SB_TYPE_CEPH):
            query_hosts = None
            stor_model = ceph.get_ceph_storage_model()
            if stor_model == constants.CEPH_STORAGE_MODEL:
                query_hosts = constants.STORAGE
            elif stor_model == constants.CEPH_CONTROLLER_MODEL:
                query_hosts = constants.CONTROLLER
            else:
                # If backend type is still undefined it means no storage nodes
                # have been configured and no worker monitor has been added,
                # so it is safe to not check the quorum.
                # Or we are dealing with an AIO-SX.
                return
            try:
                st_nodes = pecan.request.dbapi.ihost_get_by_personality(query_hosts)
            except exception.NodeNotFound:
                # If we don't have any storage nodes we don't need to
                # check for quorum. We'll allow the node to be locked.
                # We will always have at least one controller, so for
                # controllers that also act as storage nodes this should
                # never happen.
                return

            # Do not allow locking controllers when all storage nodes are locked.
            # Allow lock if unsafe=True
            if stor_model == constants.CEPH_STORAGE_MODEL:
                for node in st_nodes:
                    if (node['administrative'] == constants.ADMIN_UNLOCKED):
                        break
                else:
                    if not unsafe:
                        raise wsme.exc.ClientSideError(
                            _("Rejected: Can not lock host %s when storage nodes are locked "
                            "Use --force_unsafe if you wish to lock anyway."
                            % hostupdate.displayid))
                    return

            if (hostupdate.ihost_orig['administrative'] ==
                    constants.ADMIN_UNLOCKED and
                    hostupdate.ihost_orig['operational'] ==
                    constants.OPERATIONAL_ENABLED):
                # If the node is unlocked and enabled we need to check that we
                # have enough storage monitors.
                utils.check_node_lock_ceph_mon(
                    hostupdate.ihost_orig, unsafe=unsafe, ceph_helper=self._ceph)

        if not force:
            # sm-lock-pre-check
            node_name = hostupdate.displayid
            response = sm_api.lock_pre_check(node_name, timeout=30)
            if response:
                error_code = response.get('error_code')
                if ERR_CODE_LOCK_SOLE_SERVICE_PROVIDER == error_code:
                    impact_svc_list = response.get('impact_service_list')
                    svc_list = ','.join(impact_svc_list)
                    if len(impact_svc_list) > 1:
                        msg = _("Services {svc_list} are only running on "
                                "{host}, locking {host} will result "
                                "service outage. If lock {host} is required, "
                                "please use \"force lock\" command.").format(
                            svc_list=svc_list, host=node_name)
                    else:
                        msg = _("Service {svc_list} is only running on "
                                "{host}, locking {host} will result "
                                "service outage. If lock {host} is required, "
                                "please use \"force lock\" command.").format(
                            svc_list=svc_list, host=node_name)

                    raise wsme.exc.ClientSideError(msg)
                elif "0" != error_code:
                    raise wsme.exc.ClientSideError(
                        _("%s" % response['error_details']))

            self._check_lock_controller_during_upgrade(hostupdate.ihost_orig['hostname'])

    @staticmethod
    def _check_lock_controller_during_upgrade(hostname):
        # Check to ensure in valid upgrade state for host-lock
        try:
            upgrade = usm_service.get_platform_upgrade(pecan.request.dbapi)
        except exception.NotFound:
            # No upgrade in progress
            return

        if upgrade.state in constants.DEPLOY_STATE_TRANSIENT_STATES:
            # Lock of controllers is not allowed during
            # the deployment transient states
            raise wsme.exc.ClientSideError(
                _("host-lock %s is not allowed during upgrade state '%s'") %
                (hostname, upgrade.state))

    def check_unlock_application(self, hostupdate, force_unlock=False):
        LOG.info("%s ihost check_unlock_application" % hostupdate.displayid)
        apps = pecan.request.dbapi.kube_app_get_all()

        blocked_app_statuses = [constants.APP_APPLY_IN_PROGRESS,
                                constants.APP_UPDATE_IN_PROGRESS,
                                constants.APP_RECOVER_IN_PROGRESS,
                                constants.APP_REMOVE_IN_PROGRESS]

        # Also prevent unlocking if any apps are uploading in simplex systems
        additional_error_status = ""
        if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
            blocked_app_statuses.append(constants.APP_UPLOAD_IN_PROGRESS)
            additional_error_status = "uploaded, "

        for app in apps:
            if app.status in blocked_app_statuses:
                if not force_unlock:
                    raise wsme.exc.ClientSideError(
                        _("Rejected: Can not unlock host %s while an application is being "
                          "%sapplied, updated, recovered or removed. "
                          "Please try again later."
                          % (hostupdate.displayid, additional_error_status)))
                else:
                    LOG.warn("Allowing force-unlock of host %s while application "
                             "%s status = '%s'"
                             % (hostupdate.displayid, app.name,
                                app.status))
                    # Could break here, but it is harmless getting a stat of
                    # simultaneous app ops.

    def check_unlock_controller(self, hostupdate, force_unlock=False):
        """Pre unlock semantic checks for controller"""
        LOG.info("%s ihost check_unlock_controller" % hostupdate.displayid)
        self._semantic_check_unlock_kube_upgrade(hostupdate.ihost_orig, force_unlock)
        self._semantic_check_oam_interface(hostupdate.ihost_orig)
        self._semantic_check_cinder_volumes(hostupdate.ihost_orig)
        self._semantic_check_filesystem_sizes(hostupdate.ihost_orig)
        self._semantic_check_storage_backend(hostupdate.ihost_orig)
        system_mode_options = [
                    constants.SYSTEM_MODE_DUPLEX,
                    constants.SYSTEM_MODE_DUPLEX_DIRECT,
                ]
        if utils.get_system_mode() in system_mode_options:
            self._semantic_check_duplex_oam_config(hostupdate.ihost_orig)

    def check_unlock_worker(self, hostupdate, force_unlock=False):
        """Check semantics on  host-unlock of a worker."""
        LOG.info("%s ihost check_unlock_worker" % hostupdate.displayid)
        ihost = hostupdate.ihost_orig
        if ihost['invprovision'] is None:
            raise wsme.exc.ClientSideError(
                _("Can not unlock an unconfigured host %s. Please "
                  "configure host and wait for Availability State "
                  "'online' prior to unlock." % hostupdate.displayid))

        # Check if kubernetes upgrade is in-progress
        if cutils.is_std_system(pecan.request.dbapi):
            self._semantic_check_unlock_kube_upgrade(hostupdate.ihost_orig, force_unlock)

        # Check whether a restore was properly completed
        self._semantic_check_restore_complete(ihost)
        # Disable certain worker unlock checks in a kubernetes config
        self._semantic_check_data_interfaces(ihost,
                                             force_unlock)

        # Check whether a device has completed configuration
        self._semantic_check_devices(ihost, force_unlock)

        # Check if cpu assignments are valid
        self._semantic_check_worker_cpu_assignments(ihost)

        # only allow allocating huge pages for a single size
        self._check_memory_for_single_size(ihost)

        # check if the platform reserved memory is valid
        ihost_inodes = pecan.request.dbapi.inode_get_by_ihost(ihost['uuid'])
        mib_reserved = 0
        mib_reserved_disk_io = 0
        align_2M_memory = False
        align_1G_memory = False

        # semantic check vswitch memory if required
        host_labels = pecan.request.dbapi.label_get_by_host(ihost['uuid'])
        if (utils.get_vswitch_type() != constants.VSWITCH_TYPE_NONE and
                cutils.has_vswitch_enabled(host_labels, pecan.request.dbapi)):
            self._check_vswitch_memory(ihost_inodes)

        for node in ihost_inodes:
            # If the reserved memory has changed (eg, due to patch that
            # changes common/constants.py), then push updated reserved memory
            # to database, and automatically adjust 2M and 1G hugepages based
            # on the delta.  Patch removal will not result in the auto
            # incremented value to be brought back down as there is no record
            # of the original setting.
            self._auto_adjust_memory_for_node(ihost, node)

            # check whether the pending hugepages changes and the current
            # platform reserved memory fit within the total memory available
            mib_reserved_node, pending_2M_memory, pending_1G_memory = \
                self._semantic_check_memory_for_node(ihost, node)
            mib_reserved += mib_reserved_node
            if pending_2M_memory:
                align_2M_memory = True
                LOG.info("pending 2M memory node=%s mib_reserved=%s" %
                         (node.uuid, mib_reserved))
            if pending_1G_memory:
                align_1G_memory = True
                LOG.info("pending 1G memory node=%s mib_reserved=%s" %
                         (node.uuid, mib_reserved))
            mib_reserved_disk_io += constants.DISK_IO_RESIDENT_SET_SIZE_MIB

        if align_2M_memory or align_1G_memory:
            self._align_pending_memory(ihost, align_2M_memory, align_1G_memory)

        # update ihost huge pages allocation
        self._update_huge_pages(ihost)

        if cutils.is_virtual() or cutils.is_virtual_worker(ihost):
            mib_platform_reserved_no_io = mib_reserved
            required_platform = \
                constants.PLATFORM_CORE_MEMORY_RESERVED_MIB_VBOX
            if cutils.host_has_function(ihost, constants.CONTROLLER):
                required_platform += \
                    constants.COMBINED_NODE_CONTROLLER_MEMORY_RESERVED_MIB_VBOX
            else:
                # If not a controller, add overhead for metadata and vrouters
                required_platform += \
                    constants.NETWORK_METADATA_OVERHEAD_MIB_VBOX
        else:
            mib_platform_reserved_no_io = mib_reserved - mib_reserved_disk_io
            required_platform = constants.PLATFORM_CORE_MEMORY_RESERVED_MIB
            if cutils.host_has_function(ihost, constants.CONTROLLER):
                low_core = cutils.is_low_core_system(ihost, pecan.request.dbapi)
                if low_core:
                    required_platform += \
                        constants.COMBINED_NODE_CONTROLLER_MEMORY_RESERVED_MIB_XEOND
                else:
                    required_platform += \
                        constants.COMBINED_NODE_CONTROLLER_MEMORY_RESERVED_MIB
            else:
                # If not a controller, add overhead for metadata and vrouters
                required_platform += constants.NETWORK_METADATA_OVERHEAD_MIB

        LOG.debug("mib_platform_reserved_no_io %s required_platform %s"
                  % (mib_platform_reserved_no_io, required_platform))
        if mib_platform_reserved_no_io < required_platform:
            msg = (_("Insufficient memory reserved for platform on %(host)s. "
                     "Platform memory must be at least %(required)s MiB "
                     "summed across all numa nodes."
                     ) %
                   {'host': ihost['hostname'], 'required': required_platform})
            raise wsme.exc.ClientSideError(msg)

        shared_services = utils.get_shared_services()
        if (shared_services is not None and
                constants.SERVICE_TYPE_VOLUME in shared_services):
            # do not check storage nodes in secondary region as "volume" is
            # shared service provided by the primary region.
            pass
        elif StorageBackendConfig.has_backend_configured(
                pecan.request.dbapi,
                constants.SB_TYPE_CEPH):
            if cutils.is_aio_simplex_system(pecan.request.dbapi):
                # Check if host has enough OSDs configured for each tier
                tiers = pecan.request.dbapi.storage_tier_get_all()
                ceph_tiers = [t for t in tiers if t.type == constants.SB_TIER_TYPE_CEPH]
                max_replication, __ = \
                    StorageBackendConfig.get_ceph_max_replication(pecan.request.dbapi)
                for tier in ceph_tiers:
                    replication = max_replication  # In case tier has no storage backend configured
                    if tier.get('forbackendid'):
                        bk = pecan.request.dbapi.storage_ceph_get(tier.forbackendid)
                        replication, __ = \
                            StorageBackendConfig.get_ceph_pool_replication(pecan.request.dbapi, bk)
                    stors = pecan.request.dbapi.istor_get_by_tier(tier.id)
                    if len(stors) < replication:
                        word = 'is' if replication == 1 else 'are'
                        msg = ("Can not unlock node until at least %(replication)s osd stor %(word)s "
                              "configured for tier '%(tier)s'."
                               % {'replication': str(replication), 'word': word, 'tier': tier['name']})
                        raise wsme.exc.ClientSideError(msg)
            else:
                if cutils.is_aio_duplex_system(pecan.request.dbapi):
                    if cutils.host_has_function(ihost, constants.CONTROLLER):
                        host_stors = pecan.request.dbapi.istor_get_by_ihost(ihost['id'])
                        if not host_stors:
                            raise wsme.exc.ClientSideError(
                                _("Can not unlock node until at least one OSD is configured."))

                        tiers = pecan.request.dbapi.storage_tier_get_all()
                        ceph_tiers = [t for t in tiers if t.type == constants.SB_TIER_TYPE_CEPH]
                        # On a two-node configuration, both nodes should have at least one OSD
                        # in each tier. Otherwise, the cluster is remains in an error state.
                        for tier in ceph_tiers:
                            stors = tier['stors']
                            host_has_osd_in_tier = False
                            for stor in stors:
                                if stor['forihostid'] == ihost['id']:
                                    host_has_osd_in_tier = True

                            if not host_has_osd_in_tier:
                                raise wsme.exc.ClientSideError(
                                    "Can not unlock node until every storage tier has at least one OSD "
                                    "configured. Tier \"%s\" has no OSD configured." % tier['name'])

                else:
                    stor_model = ceph.get_ceph_storage_model()
                    if stor_model == constants.CEPH_UNDEFINED_MODEL:
                        raise wsme.exc.ClientSideError(
                            _("Can not unlock a worker node until the third Ceph monitor "
                              "is defined by either adding a storage node or configuring "
                              "a monitor on a worker node. "
                              "Note that this will select the storage deployment model, "
                              "check documentation for details and restrictions."))

        # openstack local storage
        labels = pecan.request.dbapi.label_get_by_host(ihost['uuid'])
        if cutils.has_openstack_compute(labels):
            # Required: make sure present
            if not cutils.is_host_filesystem_enabled(pecan.request.dbapi,
                                                     ihost['uuid'],
                                                     constants.FILESYSTEM_NAME_INSTANCES):
                self._semantic_check_nova_local_storage(ihost['uuid'],
                                                        ihost['personality'],
                                                        required=True)
        else:
            # Optional: Check if partially added
            self._semantic_check_nova_local_storage(ihost['uuid'],
                                                    ihost['personality'],
                                                    required=False)

    @staticmethod
    def check_unlock_storage(hostupdate):
        """Storage unlock semantic checks"""
        # Semantic Check: Cannot unlock a storage node without
        # any Storage Volumes (OSDs) configured
        LOG.info("%s ihost check_unlock_storage" % hostupdate.displayid)

        ihost = hostupdate.ihost_orig
        istors = pecan.request.dbapi.istor_get_by_ihost(ihost['uuid'])
        if len(istors) == 0:
            raise wsme.exc.ClientSideError(
                _("Can not unlock a storage node without any Storage Volumes configured"))

        ceph_helper = ceph.CephApiOperator()
        num_monitors, required_monitors, __ = \
            ceph_helper.get_monitors_status(pecan.request.dbapi)

        # Checks that the hostname is storage-0 and is provisioned
        # to determine that only one monitor is needed to perform the unlock.
        # This allows quorum to be reestablished as quickly as possible.
        if ihost['hostname'] == "storage-0" and ihost['invprovision'] == constants.PROVISIONED:
            required_monitors = 1

        if num_monitors < required_monitors:
            raise wsme.exc.ClientSideError(
                _("Can not unlock storage node. Only %d storage "
                  "monitor available. At least %s unlocked and "
                  "enabled hosts with monitors are required. Please"
                  " ensure hosts with monitors are unlocked and "
                  "enabled.") %
                (num_monitors, required_monitors))

    @staticmethod
    def check_updates_while_unlocked(hostupdate, delta):
        """Check semantics host-update of an unlocked host."""

        ihost = hostupdate.ihost_patch
        if ihost['administrative'] == constants.ADMIN_UNLOCKED:
            deltaset = set(delta)

            restricted_updates = ()
            if not pecan.request.user_agent.startswith('mtce'):
                # Allow mtc to modify the state throughthe REST API.
                # Eventually mtc should switch to using the
                # conductor API to modify ihosts because this check will also
                # allow users to modify these states (which is bad).
                restricted_updates = ('administrative',
                                      'availability',
                                      'operational',
                                      'subfunction_oper',
                                      'subfunction_avail',
                                      'task', 'uptime')

            if deltaset.issubset(restricted_updates):
                raise wsme.exc.ClientSideError(
                    ("Change set %s contains a subset of restricted %s." %
                     (deltaset, restricted_updates)))
            else:
                LOG.debug("PASS deltaset=%s restricted_updates=%s" %
                          (deltaset, restricted_updates))

            if 'administrative' in delta:
                # Transition to unlocked
                if ihost['ihost_action']:
                    LOG.info("Host: %s Admin state change to: %s "
                             "Clearing ihost_action=%s" %
                             (ihost['uuid'],
                              ihost['administrative'],
                              ihost['ihost_action']))
                    hostupdate.ihost_val_update({'ihost_action': ""})
                pass

    @staticmethod
    def check_force_swact(hostupdate):
        """Pre swact semantic checks for controller"""
        # Allow force-swact to continue
        return True

    @staticmethod
    def check_reboot(hostupdate):
        """Pre reboot semantic checks"""
        # Semantic Check: State Dependency: Reboot case
        if hostupdate.ihost_orig['administrative'] == constants.ADMIN_UNLOCKED:
            raise wsme.exc.ClientSideError(
                _("Can not 'Reboot' an 'unlocked' host %s; "
                  "Please 'Lock' first" % hostupdate.displayid))

        if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
            raise wsme.exc.ClientSideError(_(
                "Rebooting a simplex system is not allowed."))
        return True

    def _semantic_check_swact_upgrade(self, from_host, to_host, force_swact=False):
        """
        Perform semantic checks related to upgrades prior to swacting host.
        """

        # First check if we are in an upgrade
        try:
            upgrade = usm_service.get_platform_upgrade(pecan.request.dbapi)
        except exception.NotFound:
            # No upgrade in progress so nothing to check
            return

        if isinstance(upgrade, usm_service.UsmUpgrade):
            err_msg = "Swact is not allowed. "

            # fail if deployment is in a transient state
            if upgrade.state in constants.DEPLOY_STATE_TRANSIENT_STATES:
                err_msg += "Upgrade in progress with '%s' state." % upgrade.state
                raise wsme.exc.ClientSideError(err_msg)

            to_host_deploy = usm_service.UsmHostUpgrade.get_by_hostname(
                pecan.request.dbapi, to_host['hostname'])
            if to_host_deploy.state in constants.DEPLOY_HOST_DEPLOYED_STATES:
                # to host has deployed
                pass
            else:
                from_host_deploy = usm_service.UsmHostUpgrade.get_by_hostname(
                    pecan.request.dbapi, from_host['hostname'])
                if (from_host_deploy.state in constants.DEPLOY_HOST_PENDING_STATES and
                        to_host_deploy.state in constants.DEPLOY_HOST_PENDING_STATES):
                    # no host has started deploy yet
                    pass
                else:
                    err_msg += "New release has not been deployed to %s" % to_host['hostname']
                    raise wsme.exc.ClientSideError(err_msg)

    def _semantic_check_swact_kube_rootca_update(self, ihost, force_swact=False):
        """
        Perform semantic checks related to kubernetes rootca update
        prior to swacting host.
        """

        if force_swact:
            LOG.warning("Host %s force swact while kubernetes "
                        "rootca update in progress on host."
                        % ihost['hostname'])
            return

        try:
            kube_rootca_update = \
                pecan.request.dbapi.kube_rootca_update_get_one()

            if kube_rootca_update.state in [kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTBOTHCAS,
                                            kubernetes.KUBE_ROOTCA_UPDATING_PODS_TRUSTNEWCA]:
                msg = _("Can not swact %s while kubernetes root ca "
                        "update phase in progress. Wait for update "
                        "phase to complete." % ihost['hostname'])
                raise wsme.exc.ClientSideError(msg)
        except exception.NotFound:
            LOG.debug("No kubernetes rootca update was found")
            return

        try:
            kube_host_rootca_update = \
                pecan.request.dbapi.kube_rootca_host_update_get_by_host(ihost['uuid'])
            if kube_host_rootca_update.state in [kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTBOTHCAS,
                                                 kubernetes.KUBE_ROOTCA_UPDATING_HOST_UPDATECERTS,
                                                 kubernetes.KUBE_ROOTCA_UPDATING_HOST_TRUSTNEWCA]:
                msg = _("Can not swact %s while kubernetes root ca "
                        "update phase is in progress. Wait for update "
                        "phase to complete on host." % ihost['hostname'])
                raise wsme.exc.ClientSideError(msg)
        except exception.NotFound:
            LOG.debug("No kubernetes rootca update on host %s "
                      "was found" % ihost['hostname'])
            return

    def _check_swact_device_image_update(self, from_host, to_host, force=False):
        if force:
            LOG.info("device image update swact check bypassed with force option")
            return
        if (from_host['device_image_update'] ==
                device.DEVICE_IMAGE_UPDATE_IN_PROGRESS):
            raise wsme.exc.ClientSideError(_(
                "Rejected: Cannot swact %s while %s is updating device "
                "images.") % (from_host['hostname'], from_host['hostname']))

        if (to_host['device_image_update'] ==
                device.DEVICE_IMAGE_UPDATE_IN_PROGRESS):
            raise wsme.exc.ClientSideError(_(
                "Rejected: Cannot swact %s while %s is updating device "
                "images.") % (from_host['hostname'], to_host.hostname))

    def check_swact(self, hostupdate, force_swact=False):
        """Pre swact semantic checks for controller"""

        if hostupdate.ihost_orig['personality'] != constants.CONTROLLER:
            raise wsme.exc.ClientSideError(
                _("Swact action not allowed for non controller host %s." %
                  hostupdate.ihost_orig['hostname']))

        if hostupdate.ihost_orig['administrative'] == constants.ADMIN_LOCKED:
            raise wsme.exc.ClientSideError(
                _("Controller is Locked ; No services to Swact"))

        if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
            raise wsme.exc.ClientSideError(_(
                "Swact action not allowed for a simplex system."))

        # check target controller
        ihost_ctrs = pecan.request.dbapi.ihost_get_by_personality(
            personality=constants.CONTROLLER)

        for ihost_ctr in ihost_ctrs:
            if ihost_ctr.hostname != hostupdate.ihost_orig['hostname']:
                if (ihost_ctr.operational !=
                        constants.OPERATIONAL_ENABLED):
                    raise wsme.exc.ClientSideError(
                        _("%s is not enabled and has operational "
                          "state %s."
                          "Standby controller must be  operationally "
                          "enabled.") %
                        (ihost_ctr.hostname, ihost_ctr.operational))

                if (ihost_ctr.availability ==
                        constants.AVAILABILITY_DEGRADED):
                    health_helper = health.Health(pecan.request.dbapi)
                    degrade_alarms = health_helper.get_alarms_degrade(
                        pecan.request.context,
                        alarm_ignore_list=[
                            fm_constants.FM_ALARM_ID_HA_SERVICE_GROUP_STATE,
                            fm_constants.FM_ALARM_ID_HA_SERVICE_GROUP_REDUNDANCY,
                            fm_constants.FM_ALARM_ID_HA_NODE_LICENSE,
                            fm_constants.FM_ALARM_ID_HA_COMMUNICATION_FAILURE
                        ],
                        entity_instance_id_filter=ihost_ctr.hostname)
                    if degrade_alarms:
                        raise wsme.exc.ClientSideError(
                            _("%s has degraded availability status. "
                              "Standby controller must be in available status.") %
                            (ihost_ctr.hostname))

                if constants.WORKER in ihost_ctr.subfunctions:
                    if (ihost_ctr.subfunction_oper !=
                            constants.OPERATIONAL_ENABLED):
                        raise wsme.exc.ClientSideError(
                            _("%s subfunction is not enabled and has "
                              "operational state %s."
                              "Standby controller subfunctions %s "
                              "must all be operationally enabled.") %
                            (ihost_ctr.hostname,
                             ihost_ctr.subfunction_oper,
                             ihost_ctr.subfunctions))

                # Deny swact for specific in-progress actions.
                #
                # Need to handle the case where a lock action has been
                # issued against the peer controller that is shortly
                # followed by a swact before the lock is complete.
                #
                # Allowing the swact to continue can lead to activating
                # a locked standby controller.
                #
                # Note: The force_swact is not honored to prevent swact
                #       to a locked controller.
                #
                # The following is a list of host actions that if
                # any are in-progress should force a reject of the
                # swact request.
                if ihost_ctr.task:
                    rejected_actions = [constants.LOCK_ACTION,
                                        constants.FORCE_LOCK_ACTION,
                                        constants.FORCE_UNSAFE_LOCK_ACTION]
                    for reject_action in rejected_actions:
                        task_str = hostupdate.get_task_from_action(reject_action)
                        if ihost_ctr.task.startswith(task_str):
                            raise wsme.exc.ClientSideError(
                                _("%s is currently being locked. Cannot "
                                  "Swact to a controller with an in-progress "
                                  "lock operation.") % (ihost_ctr.hostname))

                # deny swact if a kube rootca update phase is in progress
                self._semantic_check_swact_kube_rootca_update(hostupdate.ihost_orig,
                                                              force_swact)

                # deny swact if storage backend not ready
                self._semantic_check_storage_backend(ihost_ctr)

                # deny swact if one of the controllers is updating device image
                self._check_swact_device_image_update(hostupdate.ihost_orig,
                                                      ihost_ctr, force_swact)

                if ihost_ctr.config_target and\
                        ihost_ctr.config_target != ihost_ctr.config_applied:
                    try:
                        upgrade = usm_service.get_platform_upgrade(pecan.request.dbapi)
                    except exception.NotFound:
                        upgrade = None
                    if upgrade and upgrade.state == \
                            constants.UPGRADE_ABORTING_ROLLBACK:
                        pass
                    elif not utils.is_host_active_controller(ihost_ctr):
                        # This condition occurs when attempting to host-swact
                        # away from "active" (platform services) controller.
                        #
                        # Since api (sysinv, sm) allows for host-swact
                        # services away from a "standby" controller, this enforcement
                        # is not required for host-swact to the already
                        # active controller.
                        raise wsme.exc.ClientSideError(
                            _("%s target Config %s not yet applied."
                              " Apply target Config via Lock/Unlock prior"
                              " to Swact") %
                            (ihost_ctr.hostname, ihost_ctr.config_target))

                self._semantic_check_swact_upgrade(hostupdate.ihost_orig,
                                                   ihost_ctr,
                                                   force_swact)

        # Check: If DRBD is resizing
        controller_fs_list = pecan.request.dbapi.controller_fs_get_list()
        for controller_fs in controller_fs_list:
            if controller_fs['replicated']:
                if (eval(controller_fs.get('state'))['status'] ==
                        constants.CONTROLLER_FS_RESIZING_IN_PROGRESS):
                    raise wsme.exc.ClientSideError(
                        _("drbd '%s' is resizing. Wait for the resizing to "
                          "complete before issuing Swact") %
                        (controller_fs['name']))

        # Check: Valid Swact action: Pre-Swact Check
        response = sm_api.swact_pre_check(hostupdate.ihost_orig['hostname'],
                                          timeout=30)
        if response and "0" != response['error_code']:
            raise wsme.exc.ClientSideError(
                _("%s" % response['error_details']))

        # Check no app apply is in progress
        # Skip if it is a force swact
        if force_swact is False:
            for _app in pecan.request.dbapi.kube_app_get_all():
                if _app.status == constants.APP_APPLY_IN_PROGRESS:
                    raise wsme.exc.ClientSideError(
                        _("Swact action not allowed. %s apply is in progress." % _app.name))

    def check_lock_storage(self, hostupdate, force=False, unsafe=False):
        """Pre lock semantic checks for storage"""
        LOG.info("%s ihost check_lock_storage" % hostupdate.displayid)

        backend = StorageBackendConfig.get_configured_backend(
            pecan.request.dbapi,
            constants.CINDER_BACKEND_CEPH
        )
        if not backend:
            raise wsme.exc.ClientSideError(
                _("Ceph must be configured as a backend."))

        if (backend.task == constants.SB_TASK_RESTORE and force):
            LOG.info("%s Allow force-locking as ceph backend is in "
                     "restore mode" % hostupdate.displayid)
            return

        ceph_pools_empty = False
        if (hostupdate.ihost_orig['administrative'] ==
                constants.ADMIN_UNLOCKED and
                hostupdate.ihost_orig['operational'] ==
                constants.OPERATIONAL_ENABLED):
            utils.check_node_lock_ceph_mon(
                hostupdate.ihost_orig, unsafe=unsafe, ceph_helper=self._ceph)

            storage_nodes = pecan.request.dbapi.ihost_get_by_personality(
                constants.STORAGE)

            replication, min_replication = \
                StorageBackendConfig.get_ceph_max_replication(pecan.request.dbapi)
            available_peer_count = 0
            for node in storage_nodes:
                if (node['id'] != hostupdate.ihost_orig['id'] and
                   node['peer_id'] == hostupdate.ihost_orig['peer_id']):
                    ihost_action_locking = False
                    ihost_action = node['ihost_action'] or ""

                    if (ihost_action.startswith(constants.FORCE_UNSAFE_LOCK_ACTION) or
                       ihost_action.startswith(constants.FORCE_LOCK_ACTION) or
                       ihost_action.startswith(constants.LOCK_ACTION)):
                        ihost_action_locking = True

                    if (node['administrative'] == constants.ADMIN_UNLOCKED and
                       node['operational'] == constants.OPERATIONAL_ENABLED and not
                       ihost_action_locking):
                        available_peer_count += 1

            if available_peer_count < min_replication:
                pools_usage = \
                    pecan.request.rpcapi.get_ceph_pools_df_stats(pecan.request.context)
                if not pools_usage:
                    raise wsme.exc.ClientSideError(
                        _("Cannot lock a storage node when ceph pool usage is undetermined."))

                ceph_pools_empty = self._ceph.ceph_pools_empty(
                    pecan.request.dbapi, pools_usage)

                if not ceph_pools_empty:
                    msg = _(
                        "Cannot lock a storage node when ceph pools are"
                        " not empty and replication is lost. This may"
                        " result in data loss. ")
                    # Ceph pool is not empty and no other enabled storage
                    # in set, so locking this storage node is not allowed.
                    raise wsme.exc.ClientSideError(msg)

        # Perform checks on storage regardless of operational state
        # as a minimum number of monitor is required.
        if not force:
            # Check if there is upgrade in progress
            try:
                upgrade = usm_service.get_platform_upgrade(pecan.request.dbapi)
                if upgrade.state in [constants.UPGRADE_ABORTING_ROLLBACK]:
                    LOG.info("%s not in a force lock and in an upgrade abort, "
                             "do not check Ceph status"
                             % hostupdate.displayid)
                    return
            except exception.NotFound:
                pass

            if not self._ceph.ceph_status_ok():
                LOG.info("%s ceph_status_ok() returned not ok"
                         % hostupdate.displayid)
                host_health = self._ceph.host_osd_status(
                    hostupdate.ihost_orig['hostname'])
                LOG.info("%s check OSD host_health=%s" %
                         (hostupdate.displayid, host_health))
                if (host_health is None or
                   host_health == constants.CEPH_HEALTH_BLOCK):
                    LOG.info("%s host_health=%s" %
                             (hostupdate.displayid, host_health))
                    if not ceph_pools_empty:
                        msg = _("Cannot lock a storage node when ceph pools are not empty "
                                "and replication is lost. This may result in data loss. ")
                        raise wsme.exc.ClientSideError(msg)

    def check_lock_worker(self, hostupdate, force=False, unsafe=False):
        """Pre lock semantic checks for worker"""

        hostname = hostupdate.ihost_patch.get('hostname')
        LOG.info("%s host check_lock_worker" % hostupdate.displayid)
        if force:
            LOG.info("Forced lock of host: %s" % hostname)
            return

        system = pecan.request.dbapi.isystem_get_one()
        system_mode = system.system_mode
        system_type = system.system_type

        # Check if host is in the process of updating device image
        if (hostupdate.ihost_orig['device_image_update'] ==
                device.DEVICE_IMAGE_UPDATE_IN_PROGRESS):
            raise wsme.exc.ClientSideError(_(
                "Rejected: Cannot lock %s while device image update is in "
                "progress.") % hostupdate.displayid)

        if system_mode == constants.SYSTEM_MODE_SIMPLEX:
            return

        # Check upgrade state for controllers with worker subfunction
        subfunctions_set = \
            set(hostupdate.ihost_patch[constants.SUBFUNCTIONS].split(','))
        if (hostupdate.ihost_orig['personality'] == constants.CONTROLLER and
                constants.WORKER in subfunctions_set):
            upgrade = None
            try:
                upgrade = usm_service.get_platform_upgrade(pecan.request.dbapi)
                upgrade_state = upgrade.state
            except exception.NotFound:
                upgrade_state = None

            if upgrade_state in [
                    constants.UPGRADE_STARTING,
                    constants.UPGRADE_STARTED,
                    constants.UPGRADE_DATA_MIGRATION,
                    constants.UPGRADE_DATA_MIGRATION_COMPLETE,
                    constants.UPGRADE_DATA_MIGRATION_FAILED]:
                if system_type == constants.TIS_AIO_BUILD:
                    if hostname == constants.CONTROLLER_1_HOSTNAME:
                        # Allow AIO-DX lock of controller-1
                        return
                raise wsme.exc.ClientSideError(
                    _("Rejected: Can not lock %s with worker function "
                      "at this upgrade stage '%s'.") %
                    (hostupdate.displayid, upgrade_state))

            if upgrade_state in [constants.UPGRADE_UPGRADING_CONTROLLERS]:
                if system_type == constants.TIS_AIO_BUILD:
                    # Allow lock for AIO-DX controller-0 after upgrading
                    # controller-1. Allow lock for AIO-DX controllers.
                    if hostname == constants.CONTROLLER_0_HOSTNAME:
                        return
                raise wsme.exc.ClientSideError(
                    _("Rejected: Can not lock %s with worker function "
                      "at this upgrade stage '%s'.") %
                    (hostupdate.displayid, upgrade_state))

        # Worker node with a Ceph Monitor service? Make sure at least
        # two monitors will remain up after lock.
        host_id = hostupdate.ihost_orig.get('id')
        ceph_mon = pecan.request.dbapi.ceph_mon_get_by_ihost(host_id)
        if ceph_mon:
            if (hostupdate.ihost_orig['personality'] ==
                    constants.WORKER and
                    hostupdate.ihost_orig['administrative'] ==
                    constants.ADMIN_UNLOCKED and
                    hostupdate.ihost_orig['operational'] ==
                    constants.OPERATIONAL_ENABLED):
                utils.check_node_lock_ceph_mon(
                    hostupdate.ihost_orig, unsafe=unsafe, ceph_helper=self._ceph)

    def check_unlock_interfaces(self, hostupdate):
        """Semantic check for interfaces on host-unlock."""
        ihost = hostupdate.ihost_patch
        if ihost['personality'] in [constants.CONTROLLER, constants.WORKER,
                                    constants.STORAGE]:

            # Check if there is an management interface on
            # controller/worker/storage
            ihost_iinterfaces = pecan.request.dbapi.iinterface_get_by_ihost(
                ihost['uuid'])
            mgmt_interface_configured = False
            for iif in ihost_iinterfaces:
                if (iif.networktypelist and
                        constants.NETWORK_TYPE_MGMT in iif.networktypelist):
                    mgmt_interface_configured = True
                    break

            if not mgmt_interface_configured:
                msg = _("Cannot unlock host %s "
                        "without configuring a management interface."
                        % hostupdate.displayid)
                raise wsme.exc.ClientSideError(msg)
            else:
                if (iif.iftype == constants.INTERFACE_TYPE_VIRTUAL and
                        not cutils.is_aio_simplex_system(pecan.request.dbapi)):
                    msg = _("Cannot unlock host %s "
                            "when management interface is configured on "
                            "a virtual interface."
                            % hostupdate.displayid)
                    raise wsme.exc.ClientSideError(msg)

            # Check if there is a cluster-host interface on
            # controller/worker/storage
            host_interfaces = pecan.request.dbapi.iinterface_get_by_ihost(
                ihost['uuid'])
            for iif in host_interfaces:
                if (iif.networktypelist and
                        constants.NETWORK_TYPE_CLUSTER_HOST in iif.networktypelist):
                    if (iif.iftype == constants.INTERFACE_TYPE_VIRTUAL and
                            not cutils.is_aio_simplex_system(pecan.request.dbapi)):
                        msg = _("Cannot unlock host %s "
                                "when cluster-host interface is configured on "
                                "a virtual interface."
                                % hostupdate.displayid)
                        raise wsme.exc.ClientSideError(msg)
                    break
            else:
                msg = _("Cannot unlock host %s "
                        "without configuring a cluster-host interface."
                        % hostupdate.displayid)
                raise wsme.exc.ClientSideError(msg)

            # Check if there is an admin network configured
            # Ensure there is an associated interface
            networktype = constants.NETWORK_TYPE_ADMIN
            pools = cutils.get_network_address_pools(pecan.request.dbapi, networktype, True)
            admin_interface_configured = False
            for iif in ihost_iinterfaces:
                if (iif.networktypelist and networktype in iif.networktypelist):
                    admin_interface_configured = True
                    break
            if pools and not admin_interface_configured:
                msg = _("Cannot unlock host %s "
                        "without assigning the admin network to an interface"
                        % hostupdate.displayid)
                raise wsme.exc.ClientSideError(msg)

            hostupdate.configure_required = True

        host_uuid = ihost['uuid']
        # Validate PTP interfaces if PTP is used on this host
        if ihost['clock_synchronization'] == constants.PTP:
            # Ensure we have at least one PTP interface
            host_interfaces = pecan.request.dbapi.iinterface_get_by_ihost(host_uuid)
            ptp_ifaces = []
            for interface in host_interfaces:
                if interface.ptp_role != constants.INTERFACE_PTP_ROLE_NONE:
                    ptp_ifaces.append(interface)

            ptp_instances = pecan.request.dbapi.ptp_instances_get_list(host_uuid)
            if not (ptp_ifaces or ptp_instances):
                raise wsme.exc.ClientSideError(
                    _("Hosts with PTP clock synchronization "
                      "must have at least one PTP "
                      "interface or instance configured"))

            # Check that interfaces have addresses assigned if PTP transport is UDP
            system_ptp = pecan.request.dbapi.ptp_get_one()
            if system_ptp.transport == constants.PTP_TRANSPORT_UDP:
                addresses = pecan.request.dbapi.addresses_get_by_host(host_uuid)
                address_interfaces = set()
                for address in addresses:
                    address_interfaces.add(address.ifname)
                for ptp_if in ptp_ifaces:
                    if ptp_if.ifname not in address_interfaces:
                        raise wsme.exc.ClientSideError(
                            _("All PTP interfaces must have an associated address when PTP transport is UDP"))

    def check_unlock_partitions(self, hostupdate):
        """Semantic check for interfaces on host-unlock."""
        ihost = hostupdate.ihost_patch
        partitions = pecan.request.dbapi.partition_get_by_ihost(ihost['uuid'])

        partition_transitory_states = [
                constants.PARTITION_CREATE_IN_SVC_STATUS,
                constants.PARTITION_DELETING_STATUS,
                constants.PARTITION_MODIFYING_STATUS]

        for part in partitions:
            if part.status in partition_transitory_states:
                msg = _("Cannot unlock host %s "
                        "while partitions on the host are in a "
                        "creating/deleting/modifying state."
                        % hostupdate.displayid)
                raise wsme.exc.ClientSideError(msg)

    @staticmethod
    def unlock_update_mgmt_interface(ihost):
        # MTU Update: Compute and storage nodes get MTU values for
        # management via DHCP. This 'check' updates the 'imtu' value based on
        # what will be served via DHCP.
        if ihost['personality'] in [constants.WORKER, constants.STORAGE]:
            host_list = pecan.request.dbapi.ihost_get_by_personality(
                personality=constants.CONTROLLER)
            interface_list_active = []
            for h in host_list:
                if utils.is_host_active_controller(h):
                    interface_list_active = \
                        pecan.request.dbapi.iinterface_get_all(h.id)
                    break

            ihost_iinterfaces = \
                pecan.request.dbapi.iinterface_get_by_ihost(ihost['uuid'])

            # updated management interfaces
            idata = {}
            for iif in ihost_iinterfaces:
                if constants.NETWORK_TYPE_MGMT in iif.networktypelist:
                    for ila in interface_list_active:
                        if constants.NETWORK_TYPE_MGMT in ila.networktypelist:
                            idata['imtu'] = ila.imtu
                            pecan.request.dbapi.iinterface_update(iif.uuid, idata)
                            break

    def stage_action(self, action, hostupdate):
        """ Stage the action to be performed.
        """
        LOG.info("%s stage_action %s" % (hostupdate.displayid, action))
        rc = True
        if not action or (action and
           action.lower() == constants.NONE_ACTION):
            LOG.error("Unrecognized action perform: %s" % action)
            return False

        if (action == constants.UNLOCK_ACTION or
           action == constants.FORCE_UNLOCK_ACTION):
            self._handle_unlock_action(hostupdate)
        elif action == constants.LOCK_ACTION:
            self._handle_lock_action(hostupdate)
        elif action == constants.FORCE_LOCK_ACTION:
            self._handle_force_lock_action(hostupdate)
        elif action == constants.FORCE_UNSAFE_LOCK_ACTION:
            self._handle_force_unsafe_lock_action(hostupdate)
        elif action == constants.SWACT_ACTION:
            self._stage_swact(hostupdate)
        elif action == constants.FORCE_SWACT_ACTION:
            self._stage_force_swact(hostupdate)
        elif action == constants.REBOOT_ACTION:
            self._stage_reboot(hostupdate)
        elif action == constants.RESET_ACTION:
            self._stage_reset(hostupdate)
        elif action == constants.REINSTALL_ACTION:
            self._stage_reinstall(hostupdate)
        elif action == constants.POWERON_ACTION:
            self._stage_poweron(hostupdate)
        elif action == constants.POWEROFF_ACTION:
            self._stage_poweroff(hostupdate)
        elif action == constants.VIM_SERVICES_ENABLED:
            self._handle_vim_services_enabled(hostupdate)
        elif action == constants.VIM_SERVICES_DISABLED:
            if not self._handle_vim_services_disabled(hostupdate):
                LOG.warn(_("%s Exit _handle_vim_services_disabled" %
                         hostupdate.ihost_patch['hostname']))
                hostupdate.nextstep = hostupdate.EXIT_RETURN_HOST
                rc = False
        elif action == constants.VIM_SERVICES_DISABLE_FAILED:
            if not self._handle_vim_services_disable_failed(hostupdate):
                LOG.warn(_("%s Exit _handle_vim_services_disable failed" %
                         hostupdate.ihost_patch['hostname']))
                hostupdate.nextstep = hostupdate.EXIT_RETURN_HOST
                rc = False
        elif action == constants.VIM_SERVICES_DISABLE_EXTEND:
            self._handle_vim_services_disable_extend(hostupdate)
            hostupdate.nextstep = hostupdate.EXIT_UPDATE_PREVAL
            rc = False
        elif action == constants.VIM_SERVICES_DELETE_FAILED:
            self._handle_vim_services_delete_failed(hostupdate)
            hostupdate.nextstep = hostupdate.EXIT_UPDATE_PREVAL
            rc = False
        elif action == constants.SUBFUNCTION_CONFIG_ACTION:
            # Not a mtc action; disable mtc checks and config
            self._stage_subfunction_config(hostupdate)
        else:
            # TODO: raise wsme
            LOG.error("%s Unrecognized action perform: %s" %
                      (hostupdate.displayid, action))
            rc = False

        if hostupdate.nextstep == hostupdate.EXIT_RETURN_HOST:
            LOG.info("%s stage_action aborting request %s %s" %
                     (hostupdate.displayid,
                      hostupdate.action,
                      hostupdate.delta))

        return rc

    @staticmethod
    def _check_subfunction_config(hostupdate):
        """Check subfunction config."""
        LOG.info("%s _check_subfunction_config" % hostupdate.displayid)
        patched_ihost = hostupdate.ihost_patch

        if patched_ihost['action'] == "subfunction_config":
            if not patched_ihost['subfunctions'] or \
               patched_ihost['personality'] == patched_ihost['subfunctions']:
                raise wsme.exc.ClientSideError(
                    _("This host is not configured with a subfunction."))

        return True

    @staticmethod
    def _stage_subfunction_config(hostupdate):
        """Stage subfunction config."""
        LOG.info("%s _stage_subfunction_config" % hostupdate.displayid)

        hostupdate.notify_mtce = False
        hostupdate.skip_notify_mtce = True

    @staticmethod
    def perform_action_subfunction_config(ihost_obj):
        """Perform subfunction config via RPC to conductor."""
        LOG.info("%s perform_action_subfunction_config" %
                 ihost_obj['hostname'])
        pecan.request.rpcapi.configure_ihost(pecan.request.context,
                                             ihost_obj,
                                             do_worker_apply=True)

    @staticmethod
    def _stage_reboot(hostupdate):
        """Stage reboot action."""
        LOG.info("%s stage_reboot" % hostupdate.displayid)
        hostupdate.notify_mtce = True

    def _stage_reinstall(self, hostupdate):
        """Stage reinstall action."""
        LOG.info("%s stage_reinstall" % hostupdate.displayid)

        # Remove manifests to enable standard install without manifests
        # and enable storage allocation change
        pecan.request.rpcapi.remove_host_config(
            pecan.request.context,
            hostupdate.ihost_orig['uuid'])

        # Remove IPSec flag to allow a new configuration after reinstall
        capabilities = hostupdate.ihost_orig['capabilities']
        if capabilities.get(constants.MGMT_IPSEC_FLAG) is not None:
            capabilities.pop(constants.MGMT_IPSEC_FLAG)
            hostupdate.ihost_val_update({'capabilities': capabilities})

        hostupdate.notify_mtce = True

        if hostupdate.ihost_orig['personality'] == constants.STORAGE:
            istors = pecan.request.dbapi.istor_get_by_ihost(hostupdate.ihost_orig['uuid'])

            for stor in istors:
                istor_obj = objects.storage.get_by_uuid(
                                    pecan.request.context, stor.uuid)
                self._ceph.remove_osd_key(istor_obj['osdid'])
        else:
            has_ceph_rook_backend = StorageBackendConfig.has_backend(
                pecan.request.dbapi,
                target=constants.SB_TYPE_CEPH_ROOK
            )

            if has_ceph_rook_backend:
                istors = pecan.request.dbapi.istor_get_by_ihost(
                                                hostupdate.ihost_orig['uuid'])
                for stor in istors:
                    istor_obj = objects.storage.get_by_uuid(
                                        pecan.request.context, stor.uuid)
                    istor_values = {'state': constants.SB_STATE_CONFIGURING_WITH_APP}
                    pecan.request.dbapi.istor_update(istor_obj['uuid'], istor_values)

        hostupdate.ihost_val_update(
            {
                constants.HOST_ACTION_STATE: constants.HAS_REINSTALLING,
                'inv_state': constants.INV_STATE_REINSTALLING
            })

    @staticmethod
    def _stage_poweron(hostupdate):
        """Stage poweron action."""
        LOG.info("%s stage_poweron" % hostupdate.displayid)
        hostupdate.notify_mtce = True

    @staticmethod
    def _stage_poweroff(hostupdate):
        """Stage poweroff action."""
        LOG.info("%s stage_poweroff" % hostupdate.displayid)
        hostupdate.notify_mtce = True

    @staticmethod
    def _stage_swact(hostupdate):
        """Stage swact action."""
        LOG.info("%s stage_swact" % hostupdate.displayid)
        hostupdate.notify_mtce = True

    @staticmethod
    def _stage_force_swact(hostupdate):
        """Stage force-swact action."""
        LOG.info("%s stage_force_swact" % hostupdate.displayid)
        hostupdate.notify_mtce = True

    @staticmethod
    def _handle_vim_services_enabled(hostupdate):
        """Handle VIM services-enabled signal."""
        vim_progress_status = (hostupdate.ihost_orig.get('vim_progress_status') or "")
        LOG.info("%s received services-enabled task=%s vim_progress_status=%s"
                 % (hostupdate.displayid,
                    hostupdate.ihost_orig['task'],
                    vim_progress_status))

        if (not vim_progress_status or
           not vim_progress_status.startswith(constants.VIM_SERVICES_ENABLED)):
            hostupdate.notify_availability = constants.VIM_SERVICES_ENABLED
            if (not vim_progress_status or
               vim_progress_status == constants.VIM_SERVICES_DISABLED):
                # otherwise allow the audit to clear the error message
                hostupdate.ihost_val_update({'vim_progress_status':
                                             constants.VIM_SERVICES_ENABLED})

        hostupdate.skip_notify_mtce = True

    @staticmethod
    def _handle_vim_services_disabled(hostupdate):
        """Handle VIM services-disabled signal."""

        LOG.info("%s _handle_vim_services_disabled'" % hostupdate.displayid)
        ihost = hostupdate.ihost_orig

        hostupdate.ihost_val_update(
            {'vim_progress_status': constants.VIM_SERVICES_DISABLED})

        ihost_task_string = ihost['ihost_action'] or ""
        if ((ihost_task_string.startswith(constants.LOCK_ACTION) or
           ihost_task_string.startswith(constants.FORCE_LOCK_ACTION) or
           ihost_task_string.startswith(constants.FORCE_UNSAFE_LOCK_ACTION)) and
           ihost['administrative'] != constants.ADMIN_LOCKED):
            # passed - skip reset for force-lock
            # iHost['ihost_action'] = constants.LOCK_ACTION
            hostupdate.notify_availability = constants.VIM_SERVICES_DISABLED
            hostupdate.notify_action_lock = True
            hostupdate.notify_mtce = True
        else:
            # return False rather than failing request.
            LOG.warn(_("%s Admin action task not Locking or Force Locking "
                       "upon receipt of 'services-disabled'." %
                       hostupdate.displayid))
            hostupdate.skip_notify_mtce = True
            return False

        return True

    @staticmethod
    def _handle_vim_services_disable_extend(hostupdate):
        """Handle VIM services-disable-extend signal."""

        ihost_action = hostupdate.ihost_orig['ihost_action'] or ""
        result_reason = hostupdate.ihost_patch.get('vim_progress_status') or ""
        LOG.info("%s handle_vim_services_disable_extend ihost_action=%s reason=%s" %
                 (hostupdate.displayid, ihost_action, result_reason))

        hostupdate.skip_notify_mtce = True
        if ihost_action.startswith(constants.LOCK_ACTION):
            val = {'task': constants.LOCKING + '-',
                   'ihost_action': constants.LOCK_ACTION}
            hostupdate.ihost_val_prenotify_update(val)
        else:
            LOG.warn("%s Skip vim services disable extend ihost action=%s" %
                     (hostupdate.displayid, ihost_action))
            return False

        # If the VIM updates vim_progress_status, could post:
        # if result_reason:
        #     hostupdate.ihost_val_prenotify_update({'vim_progress_status':
        #                                           result_reason})
        # else:
        #     hostupdate.ihost_val_prenotify_update(
        #         {'vim_progress_status': constants.VIM_SERVICES_DELETE_FAILED})

        LOG.info("services-disable-extend reason=%s" % result_reason)
        return True

    @staticmethod
    def _handle_vim_services_disable_failed(hostupdate):
        """Handle VIM services-disable-failed signal."""
        ihost_task_string = hostupdate.ihost_orig['ihost_action'] or ""
        LOG.info("%s handle_vim_services_disable_failed ihost_action=%s" %
                 (hostupdate.displayid, ihost_task_string))

        result_reason = hostupdate.ihost_patch.get('vim_progress_status') or ""

        if ihost_task_string.startswith(constants.LOCK_ACTION):
            hostupdate.skip_notify_mtce = True
            val = {'ihost_action': '',
                   'task': '',
                   'vim_progress_status': result_reason}
            hostupdate.ihost_val_prenotify_update(val)
            hostupdate.ihost_val.update(val)
            hostupdate.skip_notify_mtce = True
        elif ihost_task_string.startswith(constants.FORCE_LOCK_ACTION):
            # allow mtce to reset the host
            hostupdate.notify_mtce = True
            hostupdate.notify_action_lock_force = True
        elif ihost_task_string.startswith(constants.FORCE_UNSAFE_LOCK_ACTION):
            # allow mtce to reset the host
            hostupdate.notify_mtce = True
            hostupdate.notify_action_lock_force_unsafe = True
        else:
            hostupdate.skip_notify_mtce = True
            LOG.warn("%s Skipping vim services disable notification task=%s" %
                     (hostupdate.displayid, ihost_task_string))
            return False

        if result_reason:
            LOG.info("services-disable-failed reason=%s" % result_reason)
            hostupdate.ihost_val_update({'vim_progress_status':
                                        result_reason})
        else:
            hostupdate.ihost_val_update({'vim_progress_status':
                                        constants.VIM_SERVICES_DISABLE_FAILED})

        return True

    @staticmethod
    def _handle_vim_services_delete_failed(hostupdate):
        """Handle VIM services-delete-failed signal."""

        ihost_admin = hostupdate.ihost_orig['administrative'] or ""
        result_reason = hostupdate.ihost_patch.get('vim_progress_status') or ""
        LOG.info("%s handle_vim_services_delete_failed admin=%s reason=%s" %
                 (hostupdate.displayid, ihost_admin, result_reason))

        hostupdate.skip_notify_mtce = True
        if ihost_admin.startswith(constants.ADMIN_LOCKED):
            val = {'ihost_action': '',
                   'task': '',
                   'vim_progress_status': result_reason}
            hostupdate.ihost_val_prenotify_update(val)
            # hostupdate.ihost_val.update(val)
        else:
            LOG.warn("%s Skip vim services delete failed notify admin=%s" %
                     (hostupdate.displayid, ihost_admin))
            return False

        if result_reason:
            hostupdate.ihost_val_prenotify_update({'vim_progress_status':
                                                  result_reason})
        else:
            hostupdate.ihost_val_prenotify_update(
                {'vim_progress_status': constants.VIM_SERVICES_DELETE_FAILED})

        LOG.info("services-disable-failed reason=%s" % result_reason)
        return True

    @staticmethod
    def _stage_reset(hostupdate):
        """Handle host-reset action."""
        LOG.info("%s _stage_reset" % hostupdate.displayid)

        hostupdate.notify_mtce = True

    def _handle_unlock_action(self, hostupdate):
        """Handle host-unlock action."""
        LOG.info("%s _handle_unlock_action" % hostupdate.displayid)
        if hostupdate.ihost_patch.get('personality') == constants.STORAGE:
            self._handle_unlock_storage_host(hostupdate)
        elif hostupdate.ihost_patch.get('personality') == constants.WORKER:
            self._handle_unlock_worker_host(hostupdate)
        hostupdate.notify_vim_action = False
        hostupdate.notify_mtce = True
        val = {'ihost_action': constants.UNLOCK_ACTION}
        hostupdate.ihost_val_prenotify_update(val)
        hostupdate.ihost_val.update(val)

    def _handle_unlock_storage_host(self, hostupdate):
        self._ceph.update_crushmap(hostupdate)

    def _handle_unlock_worker_host(self, hostupdate):
        # Update crushmap if we unlocked the worker with a ceph monitor.
        monitor_list = pecan.request.dbapi.ceph_mon_get_list()
        for mon in monitor_list:
            ihost = pecan.request.dbapi.ihost_get(mon['forihostid'])
            if ihost.id == hostupdate.ihost_orig['id']:
                self._ceph.update_crushmap(hostupdate)

    @staticmethod
    def _handle_lock_action(hostupdate):
        """Handle host-lock action."""
        LOG.info("%s _handle_lock_action" % hostupdate.displayid)

        hostupdate.notify_vim_action = True
        hostupdate.skip_notify_mtce = True
        val = {'ihost_action': constants.LOCK_ACTION}
        hostupdate.ihost_val_prenotify_update(val)
        hostupdate.ihost_val.update(val)

    @staticmethod
    def _handle_force_lock_action(hostupdate):
        """Handle host-force-lock action."""
        LOG.info("%s _handle_force_lock_action" % hostupdate.displayid)

        hostupdate.notify_vim_action = True
        hostupdate.skip_notify_mtce = True
        val = {'ihost_action': constants.FORCE_LOCK_ACTION}
        hostupdate.ihost_val_prenotify_update(val)
        hostupdate.ihost_val.update(val)

    @staticmethod
    def _handle_force_unsafe_lock_action(hostupdate):
        """Handle host-force-unsafe-lock action."""
        LOG.info("%s _handle_force_unsafe_lock_action" % hostupdate.displayid)

        hostupdate.notify_vim_action = True
        hostupdate.skip_notify_mtce = True
        val = {'ihost_action': constants.FORCE_UNSAFE_LOCK_ACTION}
        hostupdate.ihost_val_prenotify_update(val)
        hostupdate.ihost_val.update(val)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Host, six.text_type, body=six.text_type)
    def kube_upgrade_control_plane(self, uuid, body):
        """Upgrade the kubernetes control plane on this host"""

        host_obj = objects.host.get_by_uuid(pecan.request.context, uuid)
        kube_host_upgrade_obj = objects.kube_host_upgrade.get_by_host_id(
            pecan.request.context, host_obj.id)
        system = pecan.request.dbapi.isystem_get_one()

        # The kubernetes upgrade must have been started
        try:
            kube_upgrade_obj = objects.kube_upgrade.get_one(
                pecan.request.context)
        except exception.NotFound:
            raise wsme.exc.ClientSideError(_(
                "A kubernetes upgrade is not in progress."))

        LOG.info("Attempting to upgrade control plane on host %s while in "
                 "state %s" % (host_obj.hostname, kube_upgrade_obj.state))

        # Either controller can be upgraded
        if host_obj.personality != constants.CONTROLLER:
            raise wsme.exc.ClientSideError(_(
                "This host does not have a kubernetes control plane."))

        cp_versions = self._kube_operator.kube_get_control_plane_versions()
        cp_version = cp_versions.get(host_obj.hostname)
        kubelet_versions = self._kube_operator.kube_get_kubelet_versions()
        kubelet_version = kubelet_versions.get(host_obj.hostname)

        if cp_version is None:
            raise wsme.exc.ClientSideError(_(
                "Unable to determine the version of the control plane."))
        if kubelet_version is None:
            raise wsme.exc.ClientSideError(_(
                "Unable to determine the version of kubelet."))

        # Determine whether this is first control-plane being upgraded
        is_first = False
        if all(LooseVersion(cp_version) >= LooseVersion(ver)
                for ver in cp_versions.values()):
            is_first = True

        # Determine target control-plane version for this host
        cp_versions_next = self._kube_operator.kube_get_higher_patch_version(
            cp_version, kube_upgrade_obj.to_version)
        if cp_versions_next:
            target_version = cp_versions_next[0]
            kubeadm_version = target_version
        else:
            target_version = None
            kubeadm_version = None

        if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
            check_upgraded_state = [
                kubernetes.KUBE_UPGRADED_STORAGE,
                kubernetes.KUBE_UPGRADED_FIRST_MASTER,
                kubernetes.KUBE_UPGRADE_CORDON_COMPLETE]
        else:
            check_upgraded_state = [
                kubernetes.KUBE_UPGRADED_STORAGE,
                kubernetes.KUBE_UPGRADED_FIRST_MASTER,
                kubernetes.KUBE_UPGRADED_SECOND_MASTER]

        # Verify the upgrade is in the correct state
        if kube_upgrade_obj.state in check_upgraded_state:
            # We are upgrading a control plane
            pass
        elif kube_upgrade_obj.state == kubernetes.KUBE_UPGRADING_KUBELETS and \
                cp_version != kube_upgrade_obj.to_version:
            pass
        elif kube_upgrade_obj.state == kubernetes.KUBE_UPGRADING_KUBELETS and \
                cp_version == kube_upgrade_obj.to_version:
            raise wsme.exc.ClientSideError(_(
                    "The control plane is already running the target version."))
        elif kube_upgrade_obj.state in [
                kubernetes.KUBE_UPGRADING_FIRST_MASTER_FAILED,
                kubernetes.KUBE_UPGRADING_SECOND_MASTER_FAILED]:
            # We are re-attempting the upgrade of a control plane. Make sure
            # this really is a re-attempt.
            if kube_host_upgrade_obj.target_version != \
                        kube_upgrade_obj.to_version and \
                        system.system_mode != constants.SYSTEM_MODE_SIMPLEX:
                raise wsme.exc.ClientSideError(_(
                    "The first control plane upgrade must be completed before "
                    "upgrading the second control plane."))
        else:
            raise wsme.exc.ClientSideError(_(
                "The kubernetes upgrade is not in a valid state to "
                "upgrade the control plane."))

        # Enforce Kubernetes Skew Policy. This prevents unsupported advancement
        # of control-plane if any nodes are not current enough.

        # Evaluate kubelet version skew for each K8S node.
        # Example:  If current kubelet is at 1.29, current kubeadm is at 1.32,
        # then the minor version skew is 3 (i.e., 32 - 29). We prevent the kubeadm
        # upgrade to 1.33 since the resulting upgrade would have skew of 4.
        if cp_version != kube_upgrade_obj.to_version:
            if kube_host_upgrade_obj.status != kubernetes.KUBE_HOST_UPGRADED_KUBELET:
                old_hosts = []
                for host, kubelet_version in kubelet_versions.items():
                    kubelet_skew = self._kube_operator.kubelet_version_skew(
                        kubeadm_version, kubelet_version)
                    if kubelet_skew > kubernetes.KUBELET_MINOR_SKEW_TOLERANCE:
                        LOG.error("Kubernetes minor version skew %d exceeds %d tolerance. "
                                  "kubelet upgrade on %s is mandatory."
                                  % (kubelet_skew, kubernetes.KUBELET_MINOR_SKEW_TOLERANCE, host))
                        old_hosts.append(host)
                if old_hosts:
                    raise wsme.exc.ClientSideError(_(
                        "Update kubelet on %s before updating control plane "
                        "again." % old_hosts))

            # Infer whether this is first control-plane being upgraded
            is_first = False
            if all(LooseVersion(cp_version) >= LooseVersion(ver)
                    for ver in cp_versions.values()):
                is_first = True

            # Evaluate control-plane version skew. Prevent kubeadm upgrade of
            # first master unless all control-planes are the same version.
            # The client and server will exceed minor version skew of +/- 1.
            all_equal = len(set(cp_versions.values())) == 1
            if is_first and not all_equal:
                LOG.error("Kubernetes minor version skew exceeds +/-1 tolerance. "
                          "second control-plane upgrade %s is mandatory.")
                raise wsme.exc.ClientSideError(_(
                    "Update second control-plane before updating first "
                    "control plane again."))

        # Check the existing control plane version
        if cp_version == kube_upgrade_obj.to_version:
            # Make sure we are not attempting to upgrade the first upgraded
            # control plane again
            if kube_upgrade_obj.state == kubernetes.KUBE_UPGRADED_FIRST_MASTER:
                raise wsme.exc.ClientSideError(_(
                    "The first control plane was already upgraded."))

            # The control plane was already upgraded, but we didn't progress
            # to the next state, so something failed along the way.
            LOG.info("Redoing kubernetes control plane upgrade for %s" %
                     host_obj.hostname)
        elif cp_version is None:
            raise wsme.exc.ClientSideError(_(
                "Unable to determine the version of the kubernetes control "
                "plane on this host."))

        # The host must be unlocked/available to upgrade the control plane
        if (host_obj.administrative != constants.ADMIN_UNLOCKED or
                host_obj.operational != constants.OPERATIONAL_ENABLED):
            raise wsme.exc.ClientSideError(_(
                "The host must be unlocked and available to upgrade the "
                "control plane."))

        # Verify the control plane is not being upgraded
        if kube_host_upgrade_obj.status == \
                kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE:
            raise wsme.exc.ClientSideError(_(
                "The control plane on this host is already being upgraded."))

        # Update the target version for this host
        kube_host_upgrade_obj.target_version = kube_upgrade_obj.to_version

        # Set the status
        kube_host_upgrade_obj.status = \
            kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE
        kube_host_upgrade_obj.save()

        if kube_upgrade_obj.state in [
                kubernetes.KUBE_UPGRADED_STORAGE,
                kubernetes.KUBE_UPGRADED_FIRST_MASTER,
                kubernetes.KUBE_UPGRADING_FIRST_MASTER_FAILED,
                kubernetes.KUBE_UPGRADED_SECOND_MASTER,
                kubernetes.KUBE_UPGRADING_SECOND_MASTER_FAILED,
                kubernetes.KUBE_UPGRADE_CORDON_COMPLETE] and is_first:
            # Update the upgrade state
            kube_upgrade_obj.state = kubernetes.KUBE_UPGRADING_FIRST_MASTER
            kube_upgrade_obj.save()

            # Tell the conductor to upgrade the control plane
            pecan.request.rpcapi.kube_upgrade_control_plane(
                pecan.request.context, host_obj.uuid)
        elif kube_upgrade_obj.state == kubernetes.KUBE_UPGRADING_KUBELETS and \
                cp_version != kube_upgrade_obj.to_version:
            LOG.info("In state upgrading kubelets, kubelet version %s, transitioning to "
                     "upgrading control plane, current control plane version %s, "
                     "target version %s." % (kubelet_version, cp_version,
                                            target_version))
            kube_upgrade_obj.state = kubernetes.KUBE_UPGRADING_FIRST_MASTER
            kube_upgrade_obj.save()
            kube_host_upgrade_obj.status = kubernetes.KUBE_HOST_UPGRADING_CONTROL_PLANE
            kube_host_upgrade_obj.save()

            # Tell the conductor to upgrade the control plane
            pecan.request.rpcapi.kube_upgrade_control_plane(
                pecan.request.context, host_obj.uuid)
        else:
            # Update the upgrade state
            kube_upgrade_obj.state = kubernetes.KUBE_UPGRADING_SECOND_MASTER
            kube_upgrade_obj.save()

            # Tell the conductor to upgrade the control plane
            pecan.request.rpcapi.kube_upgrade_control_plane(
                pecan.request.context, host_obj.uuid)

        LOG.info("Upgrading kubernetes control plane on host %s" %
                 host_obj.hostname)
        return Host.convert_with_links(host_obj)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Host, six.text_type, body=six.text_type)
    def kube_upgrade_kubelet(self, uuid, body):
        """Upgrade the kubernetes kubelet on this host"""

        force = body.get('force', False) is True
        host_obj = objects.host.get_by_uuid(pecan.request.context, uuid)

        # The kubernetes upgrade must have been started
        try:
            kube_upgrade_obj = objects.kube_upgrade.get_one(
                pecan.request.context)
        except exception.NotFound:
            raise wsme.exc.ClientSideError(_(
                "A kubernetes upgrade is not in progress."))

        LOG.info("Attempting to upgrade kubelet on host %s while in "
                 "state %s" % (host_obj.hostname, kube_upgrade_obj.state))

        # Verify the host has a kubelet
        if host_obj.personality not in [constants.CONTROLLER,
                                        constants.WORKER]:
            raise wsme.exc.ClientSideError(_(
                "This host does not have a kubelet."))

        # Verify the upgrade is in the correct state
        if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
            if kube_upgrade_obj.state not in [
                    kubernetes.KUBE_UPGRADED_FIRST_MASTER,
                    kubernetes.KUBE_UPGRADING_KUBELETS]:
                raise wsme.exc.ClientSideError(_(
                    "The kubernetes upgrade must be in the %s or %s state to "
                    "upgrade the kubelet." % (
                        kubernetes.KUBE_UPGRADED_FIRST_MASTER,
                        kubernetes.KUBE_UPGRADING_KUBELETS)))
        elif kube_upgrade_obj.state not in [
                kubernetes.KUBE_UPGRADED_SECOND_MASTER,
                kubernetes.KUBE_UPGRADING_KUBELETS]:
            raise wsme.exc.ClientSideError(_(
                "The kubernetes upgrade must be in the %s or %s state to "
                "upgrade the kubelet." % (
                    kubernetes.KUBE_UPGRADED_SECOND_MASTER,
                    kubernetes.KUBE_UPGRADING_KUBELETS)))

        # Enforce that kubelets on control-plane nodes are upgraded first
        cp_versions = self._kube_operator.kube_get_control_plane_versions()
        kubelet_versions = self._kube_operator.kube_get_kubelet_versions()
        if host_obj.personality == constants.WORKER:
            for host, version in cp_versions.items():
                if version != kubelet_versions.get(host):
                    raise wsme.exc.ClientSideError(_(
                        "The kubelets on all controller hosts must be upgraded "
                        "before upgrading kubelets on worker hosts."))

        # Check whether this host was already upgraded
        kube_host_upgrade_obj = objects.kube_host_upgrade.get_by_host_id(
            pecan.request.context, host_obj.id)
        if kube_host_upgrade_obj.target_version == kube_upgrade_obj.to_version:
            # Check the existing kubelet version
            kubelet_version = kubelet_versions.get(host_obj.hostname)
            if kubelet_version == kube_upgrade_obj.to_version:
                # If the force option was used, we will redo the upgrade
                if force:
                    LOG.info("Redoing kubelet upgrade for %s" %
                             host_obj.hostname)
                else:
                    # Set the status
                    kube_host_upgrade_obj.status = kubernetes.KUBE_HOST_UPGRADED_KUBELET
                    kube_host_upgrade_obj.save()
                    LOG.info("Upgraded kubernetes kubelet on host %s" %
                            host_obj.hostname)
                    return Host.convert_with_links(host_obj)
            elif kubelet_version is None:
                raise wsme.exc.ClientSideError(_(
                    "Unable to determine the version of the kubelet on this "
                    "host."))

        # Verify the host is in the correct state
        if utils.get_system_mode() == constants.SYSTEM_MODE_SIMPLEX:
            if (host_obj.administrative != constants.ADMIN_UNLOCKED or
                    host_obj.availability != constants.AVAILABILITY_AVAILABLE) and not force:
                raise wsme.exc.ClientSideError(_(
                    "The host must be unlocked and available to upgrade the "
                    "kubelet."))
        elif (host_obj.administrative != constants.ADMIN_LOCKED or
                host_obj.availability != constants.AVAILABILITY_ONLINE):
            raise wsme.exc.ClientSideError(_(
                "The host must be locked and online to upgrade the kubelet."))

        # Verify the kubelet is not being upgraded
        if kube_host_upgrade_obj.status == \
                kubernetes.KUBE_HOST_UPGRADING_KUBELET:
            raise wsme.exc.ClientSideError(_(
                "The kubelet on this host is already being upgraded."))

        # Set the target version of worker host to match the controller
        # control-plane version
        if host_obj.personality == constants.WORKER:
            kube_host_upgrade_obj.target_version = list(cp_versions.values())[0]

        # Set the status
        kube_host_upgrade_obj.status = kubernetes.KUBE_HOST_UPGRADING_KUBELET
        kube_host_upgrade_obj.save()

        # Tell the conductor to upgrade the kubelet
        pecan.request.rpcapi.kube_upgrade_kubelet(pecan.request.context,
                                                  host_obj.uuid)

        # Update the upgrade state if necessary
        if kube_upgrade_obj.state != kubernetes.KUBE_UPGRADING_KUBELETS:
            kube_upgrade_obj.state = kubernetes.KUBE_UPGRADING_KUBELETS
            kube_upgrade_obj.save()

        LOG.info("Upgrading kubernetes kubelet on host %s" %
                 host_obj.hostname)
        return Host.convert_with_links(host_obj)

    # POST ihosts/<uuid>/device_image_update
    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Host, types.uuid)
    def device_image_update(self, host_uuid):
        """ Update device image on the specified host.
            :param host_uuid: UUID of the host
        """
        LOG.info("device_image_update host_uuid=%s " % host_uuid)
        host_obj = objects.host.get_by_uuid(pecan.request.context, host_uuid)

        if host_obj.device_image_update == device.DEVICE_IMAGE_UPDATE_IN_PROGRESS:
            raise wsme.exc.ClientSideError(_(
                "The host %s is already in the process of updating the "
                "device images." % host_obj.hostname))

        # The host must be unlocked/enabled to update device images
        if (host_obj.administrative != constants.ADMIN_UNLOCKED or
                host_obj.operational != constants.OPERATIONAL_ENABLED):
            raise wsme.exc.ClientSideError(_(
                "The host %s must be unlocked and enabled to update the "
                "device images." % host_obj.hostname))

        # Call rpcapi to tell conductor to begin device image update
        pecan.request.rpcapi.host_device_image_update(
            pecan.request.context, host_uuid)
        return Host.convert_with_links(host_obj)

    # POST ihosts/<uuid>/device_image_update_abort
    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Host, types.uuid)
    def device_image_update_abort(self, host_uuid):
        """ Abort device image update on the specified host.
            :param host_uuid: UUID of the host
            :param install_uuid: install_uuid.
        """
        LOG.info("device_image_update_abort host_uuid=%s " % host_uuid)
        host_obj = objects.host.get_by_uuid(pecan.request.context, host_uuid)

        if host_obj.device_image_update != device.DEVICE_IMAGE_UPDATE_IN_PROGRESS:
            raise wsme.exc.ClientSideError(_(
                "Abort rejected. The host %s is not in the process of "
                "updating the device images." % host_obj.hostname))

        # Call rpcapi to tell conductor to abort device image update
        pecan.request.rpcapi.host_device_image_update_abort(
            pecan.request.context, host_uuid)
        return Host.convert_with_links(host_obj)

    def enforce_policy(self, method_name, request):
        """Check policy rules for each action of this controller."""
        context_dict = request.context.to_dict()
        if method_name in ["get_all", "get_one"]:
            policy.authorize(ihosts_policy.POLICY_ROOT % "get", {}, context_dict)
        elif method_name in ["delete", "patch", "post"]:
            policy.authorize(ihosts_policy.POLICY_ROOT % method_name, {}, context_dict)
        elif method_name in self._custom_actions:
            request_method = self._custom_actions[method_name][0].lower()
            policy.authorize(ihosts_policy.POLICY_ROOT % request_method, {},
                             context_dict)
        else:
            raise exception.PolicyNotFound()


def _create_node(host, xml_node, personality, is_dynamic_ip):
    host_node = et.SubElement(xml_node, 'host')
    et.SubElement(host_node, 'personality').text = personality
    if personality == constants.WORKER:
        et.SubElement(host_node, 'hostname').text = host.hostname
        et.SubElement(host_node, 'subfunctions').text = host.subfunctions

    et.SubElement(host_node, 'mgmt_mac').text = host.mgmt_mac
    if not is_dynamic_ip:
        et.SubElement(host_node, 'mgmt_ip').text = host.mgmt_ip
    if host.location is not None and 'locn' in host.location:
        et.SubElement(host_node, 'location').text = host.location['locn']

    pw_on_instruction = _('Uncomment the statement below to power on the host '
                          'automatically through board management.')
    host_node.append(et.Comment(pw_on_instruction))
    host_node.append(et.Comment('<power_on />'))
    et.SubElement(host_node, 'bm_type').text = host.bm_type
    et.SubElement(host_node, 'bm_username').text = host.bm_username
    et.SubElement(host_node, 'bm_password').text = ''

    et.SubElement(host_node, 'boot_device').text = host.boot_device
    et.SubElement(host_node, 'rootfs_device').text = host.rootfs_device
    et.SubElement(host_node, 'hw_settle').text = host.hw_settle
    et.SubElement(host_node, 'install_output').text = host.install_output
    if host.vsc_controllers is not None:
        et.SubElement(host_node, 'vsc_controllers').text = host.vsc_controllers
    et.SubElement(host_node, 'console').text = host.console
    et.SubElement(host_node, 'tboot').text = host.tboot
