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
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#


import six
import jsonpatch
import pecan
import wsme
import wsmeext.pecan as wsme_pecan
from oslo_config import cfg
from pecan import expose
from pecan import rest
from sysinv import objects
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import cpu as cpu_api
from sysinv.api.controllers.v1 import disk as disk_api
from sysinv.api.controllers.v1 import partition as partition_api
from sysinv.api.controllers.v1 import interface as interface_api
from sysinv.api.controllers.v1 import interface_network as ifnet_api
from sysinv.api.controllers.v1 import memory as memory_api
from sysinv.api.controllers.v1 import node as node_api
from sysinv.api.controllers.v1 import storage as storage_api
from sysinv.api.controllers.v1 import lvg as lvg_api
from sysinv.api.controllers.v1 import pv as pv_api
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1 import utils
from sysinv.api.controllers.v1 import cpu_utils
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import port as port_api
from sysinv.api.controllers.v1 import ethernet_port as ethernet_port_api
from sysinv.common import ceph
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.openstack.common import log
import xml.etree.ElementTree as et
from lxml import etree
from sysinv.api.controllers.v1 import profile_utils
from sysinv.openstack.common.db import exception as dbException
from sysinv.openstack.common.gettextutils import _
from wsme import types as wtypes
from sysinv.common.storage_backend_conf import StorageBackendConfig

LOG = log.getLogger(__name__)

CONF = cfg.CONF
CONF.import_opt('journal_min_size',
                'sysinv.api.controllers.v1.storage',
                group='journal')
CONF.import_opt('journal_max_size',
                'sysinv.api.controllers.v1.storage',
                group='journal')
CONF.import_opt('journal_default_size',
                'sysinv.api.controllers.v1.storage',
                group='journal')

# Defines the fields that must be copied in/out of interface profiles
INTERFACE_PROFILE_FIELDS = ['ifname', 'iftype', 'imtu', 'networktype',
                            'ifclass', 'aemode', 'networks',
                            'txhashpolicy', 'forihostid', 'datanetworks',
                            'vlan_id', 'ipv4_mode', 'ipv6_mode',
                            'ipv4_pool', 'ipv6_pool',
                            'sriov_numvfs', 'sriov_vf_driver']


class Profile(base.APIBase):
    """API representation of a host profile.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation
    of an ihost.
    """

    _ihost_uuid = None
    _profilename = None

    def _get_ihost_uuid(self):
        return self._ihost_uuid

    def _set_ihost_uuid(self, value):
        if value and self._ihost_uuid != value:
            try:
                ihost = objects.host.get_by_uuid(pecan.request.context, value)
                self._ihost_uuid = ihost.uuid
                # NOTE(lucasagomes): Create the node_id attribute on-the-fly
                #                    to satisfy the api -> rpc object
                #                    conversion.
                # self.host_id = ihost.id
                self.forihostid = ihost.id
            except exception.NodeNotFound as e:
                # Change error code because 404 (NotFound) is inappropriate
                # response for a POST request to create a Port
                e.code = 400  # BadRequest
                raise e
        elif value == wtypes.Unset:
            self._ihost_uuid = wtypes.Unset

    def _get_profilename(self):
        if self.recordtype == 'profile':
            return self.hostname
        else:
            return self._profilename

    def _set_profilename(self, value):
        self._profilename = str(value)

    # NOTE: translate 'id' publicly to 'uuid' internally
    id = int

    created_at = wtypes.datetime.datetime
    updated_at = wtypes.datetime.datetime

    uuid = types.uuid
    hostname = wtypes.text
    profilename = wsme.wsproperty(wtypes.text,
                                  _get_profilename,
                                  _set_profilename,
                                  mandatory=True)

    profiletype = wtypes.text
    "Represent the profiletype of the iprofile - cpu, if, stor, memory"

    recordtype = wtypes.text
    "Represent the recordtype of the iprofile"

    invprovision = wtypes.text
    "Represent the current (not transition) provision state of the ihost"

    mgmt_mac = wtypes.text
    "Represent the provisioned Boot mgmt MAC address of the ihost."

    mgmt_ip = wtypes.text
    "Represent the provisioned Boot mgmt IP address of the ihost."

    personality = wtypes.text
    "Represent the personality of the ihost"

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
    # by this new method along with 'swact', 'lock' and 'unlock'.
    action = wtypes.text

    # Maintenance FSM task is just a text string
    task = wtypes.text

    reserved = wtypes.text

    ihost_uuid = wsme.wsproperty(types.uuid,
                                 _get_ihost_uuid,
                                 _set_ihost_uuid,
                                 mandatory=True)
    "The UUID of the ihost this profile was created from"

    # Host uptime
    uptime = int

    # NOTE: properties should use a class to enforce required properties
    #       current list: arch, cpus, disk, partition, ram, image
    location = {wtypes.text: utils.ValidTypes(wtypes.text, six.integer_types)}

    # NOTE: translate 'chassis_id' to a link to the chassis resource
    #       and accept a chassis uuid when creating an ihost.
    #       (Leaf not ihost)

    links = [link.Link]
    "A list containing a self link and associated ihost links"

    iinterfaces = [link.Link]
    "Links to the collection of iinterfaces on this ihost"

    ports = [link.Link]
    "Links to the collection of ports on this ihost"

    ethernet_ports = [link.Link]
    "Links to the collection of ethernet_ports on this ihost"

    inodes = [link.Link]
    "Links to the collection of inodes on this ihost"

    icpus = [link.Link]
    "Links to the collection of icpus on this ihost"

    imemorys = [link.Link]
    "Links to the collection of imemorys on this ihost"

    istors = [link.Link]
    "Links to the collection of istors on this ihost"

    ipvs = [link.Link]
    "Links to the collection of ipvs on this ihost"

    ilvgs = [link.Link]
    "Links to the collection of ilvgs on this ihost"

    idisks = [link.Link]
    "Links to the collection of idisks on this ihost"

    partitions = [link.Link]
    "Links to the collection of partitions on this ihost"

    boot_device = wtypes.text
    rootfs_device = wtypes.text
    install_output = wtypes.text
    console = wtypes.text
    tboot = wtypes.text

    def __init__(self, **kwargs):
        self.fields = list(objects.host.fields.keys())
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

        self.fields.append('profilename')
        setattr(self, 'profilename', kwargs.get('profilename', None))

        self.fields.append('profiletype')
        setattr(self, 'profiletype', kwargs.get('profiletype', None))

        self.fields.append('ihost_uuid')
        setattr(self, 'ihost_uuid', kwargs.get('ihost_uuid', None))

    @classmethod
    def convert_with_links(cls, rpc_ihost, expand=True):
        minimum_fields = ['id', 'uuid', 'hostname', 'personality',
                          'administrative', 'operational', 'availability',
                          'task', 'action', 'uptime', 'reserved',
                          'mgmt_mac', 'mgmt_ip', 'location', 'recordtype',
                          'created_at', 'updated_at', 'boot_device',
                          'rootfs_device', 'install_output', 'console',
                          'tboot', 'profilename', 'profiletype']
        fields = minimum_fields if not expand else None
        iProfile = Profile.from_rpc_object(rpc_ihost, fields)
        iProfile.profiletype = rpc_ihost.profiletype
        iProfile.links = [link.Link.make_link('self', pecan.request.host_url,
                                              'iprofile', iProfile.uuid),
                          link.Link.make_link('bookmark',
                                              pecan.request.host_url,
                                              'iprofile', iProfile.uuid,
                                              bookmark=True)
                          ]
        if expand:
            iProfile.iinterfaces = [link.Link.make_link('self',
                                                        pecan.request.host_url,
                                                        'iprofile',
                                                        iProfile.uuid + "/iinterfaces"),
                                    link.Link.make_link(
                                        'bookmark',
                                        pecan.request.host_url,
                                        'iprofile',
                                        iProfile.uuid + "/iinterfaces",
                                        bookmark=True)
                                    ]

            iProfile.ports = [link.Link.make_link('self',
                                                  pecan.request.host_url,
                                                  'iprofile',
                                                  iProfile.uuid + "/ports"),
                              link.Link.make_link(
                                  'bookmark',
                                  pecan.request.host_url,
                                  'iprofile',
                                  iProfile.uuid + "/ports",
                                  bookmark=True)
                              ]

            iProfile.ethernet_ports = [link.Link.make_link('self',
                                                           pecan.request.host_url,
                                                           'iprofile',
                                                           iProfile.uuid + "/ethernet_ports"),
                                       link.Link.make_link(
                                           'bookmark',
                                           pecan.request.host_url,
                                           'iprofile',
                                           iProfile.uuid + "/ethernet_ports",
                                           bookmark=True)
                                       ]

            iProfile.inodes = [link.Link.make_link('self',
                                                   pecan.request.host_url,
                                                   'ihosts',
                                                   iProfile.uuid + "/inodes"),
                               link.Link.make_link(
                                   'bookmark',
                                   pecan.request.host_url,
                                   'ihosts',
                                   iProfile.uuid + "/inodes",
                                   bookmark=True)
                               ]

            iProfile.icpus = [link.Link.make_link('self',
                                                  pecan.request.host_url,
                                                  'ihosts',
                                                  iProfile.uuid + "/icpus"),
                              link.Link.make_link(
                                  'bookmark',
                                  pecan.request.host_url,
                                  'ihosts',
                                  iProfile.uuid + "/icpus",
                                  bookmark=True)
                              ]

            iProfile.imemorys = [link.Link.make_link('self',
                                                     pecan.request.host_url,
                                                     'ihosts',
                                                     iProfile.uuid + "/imemorys"),
                                 link.Link.make_link(
                                     'bookmark',
                                     pecan.request.host_url,
                                     'ihosts',
                                     iProfile.uuid + "/imemorys",
                                     bookmark=True)
                                 ]

            iProfile.istors = [link.Link.make_link('self',
                                                   pecan.request.host_url,
                                                   'iprofile',
                                                   iProfile.uuid + "/istors"),
                               link.Link.make_link(
                                   'bookmark',
                                   pecan.request.host_url,
                                   'iprofile',
                                   iProfile.uuid + "/istors",
                                   bookmark=True)
                               ]

            iProfile.ilvgs = [link.Link.make_link('self',
                                                   pecan.request.host_url,
                                                   'iprofile',
                                                   iProfile.uuid + "/ilvgs"),
                               link.Link.make_link(
                                   'bookmark',
                                   pecan.request.host_url,
                                   'iprofile',
                                   iProfile.uuid + "/ilvgs",
                                   bookmark=True)
                              ]

            iProfile.ipvs = [link.Link.make_link('self',
                                                   pecan.request.host_url,
                                                   'iprofile',
                                                   iProfile.uuid + "/ipvs"),
                               link.Link.make_link(
                                   'bookmark',
                                   pecan.request.host_url,
                                   'iprofile',
                                   iProfile.uuid + "/ipvs",
                                   bookmark=True)
                             ]

            iProfile.idisks = [link.Link.make_link('self',
                                                   pecan.request.host_url,
                                                   'iprofile',
                                                   iProfile.uuid + "/idisks"),
                               link.Link.make_link(
                                   'bookmark',
                                   pecan.request.host_url,
                                   'iprofile',
                                   iProfile.uuid + "/idisks",
                                   bookmark=True)
                               ]

            iProfile.partitions = [
                link.Link.make_link(
                    'self',
                    pecan.request.host_url,
                    'iprofile',
                    iProfile.uuid + "/partitions"),
                link.Link.make_link(
                    'bookmark',
                    pecan.request.host_url,
                    'iprofile',
                    iProfile.uuid + "/partitions",
                    bookmark=True)
            ]

        return iProfile


class BaseProfile(base.APIBase):
    """API representation of a type specific profile.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation.
    """
    uuid = types.uuid
    "uuid of the profile"

    profilename = wtypes.text
    "name of the profile"

    profiletype = wtypes.text
    "type of the profile"


class InterfaceProfile(BaseProfile):

    ports = [ethernet_port_api.EthernetPort]
    "list of port objects"

    interfaces = [interface_api.Interface]
    "list of interface objects"


class CpuProfile(BaseProfile):
    cpus = [cpu_api.CPU]
    "list of cpu objects"

    nodes = [node_api.Node]
    "list of node objects"


class MemoryProfile(BaseProfile):
    memory = [memory_api.Memory]
    "list of memory objects"

    nodes = [node_api.Node]
    "list of node objects"


class StorageProfile(BaseProfile):
    disks = [disk_api.Disk]
    "list of disk objects"

    partitions = [partition_api.Partition]
    "list of partition objects"

    stors = [storage_api.Storage]
    "list of storage volume objects"

    pvs = [pv_api.PV]
    "list of physical volume objects"

    lvgs = [lvg_api.LVG]
    "list of logical volume group objects"


class ProfileCollection(collection.Collection):
    """API representation of a collection of ihosts."""

    iprofiles = [Profile]
    "A list containing ihosts objects"

    def __init__(self, **kwargs):
        self._type = 'iprofiles'

    @classmethod
    def convert_with_links(cls, iprofiles, limit, url=None,
                           expand=False, **kwargs):
        collection = ProfileCollection()
        collection.iprofiles = [
            Profile.convert_with_links(n, expand) for n in iprofiles]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'ProfileController'


class ProfileController(rest.RestController):
    """REST controller for iprofiles."""

    iinterfaces = interface_api.InterfaceController(
        from_ihosts=True)
    "Expose iinterfaces as a sub-element of iprofiles"

    ports = port_api.PortController(from_ihosts=True)
    "Expose ports as a sub-element of iprofiles"

    ethernet_ports = ethernet_port_api.EthernetPortController(from_ihosts=True)
    "Expose ethernet_ports as a sub-element of iprofiles"

    inodes = node_api.NodeController(from_ihosts=True)
    "Expose inodes as a sub-element of iprofiles"

    icpus = cpu_api.CPUController(from_ihosts=True)
    "Expose icpus as a sub-element of iprofiles"

    imemorys = memory_api.MemoryController(from_ihosts=True)
    "Expose imemorys as a sub-element of iprofiles"

    istors = storage_api.StorageController(from_ihosts=True)
    "Expose istors as a sub-element of iprofiles"

    ilvgs = lvg_api.LVGController(from_ihosts=True)
    "Expose ilvgs as a sub-element of iprofiles"

    ipvs = pv_api.PVController(from_ihosts=True)
    "Expose ipvs as a sub-element of iprofiles"

    idisks = disk_api.DiskController(from_ihosts=True)
    "Expose idisks as a sub-element of iprofiles"

    partitions = partition_api.PartitionController(from_ihosts=True)
    "Expose partitions as a sub-element of iprofiles"

    _custom_actions = {
        'detail': ['GET'],
        'ifprofiles_list': ['GET'],
        'cpuprofiles_list': ['GET'],
        'memprofiles_list': ['GET'],
        'storprofiles_list': ['GET'],
        'import_profile': ['POST'],
    }

    #############
    # INIT
    #############
    def __init__(self, from_chassis=False):
        self._from_chassis = from_chassis

    @staticmethod
    def _iprofiles_get(chassis_id, marker, limit, sort_key, sort_dir):
        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.host.get_by_uuid(pecan.request.context,
                                                  marker)

        ihosts = pecan.request.dbapi.ihost_get_list(
            limit, marker_obj,
            recordtype="profile",
            sort_key=sort_key,
            sort_dir=sort_dir)

        # The subqueries required to get the profiletype does not scale well,
        # therefore the type is not defined when getting a generic list of
        # profiles.  The type will only be set on the type specific queries.
        for host in ihosts:
            host.profiletype = None

        return ihosts

    @staticmethod
    def _interface_profile_list(marker, limit, sort_key, sort_dir, session):
        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.host.get_by_uuid(pecan.request.context,
                                                  marker)

        profiles = pecan.request.dbapi.interface_profile_get_list(
            limit, marker_obj,
            sort_key=sort_key,
            sort_dir=sort_dir,
            session=session)

        return profiles

    @staticmethod
    def _cpu_profile_list(marker, limit, sort_key, sort_dir, session):
        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.host.get_by_uuid(pecan.request.context,
                                                  marker)

        profiles = pecan.request.dbapi.cpu_profile_get_list(
            limit, marker_obj,
            sort_key=sort_key,
            sort_dir=sort_dir,
            session=session)

        return profiles

    @staticmethod
    def _memory_profile_list(marker, limit, sort_key, sort_dir, session):
        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.host.get_by_uuid(pecan.request.context,
                                                  marker)

        profiles = pecan.request.dbapi.memory_profile_get_list(
            limit, marker_obj,
            sort_key=sort_key,
            sort_dir=sort_dir,
            session=session)

        return profiles

    @staticmethod
    def _storage_profile_list(marker, limit, sort_key, sort_dir, session):
        limit = utils.validate_limit(limit)
        sort_dir = utils.validate_sort_dir(sort_dir)

        marker_obj = None
        if marker:
            marker_obj = objects.host.get_by_uuid(pecan.request.context,
                                                  marker)

        profiles = pecan.request.dbapi.storage_profile_get_list(
            limit, marker_obj,
            sort_key=sort_key,
            sort_dir=sort_dir,
            session=session)

        return profiles

    #############
    # REQUESTS
    #############

    @wsme_pecan.wsexpose([InterfaceProfile])
    def ifprofiles_list(self, marker=None, limit=None,
                        sort_key='id', sort_dir='asc'):
        """Retrieve a list of interface profiles."""

        # session is held for the duration of the profile list
        session = pecan.request.dbapi.get_session()

        profiles = self._interface_profile_list(marker, limit,
                                                sort_key, sort_dir, session)

        if_profiles = []
        for profile in profiles:
            interfaces = []
            ports = []

            for i in profile.interfaces:
                interface = objects.interface.from_db_object(i)
                ic = interface_api.Interface.convert_with_links(interface)
                interfaces.append(ic)

            for p in profile.ports:
                port = objects.ethernet_port.from_db_object(p)
                pc = ethernet_port_api.EthernetPort.convert_with_links(port)
                ports.append(pc)

            if_profiles.append(
                InterfaceProfile(uuid=profile.uuid,
                                 profilename=profile.hostname,
                                 profiletype=constants.PROFILE_TYPE_INTERFACE,
                                 ports=ports,
                                 interfaces=interfaces))

        LOG.debug("ifprofiles_list response result %s" % if_profiles)

        return if_profiles

    @wsme_pecan.wsexpose([CpuProfile])
    def cpuprofiles_list(self, marker=None, limit=None,
                         sort_key='id', sort_dir='asc'):
        """Retrieve a list of cpu profiles."""

        # session is held for the duration of the profile list
        session = pecan.request.dbapi.get_session()

        profiles = self._cpu_profile_list(marker, limit,
                                          sort_key, sort_dir, session)

        cpu_profiles = []
        for profile in profiles:
            cpus = []
            nodes = []

            for c in profile.cpus:
                cpu = objects.cpu.from_db_object(c)
                cc = cpu_api.CPU.convert_with_links(cpu)
                cpus.append(cc)

            for n in profile.nodes:
                node = objects.node.from_db_object(n)
                nc = node_api.Node.convert_with_links(node)
                nodes.append(nc)

            cpu_profiles.append(
                CpuProfile(uuid=profile.uuid,
                           profilename=profile.hostname,
                           profiletype=constants.PROFILE_TYPE_CPU,
                           cpus=cpus,
                           nodes=nodes))

        LOG.debug("cpuprofiles_list response result %s" % cpu_profiles)

        return cpu_profiles

    @wsme_pecan.wsexpose([MemoryProfile])
    def memprofiles_list(self, marker=None, limit=None,
                         sort_key='id', sort_dir='asc'):
        """Retrieve a list of memory profiles."""

        # session is held for the duration of the profile list
        session = pecan.request.dbapi.get_session()

        profiles = self._memory_profile_list(marker, limit,
                                             sort_key, sort_dir, session)

        memory_profiles = []
        for profile in profiles:
            memory = []
            nodes = []

            for m in profile.memory:
                mem = objects.memory.from_db_object(m)
                mc = memory_api.Memory.convert_with_links(mem)
                memory.append(mc)

            for n in profile.nodes:
                node = objects.node.from_db_object(n)
                nc = node_api.Node.convert_with_links(node)
                nodes.append(nc)

            memory_profiles.append(
                MemoryProfile(uuid=profile.uuid,
                              profilename=profile.hostname,
                              profiletype=constants.PROFILE_TYPE_MEMORY,
                              memory=memory,
                              nodes=nodes))

        LOG.debug("memprofiles_list response result %s" % memory_profiles)

        return memory_profiles

    @wsme_pecan.wsexpose([StorageProfile])
    def storprofiles_list(self, marker=None, limit=None,
                          sort_key='id', sort_dir='asc'):
        """Retrieve a list of storage profiles."""

        # session is held for the duration of the profile list
        session = pecan.request.dbapi.get_session()

        profiles = self._storage_profile_list(marker, limit,
                                              sort_key, sort_dir, session)

        stor_profiles = []
        for profile in profiles:
            disks = []
            partitions = []
            stors = []
            lvgs = []
            pvs = []

            for d in profile.disks:
                disk = objects.disk.from_db_object(d)
                dc = disk_api.Disk.convert_with_links(disk)
                disks.append(dc)

            for part in profile.partitions:
                partition = objects.partition.from_db_object(part)
                partc = partition_api.Partition.convert_with_links(partition)
                partitions.append(partc)

            for s in profile.stors:
                stor = objects.storage.from_db_object(s)
                sc = storage_api.Storage.convert_with_links(stor)
                stors.append(sc)

            for p in profile.pvs:
                pv = objects.pv.from_db_object(p)
                pc = pv_api.PV.convert_with_links(pv)
                pvs.append(pc)

            for l in profile.lvgs:
                lvg = objects.lvg.from_db_object(l)
                lc = lvg_api.LVG.convert_with_links(lvg)
                lvgs.append(lc)

            profiletype = constants.PROFILE_TYPE_LOCAL_STORAGE \
                if lvgs else constants.PROFILE_TYPE_STORAGE

            stor_profiles.append(
                StorageProfile(uuid=profile.uuid,
                               profilename=profile.hostname,
                               profiletype=profiletype,
                               disks=disks,
                               partitions=partitions,
                               stors=stors,
                               lvgs=lvgs,
                               pvs=pvs))

        LOG.debug("storprofiles_list response result %s" % stor_profiles)

        return stor_profiles

    @wsme_pecan.wsexpose(ProfileCollection, six.text_type, six.text_type, int,
                         six.text_type, six.text_type)
    def get_all(self, chassis_id=None, marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of ihosts."""
        ihosts = self._iprofiles_get(
            chassis_id, marker, limit, sort_key, sort_dir)
        return ProfileCollection.convert_with_links(ihosts, limit,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

    @wsme_pecan.wsexpose(ProfileCollection, six.text_type, six.text_type, int,
                         six.text_type, six.text_type)
    def detail(self, chassis_id=None, marker=None, limit=None,
               sort_key='id', sort_dir='asc'):
        """Retrieve a list of ihosts with detail."""
        # /detail should only work against collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "ihosts":
            raise exception.HTTPNotFound

        ihosts = self._iprofiles_get(
            chassis_id, marker, limit, sort_key, sort_dir)
        resource_url = '/'.join(['ihosts', 'detail'])
        return ProfileCollection.convert_with_links(ihosts, limit,
                                                    url=resource_url,
                                                    expand=True,
                                                    sort_key=sort_key,
                                                    sort_dir=sort_dir)

    @wsme_pecan.wsexpose(Profile, six.text_type)
    def get_one(self, uuid):
        """Retrieve information about the given ihost."""
        if self._from_chassis:
            raise exception.OperationNotPermitted

        rpc_ihost = objects.host.get_by_uuid(pecan.request.context,
                                             uuid)
        rpc_ihost.profiletype = _get_profiletype(rpc_ihost)
        return Profile.convert_with_links(rpc_ihost)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Profile, body=Profile)
    def post(self, iprofile):
        """Create a new ihost profile."""
        if self._from_chassis:
            raise exception.OperationNotPermitted

        system_mode = utils.get_system_mode()
        if system_mode == constants.SYSTEM_MODE_SIMPLEX:
            raise wsme.exc.ClientSideError(_(
                "Creating a profile on a simplex system is not allowed."))

        try:
            # Ensure recordtype is a profile
            profile_dict = iprofile.as_dict()
            recordtype_profile = {'recordtype': 'profile'}
            profile_dict.update(recordtype_profile)

            # Parent host
            ihost_uuid = ''
            if 'ihost_uuid' in profile_dict:
                ihost_uuid = profile_dict['ihost_uuid']

            if 'profilename' in profile_dict and profile_dict['profilename']:
                profile_dict['hostname'] = profile_dict['profilename']
                del profile_dict['profilename']

            # Semantic checks
            _check_profilename(profile_dict['hostname'])

            from_ihost = pecan.request.dbapi.ihost_get(ihost_uuid)

            # Before proceeding, check if the host is provisioned.
            # Adding a profile while the host hasn't been provisioned
            # will result in an entry being created in the ihost
            # table for this profile, but no corresponding
            # entries in the {storage, cpu, interface, etc} tables
            if from_ihost.invprovision != constants.PROVISIONED:
                raise wsme.exc.ClientSideError(_("Cannot create profile %s "
                    "until host %s is unlocked for the first time." %
                    (profile_dict['hostname'], from_ihost.hostname)))

            profile_dict['subfunctions'] = from_ihost.subfunctions

            profiletype = ''
            if 'profiletype' in profile_dict and profile_dict['profiletype']:
                profiletype = profile_dict['profiletype']
                if profiletype == constants.PROFILE_TYPE_STORAGE:
                    stor_model = ceph.get_ceph_storage_model()
                    if constants.WORKER in from_ihost.subfunctions:
                        #  combo has no ceph
                        profiletype = constants.PROFILE_TYPE_LOCAL_STORAGE
                        LOG.info("No ceph backend for stor profile, assuming "
                            "%s" % profiletype)
                    elif not StorageBackendConfig.has_backend_configured(
                        pecan.request.dbapi,
                        constants.CINDER_BACKEND_CEPH
                    ):
                        raise wsme.exc.ClientSideError(_("Storage profiles "
                            "not applicable for %s with non Ceph backend." %
                            from_ihost.hostname))
                    elif (from_ihost.personality == constants.CONTROLLER and
                            stor_model != constants.CEPH_CONTROLLER_MODEL):
                        raise wsme.exc.ClientSideError(_("Storage profiles "
                            "not applicable for %s as storage deployment "
                            "model is: %s" %
                            (from_ihost.hostname, stor_model)))

            # Create profile
            LOG.debug("iprofileihost is: %s " % profile_dict)
            new_ihost = pecan.request.dbapi.ihost_create(profile_dict)

            try:
                profile_copy_data(from_ihost, new_ihost, profiletype)
            except wsme.exc.ClientSideError as cse:
                pecan.request.dbapi.ihost_destroy(new_ihost.id)
                LOG.exception(cse)
                raise cse
            except Exception as e:
                pecan.request.dbapi.ihost_destroy(new_ihost.id)
                LOG.exception(e)
                raise wsme.exc.ClientSideError(_("Failed to copy data to profile"))

        except exception.SysinvException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Invalid data"))

        return iprofile.convert_with_links(new_ihost)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(Profile, six.text_type, body=[six.text_type])
    def patch(self, uuid, patch):
        """Update an existing iprofile.
        """

        iHost = objects.host.get_by_uuid(pecan.request.context, uuid)

        if iHost['recordtype'] != "profile":
            raise wsme.exc.ClientSideError(_("Cannot update "
                                             "non profile record type"))

        iHost_dict = iHost.as_dict()
        utils.validate_patch(patch)
        patch_obj = jsonpatch.JsonPatch(patch)

        # Prevent auto populated fields from being updated
        state_rel_path = ['/uuid', '/id', '/recordtype']
        if any(p['path'] in state_rel_path for p in patch_obj):
            raise wsme.exc.ClientSideError(_("The following fields cannot be "
                                             "modified: uuid, id, recordtype"))

        try:
            # Update profile
            patched_iHost = jsonpatch.apply_patch(iHost_dict,
                                                  patch_obj)
        except jsonpatch.JsonPatchException as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Patching Error: %s") % e)

        # Semantic checks
        _check_profilename(patched_iHost['hostname'])

        # Once the host has been provisioned lock down additional fields
        provision_state = [constants.PROVISIONED, constants.PROVISIONING]
        if iHost['invprovision'] in provision_state:
            state_rel_path = ['/hostname', '/recordtype']
            if any(p['path'] in state_rel_path for p in patch_obj):
                raise wsme.exc.ClientSideError(
                    _("The following fields cannot be modified because this "
                      "host has been configured: hostname, recordtype "))

        try:
            # Update only the fields that have changed
            for field in objects.profile.fields:
                if iHost[field] != patched_iHost[field]:
                    iHost[field] = patched_iHost[field]

            iHost.save()
            return Profile.convert_with_links(iHost)
        except exception.HTTPNotFound:
            msg = _("Profile update failed: %s : patch %s"
                    % (patched_iHost['hostname'], patch))
            raise wsme.exc.ClientSideError(msg)

    @cutils.synchronized(LOCK_NAME)
    @wsme_pecan.wsexpose(None, six.text_type, status_code=204)
    def delete(self, ihost_id):
        """Delete an ihost profile.
        """

        ihost = objects.host.get_by_uuid(pecan.request.context,
                                         ihost_id)

        # Profiles do not require un/configuration or mtc notification
        if ihost.recordtype == "profile":
            try:
                profile_delete_data(ihost)
            except wsme.exc.ClientSideError as cse:
                LOG.exception(cse)
                raise cse
            except Exception as e:
                LOG.exception(e)
                raise wsme.exc.ClientSideError(_("Failed to delete data from profile"))

            pecan.request.dbapi.ihost_destroy(ihost_id)
        else:
            raise wsme.exc.ClientSideError(_("Delete not allowed - recordtype "
                                             "is not a profile."))

    @cutils.synchronized(LOCK_NAME)
    @expose('json')
    def import_profile(self, file):
        class ProfileObj:
            display = ""
            proc = None

            def __init__(self, display, proc):
                self.display = display
                self.proc = proc

        results = []
        file = pecan.request.POST['file']
        contents = file.file.read()
        try:
            # validate against profileschema.xsd
            with open('/etc/sysinv/profileSchema.xsd', 'r') as f:
                schema_root = etree.XML(f.read())

            schema = etree.XMLSchema(schema_root)
            xmlparser = etree.XMLParser(schema=schema)

            try:
                etree.fromstring(contents, xmlparser)
            except etree.XMLSchemaError as e:
                return [{'result': 'Invalid',
                         'type': '',
                         'name': '',
                         'msg': "Profile is invalid",
                         'detail': e.message}]

            root = et.fromstring(contents)
        except Exception as e:
            LOG.exception(e)
            error = e.message
            return [{'result': 'Invalid',
                     'type': '', 'name': '',
                     'msg': 'Profile is invalid',
                     'detail': error}]

        profile_types = ["cpuProfile", "memoryProfile", "interfaceProfile",
                         "storageProfile", "localstorageProfile"]
        profile_lookup = {
            "cpuProfile": ProfileObj("CPU Profile", _create_cpu_profile),
            "interfaceProfile": ProfileObj("Interface profile",
                                           _create_if_profile),
            "memoryProfile": ProfileObj("Memory profile", _create_mem_profile),
            "storageProfile": ProfileObj("Storage profile",
                                         _create_storage_profile),
            "localstorageProfile": ProfileObj("Local Storage profile",
                                              _create_localstorage_profile)
        }

        hosts = pecan.request.dbapi.ihost_get_list(recordtype=None)
        hostnames = []
        for host in hosts:
            hostnames.append(host.hostname)

        for profile_node in root:
            tag = profile_node.tag
            profile_name = profile_node.get("name")

            if tag not in profile_types:
                results.append({'result': 'Error',
                                'type': 'unknown',
                                'name': '',
                                'msg': 'error: profile type %s is unrecognizable.' % tag,
                                'detail': None})
            else:
                object = profile_lookup[tag]
                if not profile_name:
                    results.append({'result': 'Error',
                                    'type': object.display,
                                    'name': '',
                                    'msg': 'error: profile name is missing',
                                    'detail': None})
                else:
                    if profile_name not in hostnames:
                        hostnames.append(profile_name)

                        try:
                            result, msg, detail = \
                                object.proc(profile_name, profile_node)
                            results.append({'result': result,
                                            'type': object.display,
                                            'name': profile_name,
                                            'msg': msg,
                                            'detail': detail})
                        except Exception as e:
                            results.append({'result': "Error",
                                            'type': object.display,
                                            'name': profile_name,
                                            'msg': _('error: failed to import %s %s.' % (
                                                object.display, profile_name
                                            )),
                                            'detail': str(e)
                                            })

                    else:
                        results.append({'result': "Warning",
                                        'type': object.display,
                                        'msg': _('warning: %s %s already exists and is not imported.') %
                                                (object.display, profile_name),
                                        'detail': None})
        return results


def _create_cpu_profile(profile_name, profile_node):
    class CoreFunction:
        def __init__(self, p_index, c_index, t_index=0):
            self.processor_index = p_index
            self.core_index = c_index
            self.thread_index = t_index
            self.core_function = constants.APPLICATION_FUNCTION

    # The xml is validated against schema.
    # Validations that are covered by the schema are not checked below.
    values = dict(recordtype="profile", hostname=profile_name)

    processor = profile_node.find('processor')
    number_of_cpu = 0
    node = processor.find('numberOfProcessor')
    if node is not None:
        number_of_cpu = int(node.text)
    node = processor.find('coresPerProcessor')
    cores_per_cpu = int(node.text)

    hyper_threading = False
    node = processor.find('hyperThreading')
    if node is not None:
        hyper_threading = (node.text == 'true')

    if hyper_threading:
        max_thread = 2
    else:
        max_thread = 1

    platform_cores = [[CoreFunction(i, j) for j in range(cores_per_cpu)] for i in range(number_of_cpu)]
    platform_core_index = [0 for i in range(number_of_cpu)]

    core_function_list = [{'node_name': 'platformCores', 'node_function': constants.PLATFORM_FUNCTION},
                          {'node_name': 'vswitchCores', 'node_function': constants.VSWITCH_FUNCTION},
                          {'node_name': 'sharedCores', 'node_function': constants.SHARED_FUNCTION}]

    try:
        for core_function in core_function_list:
            function_node = profile_node.find(core_function['node_name'])
            function_name = core_function['node_function']
            if function_node is None:
                continue
            for processor_node in function_node.findall('processor'):
                p_idx = int(processor_node.get('index'))
                if p_idx >= number_of_cpu:
                    raise profile_utils.InvalidProfileData('Invalid processor index %d. '
                                                            'Valid range is 0 to %d (numberOfProcessor - 1)' %
                                                           (p_idx, number_of_cpu - 1))
                cores_node = processor_node.get('numberOfCores')
                cores = int(cores_node)
                count = 0
                for count in range(cores):
                    platform_cores[p_idx][platform_core_index[p_idx]].core_function = function_name

                    platform_core_index[p_idx] = platform_core_index[p_idx] + 1
                    if platform_core_index[p_idx] >= cores_per_cpu:
                        raise profile_utils.InvalidProfileData("Too many core functions assigned to a processor")

    except profile_utils.InvalidProfileData as e:
        return "Error", 'error: CPU profile %s is invalid' % profile_name, e.message

    try:
        ihost = pecan.request.dbapi.ihost_create(values)
    except dbException.DBDuplicateEntry as e:
        LOG.exception(e)
        return "Warning", _('warning: CPU profile %s already exists and is not imported.') % profile_name, None
    except Exception as e:
        LOG.exception(e)
        return "Error", _('error: importing CPU profile %s failed.') % profile_name, e.message

    iprofile_id = ihost['id']

    cpu_idx = 0
    node_idx = 0

    try:
        for cpulist in platform_cores:
            ndict = {'numa_node': node_idx}
            new_node = pecan.request.dbapi.inode_create(iprofile_id, ndict)
            for core in cpulist:
                for thread_id in range(max_thread):
                    cdict = {"cpu": cpu_idx,
                             "core": core.core_index,
                             "thread": thread_id,
                             "allocated_function": core.core_function,
                             'forinodeid': new_node['id']}
                    pecan.request.dbapi.icpu_create(iprofile_id, cdict)
                    cpu_idx = cpu_idx + 1

            node_idx = node_idx + 1
    except Exception as exc:
        cpuprofile_delete_data(ihost)
        pecan.request.dbapi.ihost_destroy(iprofile_id)
        LOG.exception(exc)
        raise exc

    return "Success", _('CPU profile %s is successfully imported.') % profile_name, None


def _create_route(ifUuid, ifId, routes):
    # ['interface_uuid', 'network', 'prefix',
    #                'gateway', 'metric']
    for r in routes:
        r['interface_id'] = ifId
        pecan.request.dbapi.route_create(ifId, r)


def _create_if_profile(profile_name, profile_node):
    ethInterfaces = []
    interfaceNames = []
    detail_msg = None

    try:
        for ethIfNode in profile_node.findall("ethernetInterface"):
            ethIf = profile_utils.EthInterface(ethIfNode)
            ethIf.validate()
            if ethIf.name not in interfaceNames:
                interfaceNames.append(ethIf.name)
                ethInterfaces.append(ethIf)
            else:
                msg = _('Interface name must be unique (%s)' % ethIf.name)
                raise profile_utils.InvalidProfileData(msg)

        aeInterfaces = []
        for aeIfNode in profile_node.findall("aeInterface"):
            aeIf = profile_utils.AeInterface(aeIfNode)
            if aeIf.name not in interfaceNames:
                interfaceNames.append(aeIf.name)
                aeInterfaces.append(aeIf)
            else:
                msg = _('Interface name must be unique (%s)' % aeIf.name)
                raise profile_utils.InvalidProfileData(msg)

        vlanInterfaces = []
        for vlanIfNode in profile_node.findall("vlanInterface"):
            vlanIf = profile_utils.VlanInterface(vlanIfNode)
            if vlanIf.name not in interfaceNames:
                interfaceNames.append(vlanIf.name)
                vlanInterfaces.append(vlanIf)
            else:
                msg = _('Interface name must be unique (%s)' % aeIf.name)
                raise profile_utils.InvalidProfileData(msg)

        ethIfMap = []
        aeIfMap = {}
        vlanMap = []
        allProviderNetworks = []

        def _verifyProviderNetworks(pnetworks):
            for pnet in pnetworks:
                if pnet not in allProviderNetworks:
                    allProviderNetworks.append(pnet)
                else:
                    msg = _('provider network %s is already assigned to the other interface.') % pnet
                    raise profile_utils.InvalidProfileData(msg)

        cnt_port = True
        cnt_pciaddr = True
        for ethIf in ethInterfaces:
            if not ethIf.port:
                cnt_port = False
            if not ethIf.pciAddress:
                cnt_pciaddr = False
            ethIfMap.append(ethIf.name)
            _verifyProviderNetworks(ethIf.providerNetworks)

        if cnt_pciaddr and cnt_port:
            detail_msg = _('Eth port PCI address and name are both provided, '
                           'only PCI address will be used for port matching')
        elif cnt_pciaddr:
            detail_msg = _('PCI address will be used for port matching')
        elif cnt_port:
            detail_msg = _('Eth port name will be used for port matching')
        else:
            raise profile_utils.InvalidProfileData(_('pciAddress must be provided for each Eth port.'
                                                      'Name for each Eth port can be provided as alternative.'))

        for aeIf in aeInterfaces:
            aeIfMap[aeIf.name] = aeIf
            _verifyProviderNetworks(aeIf.providerNetworks)

        for vlanIf in vlanInterfaces:
            vlanMap.append(vlanIf.name)
            _verifyProviderNetworks(vlanIf.providerNetworks)

        for ae in aeInterfaces:
            ae.validateWithIfNames(interfaceNames)

        for vlan in vlanInterfaces:
            vlan.validateWithIfNames(interfaceNames, aeIfMap, vlanMap, ethIfMap)

    except profile_utils.InvalidProfileData as ie:
        return "Error", _('error: Interface profile %s is invalid.') % profile_name, ie.message

    values = {'recordtype': 'profile', 'hostname': profile_name}
    try:
        ihost = pecan.request.dbapi.ihost_create(values)
    except dbException.DBDuplicateEntry as e:
        LOG.exception(e)
        return "Warning", _('warning: interface profile %s already exists and is not imported.') % profile_name, None
    except Exception as e:
        LOG.exception(e)
        return "Error", _('error: importing interface profile %s failed.') % profile_name, e.message

    iprofile_id = ihost['id']
    try:
        # create interfaces in dependency order
        # eth-interfaces always go first
        newIfList = []
        # TODO: get mtu from eth ports as default mtu
        for ethIf in ethInterfaces:
            nt, providernets = ethIf.getNetworks()
            ipv4_mode = ethIf.ipv4Mode
            ipv6_mode = ethIf.ipv6Mode
            idict = {'ifname': ethIf.name,
                     'iftype': 'ethernet',
                     'imtu': ethIf.mtu,
                     'networktype': nt,
                     'forihostid': iprofile_id,
                     'datanetworks': providernets,
                     'ipv4_mode': ipv4_mode['mode'],
                     'ipv6_mode': ipv6_mode['mode'],
                     'ipv4_pool': ipv4_mode['pool'],
                     'ipv6_pool': ipv6_mode['pool'],
                     'sriov_numvfs': ethIf.virtualFunctions,
                     'sriov_vf_driver': ethIf.virtualFunctionDriver,
                     'interface_profile': True
                     }
            newIf = interface_api._create(idict, from_profile=True)
            newIf.ifData = ethIf
            newIfList.append(newIf)
            ifId = newIf.id

            pdict = {
                'host_id': iprofile_id,
                'interface_id': ifId,
                'name': ethIf.port,
                'pciaddr': ethIf.pciAddress,
                'pclass': ethIf.pclass,
                'pdevice': ethIf.pdevice,
                'mtu': ethIf.mtu
            }

            pecan.request.dbapi.ethernet_port_create(iprofile_id, pdict)

            routes = ethIf.routes
            _create_route(newIf.uuid, newIf.id, routes)

        for aeIf in aeInterfaces:
            nt, providernets = aeIf.getNetworks()
            ipv4_mode = aeIf.ipv4Mode['mode']
            ipv6_mode = aeIf.ipv6Mode['mode']
            ipv4_pool = aeIf.ipv4Mode['pool']
            ipv6_pool = aeIf.ipv6Mode['pool']
            idict = {'ifname': aeIf.name,
                     'iftype': 'ae',
                     'networktype': nt,
                     'aemode': aeIf.aeMode,
                     'txhashpolicy': aeIf.txPolicy,
                     'forihostid': iprofile_id,
                     'datanetworks': providernets,
                     'ipv4_mode': ipv4_mode,
                     'ipv6_mode': ipv6_mode,
                     'ipv4_pool': ipv4_pool,
                     'ipv6_pool': ipv6_pool,
                     'imtu': aeIf.mtu,
                     'sriov_numvfs': ethIf.virtualFunctions,
                     'sriov_vf_driver': ethIf.virtualFunctionDriver,
                     'interface_profile': True
                     }

            newIf = interface_api._create(idict, from_profile=True)
            newIf.ifData = aeIf
            newIfList.append(newIf)
            routes = aeIf.routes
            _create_route(newIf.uuid, newIf.id, routes)

        for vlanIf in vlanInterfaces:
            nt, providernets = vlanIf.getNetworks()
            ipv4_mode = vlanIf.ipv4Mode['mode']
            ipv6_mode = vlanIf.ipv6Mode['mode']
            ipv4_pool = vlanIf.ipv4Mode['pool']
            ipv6_pool = vlanIf.ipv6Mode['pool']
            idict = {'ifname': vlanIf.name,
                     'iftype': 'vlan',
                     'networktype': nt,
                     'vlan_id': vlanIf.vlanId,
                     'forihostid': iprofile_id,
                     'datanetworks': providernets,
                     'ipv4_mode': ipv4_mode,
                     'ipv6_mode': ipv6_mode,
                     'ipv4_pool': ipv4_pool,
                     'ipv6_pool': ipv6_pool,
                     'imtu': vlanIf.mtu,
                     'sriov_numvfs': ethIf.virtualFunctions,
                     'sriov_vf_driver': ethIf.virtualFunctionDriver,
                     'interface_profile': True
                     }

            newIf = interface_api._create(idict, from_profile=True)
            newIf.ifData = vlanIf
            newIfList.append(newIf)
            routes = vlanIf.routes
            _create_route(newIf.uuid, newIf.id, routes)

        # Generate the uses/used_by relationships
        ifname_to_if = {}
        used_by_list = {}
        for i in newIfList:
            ifname_to_if[i.ifname] = i

        for i in newIfList:
            ifData = i.ifData
            if hasattr(ifData, 'usesIf'):
                uses_list = ifData.usesIf
                for usesif in uses_list:
                    uuid = ifname_to_if[i.ifname]
                    if not hasattr(used_by_list, usesif):
                        used_by_list[usesif] = [uuid]
                    else:
                        used_by_list[usesif].append(uuid)

        for i in newIfList:
            ifData = i.ifData
            if not hasattr(ifData, 'usesIf'):
                continue

            uses_uuid_list = []
            uses_list = ifData.usesIf
            for usesif in uses_list:
                mapIf = ifname_to_if[usesif]
                uuid = mapIf.uuid
                uses_uuid_list.append(uuid)

            idict = {}
            idict['uses'] = uses_uuid_list
            if hasattr(used_by_list, i.ifname):
                idict['used_by'] = used_by_list[i.ifname]

            try:
                pecan.request.dbapi.iinterface_update(i.uuid, idict)
            except Exception as e:
                raise wsme.exc.ClientSideError(_("Failed to link interface uses."))
    except Exception as exc:
        ihost.ethernet_ports = \
            pecan.request.dbapi.ethernet_port_get_by_host(ihost.uuid)

        ifprofile_delete_data(ihost)
        pecan.request.dbapi.ihost_destroy(iprofile_id)
        LOG.exception(exc)
        raise exc

    return "Success", _('Interface profile %s is successfully imported.') % profile_name, detail_msg


def _create_mem_profile(profile_name, profile_node):
    class MemoryAssignment(object):
        def __init__(self, processor_idx, size):
            self.processor_idx = processor_idx
            self.size = size

    # The xml is validated against schema.
    # Validations that are covered by the schema are not checked below.
    values = dict(recordtype="profile", hostname=profile_name)

    node = profile_node.find('numberOfProcessor')
    number_of_cpu = int(node.text)

    def get_mem_assignment(profile_node, name):
        mem_node = profile_node.find(name)
        if node is None:
            return

        mem_assignments = []
        processor_indexes = []
        for processor_node in mem_node.findall('processor'):
            p_idx = int(processor_node.get('index'))
            if p_idx >= number_of_cpu:
                msg = _('Invalid processor index {0}. '
                        'Valid range is 0 to {1} (numberOfProcessor - 1)')\
                        .format(p_idx, number_of_cpu - 1)
                raise profile_utils.InvalidProfileData(msg)

            if p_idx in processor_indexes:
                msg = _('Invalid processor index {0}, duplicated. ').format(p_idx)
                raise profile_utils.InvalidProfileData(msg)

            processor_indexes.append(p_idx)
            mem_size = int(processor_node.get('size'))

            mem_assignments.append(MemoryAssignment(p_idx, mem_size))
        return mem_assignments

    def get_mem_size(mem_assignments, processor_idx):
        for mem_assignment in mem_assignments:
            if mem_assignment.processor_idx == processor_idx:
                return mem_assignment.size

        return 0

    try:
        platform_reserved = get_mem_assignment(profile_node, "platformReservedMiB")
        vm_hp_2m = get_mem_assignment(profile_node, "vmHugePages2M")
        vm_hp_1g = get_mem_assignment(profile_node, "vmHugePages1G")
        vs_hp_nr = get_mem_assignment(profile_node, "vsHugePagesNr")
        vs_hp_sz = get_mem_assignment(profile_node, "vsHugePagesSz")
    except profile_utils.InvalidProfileData as e:
        return "Error", _('error: CPU profile %s is invalid') % profile_name, e.message

    try:
        ihost = pecan.request.dbapi.ihost_create(values)
    except dbException.DBDuplicateEntry as e:
        LOG.exception(e)
        return "Warning", _('warning: Memory profile %s already exists and is not imported.') % profile_name, None
    except Exception as e:
        LOG.exception(e)
        return "Error", _('error: Creating memory profile %s failed.') % profile_name, e.message

    iprofile_id = ihost['id']

    node_idx = 0

    try:
        for cpulist in range(number_of_cpu):
            ndict = {'numa_node': node_idx}
            new_node = pecan.request.dbapi.inode_create(iprofile_id, ndict)

            mdict = {}
            mdict['forihostid'] = iprofile_id
            mdict['forinodeid'] = new_node['id']
            mdict['platform_reserved_mib'] = get_mem_size(platform_reserved, node_idx)
            mdict['vm_hugepages_nr_2M_pending'] = get_mem_size(vm_hp_2m, node_idx)
            mdict['vm_hugepages_nr_1G_pending'] = get_mem_size(vm_hp_1g, node_idx)
            mdict['vswitch_hugepages_reqd'] = get_mem_size(vs_hp_nr, node_idx)
            mdict['vswitch_hugepages_size_mib'] = get_mem_size(vs_hp_sz, node_idx)
            pecan.request.dbapi.imemory_create(iprofile_id, mdict)

            node_idx += 1
    except Exception as exc:
        memoryprofile_delete_data(ihost)
        pecan.request.dbapi.ihost_destroy(iprofile_id)
        LOG.exception(exc)
        raise exc

    return "Success", _('Memory profile %s is successfully imported.') % profile_name, None


def _create_storage_profile(profile_name, profile_node):
    if not StorageBackendConfig.has_backend_configured(
        pecan.request.dbapi,
        constants.CINDER_BACKEND_CEPH
    ):
        return "Error", _("error: Storage profile can only be imported into "
                          "a system with Ceph backend."), None
    # The xml is validated against schema.
    # Validations that are covered by the schema are not checked below.
    values = dict(recordtype="profile", hostname=profile_name)

    disks = profile_node.findall('disk')
    dev_paths = []

    # Any supported storage functions should be appended here
    supportedFuncs = [constants.STOR_FUNCTION_OSD,
                      constants.STOR_FUNCTION_JOURNAL]

    # Gather the storage tiers and build a map for the OSD create call
    tier_map = {}
    tiers = pecan.request.dbapi.storage_tier_get_all(type=constants.SB_TIER_TYPE_CEPH)
    for t in tiers:
        tier_map[t.name] = t

    journal_disks = []
    for disk in disks:
        dev_path = disk.get('path')
        dev_func = disk.get('volumeFunc')
        # Convert from GiB to MiB
        dev_size = int(disk.get('size')) * 1024
        journal_size = int(disk.get('journalSize', '0')) * 1024
        tier = disk.get('tier', constants.SB_TIER_DEFAULT_NAMES[
            constants.SB_TIER_TYPE_CEPH])
        if not dev_path:
            return "Error", _('error: Storage profile %s is invalid') % \
                   profile_name, _('path is empty.')
        if dev_func not in supportedFuncs:
            return "Error", _('error: Storage profile %s is invalid') % \
                   profile_name, \
                    _('volumeFunc (%s) is not supported.') % dev_func
        if dev_path not in dev_paths:
            dev_paths.append(dev_paths)
        else:
            return "Error", _('error: Storage profile %s is invalid') % profile_name, \
                   _('Device %s is duplicated') % dev_path
        if journal_size:
            if journal_size < CONF.journal.journal_min_size and \
                    journal_size > CONF.journal.journal_max_size:
                return "Error", \
                       _('error: Storage profile %s'
                         ' is invalid') % profile_name, \
                       _('device path %(dev)s journal size of %(size)s'
                         ' is invalid.') % {'dev': dev_path,
                                            'size': journal_size / 1024}, \
                       _('size should be between %(min)s and '
                         ' %(max)s.') % {'min': CONF.journal.journal_min_size / 1024,
                                         'max': CONF.journal.journal_max_size / 1024}

        if dev_func == constants.STOR_FUNCTION_JOURNAL:
            journal_disks.append(dev_path)

        if dev_func == constants.STOR_FUNCTION_OSD:
            if tier not in tier_map:
                return "Error", _('error: Storage profile %s is invalid') % profile_name, \
                    _('Storage tier %s is not present in this cluster') % tier

    # Validate journal locations
    for disk in disks:
        dev_path = disk.get('path')
        dev_func = disk.get('volumeFunc')
        if len(journal_disks) > 1 and dev_func == constants.STOR_FUNCTION_OSD:
            journal_location = disk.get('journalLocation')
            if not journal_location:
                return "Error", \
                       _('error: Storage profile %s'
                         ' is invalid') % profile_name, \
                       _('journal location not defined for %s and multiple '
                         'journal drives are available.') % dev_path
            elif journal_location not in journal_disks:
                return "Error", \
                       _('error: Storage profile %s'
                         ' is invalid') % profile_name, \
                       _('journal location for %s not on a '
                         'journal function device.') % dev_path
    try:
        ihost = pecan.request.dbapi.ihost_create(values)
    except dbException.DBDuplicateEntry as e:
        LOG.exception(e)
        return "Warning", _('warning: Storage profile %s already exists and is not imported.') % profile_name, None
    except Exception as e:
        LOG.exception(e)
        return "Error", _('error: importing storage profile %s failed.') % profile_name, e.message

    profile_id = ihost['id']

    try:
        # First create the journals and keep (dev_name, uuid) associations
        journals = {}
        for disk in disks:
            dev_func = disk.get('volumeFunc')
            if dev_func == constants.STOR_FUNCTION_JOURNAL:
                dev_path = disk.get('path')
                # Convert disk size from GiB to MiB
                dev_size = int(disk.get('size')) * 1024
                ddict = {'device_path': dev_path,
                         'size_mib': dev_size,
                         'forihostid': profile_id,
                         'device_type': constants.DEVICE_TYPE_SSD}
                newdisk = pecan.request.dbapi.idisk_create(profile_id, ddict)

                # create stor
                sdict = {'function': dev_func, 'idisk_uuid': newdisk.uuid, 'forihostid': profile_id}
                # this goes through istor semantic checks versus
                # just adding to db (by calling dbapi.istor_create)
                newstor = storage_api._create(sdict, iprofile=True)
                journals[dev_path] = newstor.uuid

        # Create the other functions
        for disk in disks:
            dev_path = disk.get('path')
            dev_func = disk.get('volumeFunc')
            # convert disk size from GiB to MiB
            dev_size = int(disk.get('size')) * 1024
            tier = disk.get('tier', constants.SB_TIER_DEFAULT_NAMES[
                constants.SB_TIER_TYPE_CEPH])

            if dev_func != constants.STOR_FUNCTION_JOURNAL:
                ddict = {'device_path': dev_path,
                         'size_mib': dev_size,
                         'forihostid': profile_id}
                newdisk = pecan.request.dbapi.idisk_create(profile_id, ddict)

                # create stor
                sdict = {'function': dev_func, 'idisk_uuid': newdisk.uuid, 'forihostid': profile_id}
                if dev_func == constants.STOR_FUNCTION_OSD:
                    default_size = CONF.journal.journal_default_size
                    if len(journals) > 0:
                        # we don't expect collocated journals
                        if disk.get('journalSize'):
                            journal_size = int(disk.get('journalSize')) * 1024
                        else:
                            journal_size = default_size
                        sdict['journal_size_mib'] = journal_size
                        if len(journals) > 1:
                            # multiple journal disks are available, use
                            # location, otherwise just do the default
                            # (journal will be placed on first disk)
                            location_dev = disk.get('journalLocation')
                            location_uuid = journals[location_dev]
                            sdict['journal_location'] = location_uuid
                        else:
                            # get the first journal
                            journal = journals[journals.keys()[0]]
                            sdict['journal_location'] = journal
                    else:
                        # journal is collocated
                        sdict['journal_size_mib'] = default_size

                    sdict['fortierid'] = tier_map[tier].id

                # this goes through istor semantic checks versus
                # just adding to db (by calling dbapi.istor_create)
                newstor = storage_api._create(sdict, iprofile=True)
    except Exception as exc:
        storprofile_delete_data(ihost)
        pecan.request.dbapi.ihost_destroy(profile_id)
        LOG.exception(exc)
        raise exc

    return "Success", _('Storage profile %s is successfully imported.') % profile_name, None


def _create_localstorage_profile(profile_name, profile_node):
    """ Validate and create the localstorage profile from xml.

        The xml is validated against xsd schema.
    """
    values = dict(recordtype="profile",
                  hostname=profile_name,
                  subfunctions=constants.WORKER)

    disks = profile_node.findall('disk')
    all_ilvg_nodes = profile_node.findall('lvg')  # should only be ONE ?
    # ipv_nodes = profile_node.findall('pv')  # can be multiple, base this on disks
    dev_paths = []

    prohibitedFuncs = ['osd']  # prohibited volumeFunc must be appended here
    ilvgs_local = [ilvg for ilvg in all_ilvg_nodes if
                  ilvg.get('lvm_vg_name') == constants.LVG_NOVA_LOCAL]

    if not disks:
        return ("Error", _('error: Local Storage profile %s is invalid') %
                profile_name, _('No disk provided in profile.'))

    if not ilvgs_local:
        return ("Error", _('error: Local Storage profile %s is invalid') %
                profile_name, _('No lvg nova-local (logical volume group) '
                                'in profile.'))
    else:
        nova_local_nodes_len = len(ilvgs_local)
        if nova_local_nodes_len > 1:
            return ("Error", _('error: Local Storage profile %s is invalid') %
                profile_name, _('Currently only one nova-local lvg '
                                'is allowed per host.  Defined %s in %s.' %
                                (nova_local_nodes_len, profile_name)))

    for disk in disks:
        dev_path = disk.get('path')
        # Convert disk size from GiB to MiB
        dev_size = int(disk.get('size')) * 1024
        dev_func = disk.get('volumeFunc')

        if dev_func and dev_func in prohibitedFuncs:
            return ("Error", _('error: Local Storage profile %s is invalid') %
                profile_name, _('dev_func %s is not required.') % dev_func)

        if not dev_path:
            return ("Error", _('error: Local Storage profile %s is invalid') %
                profile_name, _('path is empty.'))

        if dev_path not in dev_paths:
            dev_paths.append(dev_path)
        else:
            return ("Error", _('error: Local Storage profile %s is invalid') %
                    profile_name, _('Device %s is duplicated') % dev_path)

    try:
        ihost = pecan.request.dbapi.ihost_create(values)
    except dbException.DBDuplicateEntry as e:
        LOG.exception(e)
        return ("Warning", _('warning: Local Storage profile %s already '
                'exists and is not imported.') % profile_name, None)
    except Exception as e:
        LOG.exception(e)
        return ("Error", _('error: importing Local Storage profile %s '
                           'failed.') % profile_name, e.message)

    profile_id = ihost.id
    try:
        capabilities_dict = {}

        # create profile ilvg
        lvgdict = {'capabilities': capabilities_dict,
                   'lvm_vg_name': constants.LVG_NOVA_LOCAL,
                   'forihostid': profile_id}
        # this goes through ilvg semantic checks versus
        # just adding to db (by calling dbapi.ilvg_create)
        ilvg_pf = lvg_api._create(lvgdict, iprofile=True)

        for disk in disks:
            dev_path = disk.get('path')
            dev_size = int(disk.get('size')) * 1024

            ddict = {'device_path': dev_path,
                     'size_mib': dev_size,
                     'forihostid': profile_id}
            disk_pf = pecan.request.dbapi.idisk_create(profile_id, ddict)

            # create profile physical volume. nova-local:pv can be 1:n.
            pvdict = {'disk_or_part_device_path': dev_path,
                      'lvm_vg_name': ilvg_pf.lvm_vg_name,
                      'disk_or_part_uuid': disk_pf.uuid,
                      'forihostid': profile_id,
                      'forilvgid': ilvg_pf.id}

            pv_api._create(pvdict, iprofile=True)

    except wsme.exc.ClientSideError as cse:
        pecan.request.dbapi.ihost_destroy(ihost.uuid)
        LOG.exception(cse)
        return "Fail", _('Local Storage profile %s not imported.') % profile_name, str(cse)

    except Exception as exc:
        pecan.request.dbapi.ihost_destroy(profile_id)
        LOG.exception(exc)
        return "Fail", _('Local Storage profile %s not imported.') % profile_name, str(exc)

    return "Success", _('Local Storage profile %s successfully imported.') % profile_name, None


###################
# CHECK
###################
def _check_profilename(profilename):
    # Check if profile name already exists
    iprofiles = pecan.request.dbapi.ihost_get_list(recordtype="profile")
    for profile in iprofiles:
        if profile.hostname == profilename:
            raise wsme.exc.ClientSideError(_("Profile name already exists: %s."
                                             % profilename))

    # Check if profile name = hostname
    ihosts = pecan.request.dbapi.ihost_get_list(recordtype="standard")
    for host in ihosts:
        if host.hostname == profilename:
            raise wsme.exc.ClientSideError(_("Profile name must be different "
                                             "than host name. %s" % profilename))

    return True


def _get_profiletype(profile):
    profile_id = profile['id']

    profile.cpus = pecan.request.dbapi.icpu_get_by_ihost(profile_id)
    if profile.cpus:
        profile.nodes = pecan.request.dbapi.inode_get_by_ihost(profile_id)
        return constants.PROFILE_TYPE_CPU

    profile.ethernet_ports = pecan.request.dbapi.ethernet_port_get_by_host(
        profile_id)
    if profile.ethernet_ports:
        return constants.PROFILE_TYPE_INTERFACE

    profile.memory = pecan.request.dbapi.imemory_get_by_ihost(profile_id)
    if profile.memory:
        profile.nodes = pecan.request.dbapi.inode_get_by_ihost(profile_id)
        return constants.PROFILE_TYPE_MEMORY

    profile.istor = pecan.request.dbapi.istor_get_by_ihost(profile_id)
    if profile.istor:
        return constants.PROFILE_TYPE_STORAGE

    profile.ilvgs = pecan.request.dbapi.ilvg_get_by_ihost(profile_id)
    if profile.ilvgs:
        return constants.PROFILE_TYPE_LOCAL_STORAGE

    return constants.PROFILE_TYPE_STORAGE
    raise wsme.exc.ClientSideError(
        _("Profile not found: %s" % profile['hostname']))

    return None


###################
# CREATE
###################
def profile_copy_data(host, profile, profiletype):
    profile.profiletype = profiletype
    if constants.PROFILE_TYPE_CPU in profiletype.lower():
        return cpuprofile_copy_data(host, profile)
    elif constants.PROFILE_TYPE_INTERFACE in profiletype.lower():
        return ifprofile_copy_data(host, profile)
    elif constants.PROFILE_TYPE_MEMORY in profiletype.lower():
        return memoryprofile_copy_data(host, profile)
    elif constants.PROFILE_TYPE_STORAGE in profiletype.lower():
        return storprofile_copy_data(host, profile)
    elif constants.PROFILE_TYPE_LOCAL_STORAGE in profiletype.lower():
        return localstorageprofile_copy_data(host, profile)
    else:
        raise wsme.exc.ClientSideError(_("Must provide a value for 'profiletype'. "
                                         "Choose from: cpu, if, stor, memory"))


def cpuprofile_copy_data(host, profile):
    # Copy nodes and cpus from host
    inodes = pecan.request.dbapi.inode_get_by_ihost(host['id'])
    icpus = pecan.request.dbapi.icpu_get_by_ihost(host['id'])

    iprofile_id = profile['id']
    for n in inodes:
        n.forihostid = iprofile_id
        nodefields = ['numa_node', 'capabilities', 'forihostid']
        ndict = {k: v for (k, v) in n.as_dict().items() if k in nodefields}
        new_node = pecan.request.dbapi.inode_create(iprofile_id, ndict)

        for c in icpus:
            if c.forinodeid == n.id:
                c.forihostid = iprofile_id
                c.forinodeid = new_node.id
                cpufields = ['cpu', 'numa_node', 'core', 'thread', 'allocated_function',
                             'cpu_model', 'cpu_family', 'capabilities',
                             'forihostid', 'forinodeid']
                cdict = {k: v for (k, v) in c.as_dict().items() if k in cpufields}
                pecan.request.dbapi.icpu_create(iprofile_id, cdict)


ROUTE_FIELDS = ['family', 'network', 'prefix', 'gateway', 'metric']


def _get_routes(host_id):
    """
    Get routes associated to any interface on this host and then index by
    interface uuid value.
    """
    result = {}
    routes = pecan.request.dbapi.routes_get_by_host(host_id)
    for r in routes:
        interface_uuid = r['interface_uuid']
        if interface_uuid not in result:
            result[interface_uuid] = []
        route = {k: v for (k, v) in r.as_dict().items() if k in ROUTE_FIELDS}
        result[interface_uuid].append(route)
    return result


def ifprofile_copy_data(host, profile):
    # Copy interfaces and ports from host
    ethernet_ports = pecan.request.dbapi.ethernet_port_get_by_host(host['id'])
    iinterfaces = pecan.request.dbapi.iinterface_get_by_ihost(host['id'])
    routes = _get_routes(host['id'])

    iprofile_id = profile['id']
    newIfList = []
    for i in iinterfaces:
        i.forihostid = iprofile_id
        iffields = INTERFACE_PROFILE_FIELDS
        idict = {k: v for (k, v) in i.as_dict().items() if k in iffields}
        idict['interface_profile'] = True
        newIf = interface_api._create(idict, from_profile=True)
        newIfList.append(newIf)

        for r in routes.get(i.uuid, []):
            pecan.request.dbapi.route_create(newIf.id, r)

        for p in ethernet_ports:
            if p.interface_id == i.id:
                p.host_id = iprofile_id
                p.interface_id = newIf.id

                # forinodeid attribute for 001 only.
                if hasattr(p, 'forinodeid'):
                    p.forinodeid = None

                ethernet_port_fields = ['name', 'pclass', 'pvendor', 'pdevice',
                                        'psvendor', 'psdevice', 'mtu', 'speed',
                                        'link_mode', 'bootp', 'pciaddr', 'dev_id',
                                        'host_id', 'interface_id', 'node_id']
                pdict = {k: v for (k, v) in p.as_dict().items() if k in ethernet_port_fields}
                pecan.request.dbapi.ethernet_port_create(iprofile_id, pdict)

        if i.ifclass == constants.INTERFACE_CLASS_PLATFORM:
            interface_networks = pecan.request.dbapi.interface_network_get_by_interface(i.id)
            for ifnet in interface_networks:
                ifnetdict = {}
                ifnetdict['interface_id'] = newIf.id
                ifnetdict['network_id'] = ifnet.network_id
                pecan.request.dbapi.interface_network_create(ifnetdict)
        else:
            interface_datanetworks = pecan.request.dbapi.interface_datanetwork_get_by_interface(i.id)
            for ifdn in interface_datanetworks:
                ifdndict = {}
                ifdndict['interface_id'] = newIf.id
                ifdndict['datanetwork_id'] = ifdn.datanetwork_id
                pecan.request.dbapi.interface_datanetwork_create(ifdndict)

    # Generate the uses/used_by relationships
    for i in newIfList:
        uses_list = []
        uses_uuid_list = []
        for u in iinterfaces:
            if u.ifname == i.ifname:
                uses_list = u.uses[:]
                break

        for u in uses_list:
            for interface in newIfList:
                if u == interface.ifname:
                    uses_uuid_list.append(interface.uuid)
                    continue

        idict = {}
        idict['uses'] = uses_uuid_list
        try:
            pecan.request.dbapi.iinterface_update(i.uuid, idict)
        except Exception as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Failed to link interface uses."))


def _storprofile_copy_stor(profile, disk, stor):
    # Create disk.
    diskfields = ['device_node', 'device_path', 'device_num',
                  'device_type', 'size_mib',
                  'serial_id', 'capabilities',
                  'forihostid']
    ddict = {k: v for (k, v) in disk.as_dict().items() if k in diskfields}
    newdisk = pecan.request.dbapi.idisk_create(profile.id, ddict)

    # Create stor.
    stor.forihostid = profile.id
    stor.idisk_uuid = newdisk.uuid
    storfields = ['function', 'idisk_uuid', 'forihostid', 'fortierid',
                  'journal_location', 'journal_size_mib']
    sdict = {k: v for (k, v) in stor.as_dict().items() if k in storfields}
    # This goes through istor semantic checks versus just adding to db (by
    # calling dbapi.istor_create).
    newstor = storage_api._create(sdict, iprofile=True)

    # If disk or stor weren't actually created, then delete profile and exit.
    if not newdisk or not newstor:
        raise wsme.exc.ClientSideError(
            _("Could not create storage volumes or disks "
              "for profile %s" % profile.hostname))
    return newstor


def storprofile_copy_data(host, profile):
    # get host data
    istors = pecan.request.dbapi.istor_get_by_ihost(host['id'])
    idisks = pecan.request.dbapi.idisk_get_by_ihost(host['id'])

    if not idisks or not istors:
        raise wsme.exc.ClientSideError(_("Storage profile cannot be created if there "
                                         "are no disks associated to storage volumes. "
                                         "Add storage volumes then try again."))

    # first copy the journal stors from host and store the association
    # between old journal_locations and the new ones
    journals = {}
    for d in idisks:
        for s in istors:
            if (d.foristorid == s.id and
                    s.function == constants.STOR_FUNCTION_JOURNAL):
                s_ret = _storprofile_copy_stor(profile, d, s)
                association = {s.uuid: s_ret.uuid}
                journals.update(association)

    # copy the rest of the stors from host
    for d in idisks:
        for s in istors:
            if (d.foristorid == s.id and
                    s.function != constants.STOR_FUNCTION_JOURNAL):
                # replace the old journal location with the new one
                if s.journal_location in journals:
                    s.journal_location = journals[s.journal_location]
                else:
                    # collocated, clean journal location
                    s.journal_location = None
                _storprofile_copy_stor(profile, d, s)


def _create_disk_profile(disk, iprofile_id):
    fields = ['device_node', 'device_path', 'device_num', 'device_type',
              'size_mib', 'serial_id', 'capabilities']
    disk_profile_dict = {k: v for (k, v) in disk.as_dict().items()
                         if k in fields}

    disk_profile_dict['forihostid'] = iprofile_id

    try:
        disk_profile = pecan.request.dbapi.idisk_create(
            iprofile_id, disk_profile_dict)
    except Exception as e:
        err_msg = '{} {}: {}'.format(
            "Could not create disk profile from disk", disk.uuid, str(e))
        raise wsme.exc.ClientSideError(_(err_msg))

    return disk_profile


def _create_partition_profile(partition, iprofile_id):
    fields = ['device_node', 'device_path', 'size_mib', 'capabilities',
              'type_guid', 'status']
    part_profile_dict = {k: v for (k, v) in partition.as_dict().items()
                         if k in fields}
    # Obtain all the disks of the current profile.
    profile_disks = pecan.request.dbapi.idisk_get_by_ihost(iprofile_id)

    # Obtain the disk this partition is residing on.
    disk = pecan.request.dbapi.idisk_get(partition.idisk_uuid)

    # Check if the current profile already has the disk needed for the
    # required partition.
    disk_profile = None
    if profile_disks:
        disk_profile = next((d for d in profile_disks
                            if (d.device_path == disk.device_path or
                                d.device_node == disk.device_node)),
                            None)

    if disk_profile is None:
        disk_profile = _create_disk_profile(disk, iprofile_id)

    part_profile_dict['forihostid'] = iprofile_id
    part_profile_dict['status'] = constants.PARTITION_CREATE_ON_UNLOCK_STATUS
    part_profile_dict['idisk_id'] = disk_profile.id
    part_profile_dict['idisk_uuid'] = disk_profile.uuid

    try:
        part_profile = pecan.request.dbapi.partition_create(iprofile_id,
                                                            part_profile_dict)
    except Exception as e:
        err_msg = '{} {}: {}'.format(
            "Could not create partition profile from partition",
            partition.uuid, str(e))
        raise wsme.exc.ClientSideError(_(err_msg))

    return part_profile


def _create_device_profile(device, pv_type, iprofile_id):
    """Create a profile disk or partition, depending on the physical volume
       type."""
    device_profile = None

    if pv_type == constants.PV_TYPE_DISK:
        device_profile = _create_disk_profile(device, iprofile_id)
    elif pv_type == constants.PV_TYPE_PARTITION:
        device_profile = _create_partition_profile(device, iprofile_id)

    return device_profile


def localstorageprofile_copy_data(host, profile):
    """Create nova-local storage profile from host data

       All workers will have nova local storage and is independent of
       the Cinder backend.

       Controller nodes in the  small footprint scenario will always be
       the Cinder/LVM configuration and nova local storage.
       Ceph is not supported for the backend in the small footprint.

       A storage node should be the only host with a stor profile
       (idisks + istors).

       A worker will only have a local stor profile
       (idisks + ipvs + ilvgs).

       A combo controller should have a local stor profile
       (idisks + ipvs + ilvgs) BUT we need to filter out the ipvs and ilvgs
       not associated with the nova-local volume group since there are the
       cinder-volumes and cgts-vg volume groups.

       A normal controller should have no storage profiles.
    """

    hostid = host['id']
    idisks = pecan.request.dbapi.idisk_get_by_ihost(hostid)
    partitions = pecan.request.dbapi.partition_get_by_ihost(hostid)

    ilvgs_all = pecan.request.dbapi.ilvg_get_by_ihost(hostid)
    ilvgs = [ilvg for ilvg in ilvgs_all if constants.LVG_NOVA_LOCAL
             in ilvg.lvm_vg_name]

    ipvs = pecan.request.dbapi.ipv_get_by_ihost(hostid)

    if not idisks or not ilvgs or not ipvs:
        raise wsme.exc.ClientSideError(_("Storage profile cannot be "
            "created if there are no disks associated to logical volume "
            "groups or physical volumes.  Check %s storage configuration "
            "then try again." % host['hostname']))

    # Keep track of partitions used by PVs.
    used_partitions = []

    if len(ilvgs) > 1:
        LOG.warn("ilvgs %s contain more than one nova local lvg" % ilvgs)

    ilvg = ilvgs[0]

    # Copy local storage configuration from host to new profile.
    iprofile_id = profile.id

    # Create new profile logical volume.
    lvgfields = ['capabilities', 'lvm_vg_name']
    lvgdict = {k: v for (k, v) in ilvg.as_dict().items() if k in lvgfields}
    lvgdict['forihostid'] = iprofile_id
    LOG.debug("lvgdict=%s" % lvgdict)
    lvg_pf = lvg_api._create(lvgdict, iprofile=True)
    LOG.info("lvg_pf=%s" % lvg_pf.as_dict())

    for ipv in ipvs:
        if ipv.forilvgid != ilvg.id:
            continue

        device = None
        # Gather the info about the disk/partition used by the current PV.
        if ipv.get('pv_type') == constants.PV_TYPE_DISK:
            try:
                pv_disk = pecan.request.dbapi.idisk_get_by_ipv(ipv.get('uuid'))
            except Exception:
                err_msg = '{} {}'.format("Could not obtain the disk used by "
                                         "physical volume", ipv.get('uuid'))
                raise wsme.exc.ClientSideError(_(err_msg))

            device = pv_disk[0]

        elif ipv.get('pv_type') == constants.PV_TYPE_PARTITION:
            try:
                pv_part = pecan.request.dbapi.partition_get_by_ipv(
                    ipv.get('uuid'))
            except Exception:
                err_msg = '{} {}'.format("Could not obtain the partition "
                                         "used by physical volume",
                                         ipv.get('uuid'))
                raise wsme.exc.ClientSideError(_(err_msg))

            device = pv_part[0]
            used_partitions.append(device)

        # Create the profile object for the device used by the current PV.
        device_profile = _create_device_profile(
            device, ipv.get('pv_type'), iprofile_id)

        # Create new profile physical volume.
        pvfields = ['disk_or_part_device_node', 'disk_or_part_device_path',
                    'lvm_vg_name', 'pv_type']
        # 'lvm_pv_name', from Agent, not in profile.

        pvdict = {k: v for (k, v) in ipv.as_dict().items() if k in pvfields}
        pvdict['disk_or_part_uuid'] = device_profile.uuid
        pvdict['forihostid'] = iprofile_id
        pvdict['forilvgid'] = lvg_pf.id
        pv_profile = pv_api._create(pvdict, iprofile=True)
        LOG.info("pv_pf=%s" % pv_profile.as_dict())

        if not device_profile or not lvg_pf or not pv_profile:
            hostname = profile.hostname
            pecan.request.dbapi.ihost_destroy(iprofile_id)
            emsg = ("Could not create local storage profile from host %s"
                    % hostname)
            LOG.error("%s ddict=%s, lvg_pf=%s, pv_pf=%s" %
                      (emsg, device.as_dict(), lvg_pf.as_dict(),
                       pv_profile.as_dict()))
            raise wsme.exc.ClientSideError(_(emsg))

    # Create profiles for other remaining partitions.
    unused_partitions = [
        p for p in partitions if p.device_path not in
        [used_part.device_path for used_part in used_partitions]]

    for p in unused_partitions:
        if p.type_guid == constants.USER_PARTITION_PHYSICAL_VOLUME:
            _create_partition_profile(p, iprofile_id)


def memoryprofile_copy_data(host, profile):
    # check if the node is provisioned
    if host.invprovision != constants.PROVISIONED:
        raise wsme.exc.ClientSideError(_("Could not create memory "
                "profile until host %s is unlocked for the first time." %
                                         host.hostname))

    # Copy hugepage information from host
    inodes = pecan.request.dbapi.inode_get_by_ihost(host['id'])
    memory = pecan.request.dbapi.imemory_get_by_ihost(host['id'])

    iprofile_id = profile['id']
    for n in inodes:
        n.forihostid = iprofile_id
        nodefields = ['numa_node', 'capabilities', 'forihostid']
        ndict = {k: v for (k, v) in n.as_dict().items() if k in nodefields}
        new_node = pecan.request.dbapi.inode_create(iprofile_id, ndict)
        for m in memory:
            if m.forinodeid == n.id:
                m.forihostid = iprofile_id
                m.forinodeid = new_node.id
                memfields = ['numa_node', 'forihostid', 'forinodeid']
                mdict = {k: v for (k, v) in m.as_dict().items() if k in memfields}
                mdict['platform_reserved_mib'] = m.platform_reserved_mib
                mdict['vm_hugepages_nr_2M_pending'] = m.vm_hugepages_nr_2M
                mdict['vm_hugepages_nr_1G_pending'] = m.vm_hugepages_nr_1G
                mdict['vswitch_hugepages_reqd'] = m.vswitch_hugepages_nr
                mdict['vswitch_hugepages_size_mib'] = m.vswitch_hugepages_size_mib
                newmemory = pecan.request.dbapi.imemory_create(iprofile_id, mdict)

                # if memory wasn't actualy created,
                # then delete profile and exit
                if not newmemory:
                    raise wsme.exc.ClientSideError(_("Could not create memory "
                                                     "profile %s" % profile.hostname))


###################
# DELETE
###################
def profile_delete_data(profile):
    profiletype = _get_profiletype(profile)
    if constants.PROFILE_TYPE_CPU in profiletype.lower():
        return cpuprofile_delete_data(profile)
    elif constants.PROFILE_TYPE_INTERFACE in profiletype.lower():
        return ifprofile_delete_data(profile)
    elif constants.PROFILE_TYPE_STORAGE in profiletype.lower():
        return storprofile_delete_data(profile)
    elif constants.PROFILE_TYPE_MEMORY in profiletype.lower():
        return memoryprofile_delete_data(profile)
    else:
        return False


def cpuprofile_delete_data(profile):
    for cpu in profile.cpus:
        pecan.request.dbapi.icpu_destroy(cpu.uuid)
    for node in profile.nodes:
        pecan.request.dbapi.inode_destroy(node.uuid)


def ifprofile_delete_data(profile):
    profile.interfaces = pecan.request.dbapi.iinterface_get_by_ihost(profile['id'])
    for p in profile.ethernet_ports:
        pecan.request.dbapi.ethernet_port_destroy(p.uuid)
    for i in profile.interfaces:
        pecan.request.dbapi.iinterface_destroy(i.uuid)


def storprofile_delete_data(profile):
    profile.stors = pecan.request.dbapi.istor_get_by_ihost(profile['id'])
    profile.disks = pecan.request.dbapi.idisk_get_by_ihost(profile['id'])
    for stor in profile.stors:
        pecan.request.dbapi.idisk_update(stor.idisk_uuid, {'foristorid': None})
        pecan.request.dbapi.istor_destroy(stor.uuid)
    for disk in profile.disks:
        pecan.request.dbapi.idisk_destroy(disk.uuid)


def memoryprofile_delete_data(profile):
    profile.memory = pecan.request.dbapi.imemory_get_by_ihost(profile['id'])
    for m in profile.memory:
        pecan.request.dbapi.imemory_destroy(m.uuid)
    for node in profile.nodes:
        pecan.request.dbapi.inode_destroy(node.uuid)


###################
# APPLY
###################
def apply_profile(host_id, profile_id):
    host = pecan.request.dbapi.ihost_get(host_id)
    profile = pecan.request.dbapi.ihost_get(profile_id)

    """
    NOTE (neid):
        if adding a functionality for some or 'all' profiles (eg applying cpu, if AND stor)
        replace 'elif' with 'if' and do not 'return' after each callable
        That way, can cycle through some or all of cpus, if, stors based on what's
        included in the profile and apply the relevant items

        TODO:   might need an action to continue on next profile type even if exception raised?
                eg: if failed to apply cpuprofile, report error and continue to apply ifprofile
    """
    profiletype = _get_profiletype(profile)
    if constants.PROFILE_TYPE_CPU in profiletype.lower():
        return cpuprofile_apply_to_host(host, profile)
    elif constants.PROFILE_TYPE_INTERFACE in profiletype.lower():
        return ifprofile_apply_to_host(host, profile)
    elif constants.PROFILE_TYPE_MEMORY in profiletype.lower():
        return memoryprofile_apply_to_host(host, profile)
    elif constants.PROFILE_TYPE_STORAGE in profiletype.lower():
        return storprofile_apply_to_host(host, profile)
    elif constants.PROFILE_TYPE_LOCAL_STORAGE in profiletype.lower():
        return localstorageprofile_apply_to_host(host, profile)
    else:
        raise wsme.exc.ClientSideError("Profile %s is not applicable to host" %
                                       profiletype)


@cutils.synchronized(cpu_api.LOCK_NAME)
def cpuprofile_apply_to_host(host, profile):
    host.cpus = pecan.request.dbapi.icpu_get_by_ihost(host.uuid, sort_key=['forinodeid', 'core', 'thread'])
    host.nodes = pecan.request.dbapi.inode_get_by_ihost(host.uuid, sort_key='numa_node')
    if not host.cpus or not host.nodes:
        raise wsme.exc.ClientSideError("Host (%s) has no processors "
                                       "or cores." % host.hostname)

    profile.cpus = pecan.request.dbapi.icpu_get_by_ihost(profile.uuid, sort_key=['forinodeid', 'core', 'thread'])
    profile.nodes = pecan.request.dbapi.inode_get_by_ihost(profile.uuid, sort_key='numa_node')
    if not profile.cpus or not profile.nodes:
        raise wsme.exc.ClientSideError("Profile (%s) has no processors "
                                       "or cores." % profile.hostname)

    h_struct = cpu_utils.HostCpuProfile(host.subfunctions, host.cpus, host.nodes)
    cpu_profile = cpu_utils.CpuProfile(profile.cpus, profile.nodes)

    errorstring = h_struct.profile_applicable(cpu_profile)

    if errorstring:
        raise wsme.exc.ClientSideError(errorstring)

    numa_node_idx = -1
    core_idx = 0
    cur_numa_node = None
    cur_core = None
    for hcpu in host.cpus:
        if hcpu.numa_node != cur_numa_node:
            cur_numa_node = hcpu.numa_node
            numa_node_idx += 1
            core_idx = 0
            cur_core = hcpu.core
            p_processor = cpu_profile.processors[numa_node_idx]
            vswitch_core_start = p_processor.platform
            shared_core_start = p_processor.vswitch + vswitch_core_start
            vm_core_start = p_processor.shared + shared_core_start
            vm_core_end = p_processor.vms + vm_core_start
        else:
            if hcpu.core != cur_core:
                core_idx += 1
                cur_core = hcpu.core

        if core_idx < vswitch_core_start:
            new_func = constants.PLATFORM_FUNCTION
        elif core_idx < shared_core_start:
            new_func = constants.VSWITCH_FUNCTION
        elif core_idx < vm_core_start:
            new_func = constants.SHARED_FUNCTION
        elif core_idx < vm_core_end:
            new_func = constants.APPLICATION_FUNCTION

        if new_func != hcpu.allocated_function:
            values = {'allocated_function': new_func}
            cpu_api._update(hcpu.uuid, values, from_profile=True)


def ifprofile_applicable(host, profile):
    # If profile does not have the same number of ethernet ports than in host
    if len(host.ethernet_ports) != len(profile.ethernet_ports):
        raise wsme.exc.ClientSideError(_(
            "Cannot apply the profile to host: "
            "Number of ethernet ports not the same on host %s (%s) and "
            "profile %s (%s)" %
            (host.hostname, len(host.ethernet_ports), profile.hostname,
             len(profile.ethernet_ports))))

    # Check if the ethernet ports and their pci addresses have exact match
    hset = set((h.name, h.pciaddr) for h in host.ethernet_ports)
    pset = set((p.name, p.pciaddr) for p in profile.ethernet_ports)
    if hset != pset:
        raise wsme.exc.ClientSideError(_(
            "Cannot apply the profile to host: "
            "The port PCI devices are not the same in host %s and profile "
            "%s." % (host.hostname, profile.hostname)))


def interface_type_sort_key(interface):
    """Sort interfaces by interface type placing ethernet interfaces ahead of
    aggregated ethernet interfaces, and vlan interfaces last."""
    if interface["iftype"] == constants.INTERFACE_TYPE_ETHERNET:
        return 0, interface["ifname"]
    elif interface["iftype"] == constants.INTERFACE_TYPE_AE:
        return 1, interface["ifname"]
    elif interface["iftype"] == constants.INTERFACE_TYPE_VLAN:
        return 2, interface["ifname"]
    else:
        return 99, interface["ifname"]


@cutils.synchronized(interface_api.LOCK_NAME)
def ifprofile_apply_to_host(host, profile):
    host.ethernet_ports = pecan.request.dbapi.ethernet_port_get_by_host(host.uuid)
    host.interfaces = pecan.request.dbapi.iinterface_get_by_ihost(host.uuid)
    if not host.ethernet_ports:
        raise wsme.exc.ClientSideError(_("Host (%s) has no ports." % host.hostname))

    profile.ethernet_ports = pecan.request.dbapi.ethernet_port_get_by_host(profile.uuid)
    profile.interfaces = pecan.request.dbapi.iinterface_get_by_ihost(profile.uuid)
    profile.routes = _get_routes(profile.id)

    ifprofile_applicable(host, profile)

    # Create Port Mapping between Interface Profile and Host
    pci_addr_available = True
    eth_name_available = True
    for port in profile.ethernet_ports:
        if not port.pciaddr:
            pci_addr_available = False
        if not port.name:
            eth_name_available = False

    if pci_addr_available:

        def match_express(hport, port):
            return hport.pciaddr == port.pciaddr
    elif eth_name_available:

        def match_express(hport, port):
            return hport.name == port.name
    portPairings = []
    hostPortsUsed = []

    for port in profile.ethernet_ports:
        bestmatch = False
        for hport in host.ethernet_ports:
            if (hport.id not in hostPortsUsed and
                    port.pclass == hport.pclass and
                    port.pdevice == hport.pdevice):

                if match_express(hport, port):
                    hostPortsUsed.append(hport.id)
                    portPairings.append((hport, port))
                    bestmatch = True
                    break
        if not bestmatch:
            raise wsme.exc.ClientSideError(_("Cannot apply this profile to host."))

    prts = []
    for host_interface in host.interfaces:
        # Save a list of the interfaces and ports per interface
        ports = pecan.request.dbapi.ethernet_port_get_by_interface(host_interface.uuid)
        for p in ports:
            prts.append((host_interface, p))

    # Unlink all ports from their interfaces.
    for p in host.ethernet_ports:
        data = {'interface_id': None}
        try:
            pecan.request.dbapi.ethernet_port_update(p.uuid, data)
        except dbException.DBError:
            raise wsme.exc.ClientSideError(_("Failed to unlink port from interface."))

    # Delete all Host's interfaces in reverse order (VLANs, AEs, ethernet, etc)
    for i in sorted(host.interfaces, key=interface_type_sort_key, reverse=True):
        try:
            # Re-read the interface from the DB because the uses/used_by list
            # would have been updated by any preceeding delete operations.
            interface = pecan.request.dbapi.iinterface_get(
                i['ifname'], host.uuid)
            interface_api._delete(interface, from_profile=True)
        except Exception as e:
            LOG.exception("Failed to delete existing"
                          " interface {}; {}".format(i['ifname'], e))

    # Create New Host's interfaces and link them to Host's ports
    interfacePairings = {}
    for portPair in portPairings:
        hport = portPair[0]
        port = portPair[1]

        if port.interface_id not in interfacePairings.keys():
            for interface in profile.interfaces:
                if interface.id == port.interface_id:
                    break
            else:
                raise wsme.exc.ClientSideError(_("Corrupt interface profile: %s." % profile.hostname))
            try:
                fields = INTERFACE_PROFILE_FIELDS
                data = dict((k, v) for k, v in interface.as_dict().items() if k in fields)
                data['forihostid'] = host.id
                data['imac'] = hport.mac
                interface_found = False
                iinterfaces = pecan.request.dbapi.iinterface_get_by_ihost(host.id)
                for u in iinterfaces:
                    if str(u.ifname) == str(data['ifname']):
                        interface_found = True
                        break

                if interface_found is False:
                    hinterface = interface_api._create(data, from_profile=True)
                    if interface.ifclass == constants.INTERFACE_CLASS_PLATFORM:
                        interface_networks = pecan.request.dbapi.interface_network_get_by_interface(interface.id)
                        for ifnet in interface_networks:
                            ifnetdict = {}
                            ifnetdict['interface_id'] = hinterface.id
                            ifnetdict['network_id'] = ifnet.network_id
                            pecan.request.dbapi.interface_network_create(ifnetdict)
                            network = pecan.request.dbapi.network_get_by_id(ifnet.network_id)
                            ifnet_api._update_host_address(host, hinterface, network.type)
                    else:
                        interface_datanetworks = pecan.request.dbapi.interface_datanetwork_get_by_interface(interface.id)
                        for ifdn in interface_datanetworks:
                            ifdndict = {}
                            ifdndict['interface_id'] = hinterface.id
                            ifdndict['datanetwork_id'] = ifdn.datanetwork_id
                            pecan.request.dbapi.interface_datanetwork_create(ifdndict)

            except Exception as e:
                # Delete all Host's interfaces
                for p in host.ethernet_ports:
                    data = {'interface_id': None}
                    try:
                        pecan.request.dbapi.ethernet_port_update(p.uuid, data)
                    except dbException.DBError:
                        LOG.debug(_("Failed to unlink port from interface."))

                for i in host.interfaces:
                    try:
                        interface_api._delete(i.as_dict(), from_profile=True)
                    except exception.SysinvException:
                        LOG.debug(_("Can not delete host interface: %s" % i.uuid))

                # Restore the previous interfaces
                for host_interface in host.interfaces:
                    try:
                        fields = INTERFACE_PROFILE_FIELDS
                        data = dict((k, v) for k, v in host_interface.as_dict().items() if k in fields)
                        data['forihostid'] = host.id
                        hinterface = interface_api._create(data, from_profile=True)
                    except Exception as e:
                        LOG.exception(e)
                        raise wsme.exc.ClientSideError(_("Failed to create interface."))

                    # Restore the ports per interface
                    data = {'interface_id': hinterface.id}
                    for p in prts:
                        h_interface = p[0]
                        h_port = p[1]

                        if h_interface.ifname == hinterface.ifname:
                            try:
                                pecan.request.dbapi.ethernet_port_update(h_port.uuid, data)
                            except Exception as e:
                                LOG.exception(e)

                LOG.exception(e)
                raise wsme.exc.ClientSideError(_("Failed to update interface."))
        interfacePairings[port.interface_id] = hinterface.id
        data = {'interface_id': interfacePairings[port.interface_id]}
        try:
            pecan.request.dbapi.ethernet_port_update(hport.uuid, data)
        except Exception as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Failed to link port to interface."))

    # update interface pairings
    iinterfaces = pecan.request.dbapi.iinterface_get_by_ihost(host.id)
    for i in profile.interfaces:
        found_interface = False
        for u in iinterfaces:
            if i.ifname == u.ifname:
                found_interface = True
                hinterface = u
                break
        if found_interface is False:
            fields = INTERFACE_PROFILE_FIELDS
            data = dict((k, v) for k, v in i.as_dict().items() if k in fields)
            data['forihostid'] = host.id
            hinterface = interface_api._create(data, from_profile=True)

            if i.ifclass == constants.INTERFACE_CLASS_PLATFORM:
                interface_networks = pecan.request.dbapi.interface_network_get_by_interface(i.id)
                for ifnet in interface_networks:
                    ifnetdict = {}
                    ifnetdict['interface_id'] = hinterface.id
                    ifnetdict['network_id'] = ifnet.network_id
                    pecan.request.dbapi.interface_network_create(ifnetdict)
                    network = pecan.request.dbapi.network_get_by_id(ifnet.network_id)
                    ifnet_api._update_host_address(host, hinterface, network.type)
            else:
                interface_datanetworks = pecan.request.dbapi.interface_datanetwork_get_by_interface(i.id)
                for ifdn in interface_datanetworks:
                    ifdndict = {}
                    ifdndict['interface_id'] = hinterface.id
                    ifdndict['datanetwork_id'] = ifdn.datanetwork_id
                    pecan.request.dbapi.interface_datanetwork_create(ifdndict)

        for r in profile.routes.get(i.uuid, []):
            pecan.request.dbapi.route_create(hinterface.id, r)

    iinterfaces = pecan.request.dbapi.iinterface_get_by_ihost(host.id)

    # interfaces need to be associated to each other based on their hierarchy
    # to ensure that inspecting the uses list to have complete data before
    # copying fields.
    iinterfaces = sorted(iinterfaces, key=interface_type_sort_key)

    for i in iinterfaces:
        idict = {}
        for p in profile.interfaces:
            if str(p.ifname) == str(i.ifname):
                i.uses = p.uses
                i.used_by = p.used_by

        if i.uses:
            # convert uses from ifname to uuid
            uses_list = []
            usedby_list = []
            for u in iinterfaces:
                if six.text_type(u.ifname) in i.uses or u.uuid in i.uses:
                    uses_list.append(u.uuid)
                if six.text_type(u.ifname) in i.used_by or u.uuid in i.used_by:
                    usedby_list.append(u.uuid)

            idict['uses'] = uses_list
            idict['used_by'] = usedby_list

            # Set the MAC address on the interface based on the uses list
            tmp_interface = i.as_dict()
            tmp_interface.update(idict)
            tmp_interface = interface_api.set_interface_mac(host, tmp_interface)
            idict['imac'] = tmp_interface['imac']

            try:
                pecan.request.dbapi.iinterface_update(i.uuid, idict)
            except Exception as e:
                LOG.exception(e)
                raise wsme.exc.ClientSideError(_(
                    "Failed to link interfaces to interface."))


def storprofile_applicable(host, profile):
    # If profile has more disks than in host.
    if not len(host.disks) >= len(profile.disks):
        return (False, _('profile has more disks than host does'))

    return (True, None)


@cutils.synchronized(storage_api.LOCK_NAME)
def storprofile_apply_to_host(host, profile):
    # Prequisite checks
    profile.disks = pecan.request.dbapi.idisk_get_by_ihost(profile.uuid)
    profile.stors = pecan.request.dbapi.istor_get_by_ihost(profile.uuid)
    if not profile.disks:
        raise wsme.exc.ClientSideError(_("Profile (%s) has no disks" % profile.hostname))

    host.disks = pecan.request.dbapi.idisk_get_by_ihost(host.uuid)
    host.stors = pecan.request.dbapi.istor_get_by_ihost(host.uuid)
    if not host.disks:
        raise wsme.exc.ClientSideError(_("Host (%s) has no disks" % host.hostname))

    # Check for applicability
    (applicable, reason) = storprofile_applicable(host, profile)
    if not applicable:
        raise wsme.exc.ClientSideError(_("Can not apply this profile to host. Reason: {}").format(reason))

    # Gather the storage tiers and build a map for the create call
    tier_map = {}
    tiers = pecan.request.dbapi.storage_tier_get_all(type=constants.SB_TIER_TYPE_CEPH)
    for t in tiers:
        tier_map[t.name] = t.uuid

    # Create mapping between Disk Profile and Host
    # if for each disk in the profile, there exists a disk in the host
    # with same path value and more than or equal profile disk's size
    diskPairs = []
    disksUsed = []
    for pdisk in profile.disks:
        match = False
        for hdisk in host.disks:
            if ((hdisk.device_path == pdisk.device_path or
                    hdisk.device_node == pdisk.device_node) and
                    hdisk.size_mib >= pdisk.size_mib):
                match = True
                diskPairs.append((hdisk, pdisk))
                disksUsed.append(hdisk.id)
                break
        if match:
            # matched, continue to next pdisk
            continue
        else:
            msg = _("Can not apply this profile to host. Please "
                    "check if host's disks match profile criteria.")
            raise wsme.exc.ClientSideError(msg)

    # Delete host's stors that will be replaced
    for disk in host.disks:
        # There could be some disks that are on host but not in profile
        if disk.id in disksUsed:
            for stor in host.stors:
                # If this stor was attached to a disk identified in the profile
                # reject applying profile
                if stor.id == disk.foristorid:
                    # deleting stor is not supported
                    # try:
                    #    cc.istor.delete(stor.uuid)
                    # except Exception:
                    msg = _("A storage volume %s is already associated. "
                            "Please delete storage volume before applying profile" % stor.uuid)
                    raise wsme.exc.ClientSideError(msg)

            data = {'foristorid': None}
            try:
                pecan.request.dbapi.idisk_update(disk.uuid, data)
            except Exception as e:
                LOG.exception(e)
                raise wsme.exc.ClientSideError(_("Failed to unlink storage from disk"))

    # OSDs have journals that may be on different drives than the OSD data
    # itself, therefore we first need to create the journals so that we can
    # later grab their real uuid's. To do that, we store an association between
    # the old uuid of the journals in the profile and the uuid of the newly
    # created journals.
    journalPairs = {}
    storPairs = {}
    # Create the journal devices first, keep the association
    _create_stor(host, profile, diskPairs, constants.STOR_FUNCTION_JOURNAL, tier_map,
                 journalPairs, storPairs)

    # Create the OSDs
    _create_stor(host, profile, diskPairs, constants.STOR_FUNCTION_OSD, tier_map,
                 journalPairs, storPairs)

    # Update foristorid for all the disks
    for diskPair in diskPairs:
        hdisk = diskPair[0]
        pdisk = diskPair[1]

        pdata = {'foristorid': storPairs[pdisk.foristorid]}
        try:
            pecan.request.dbapi.idisk_update(hdisk.uuid, pdata)
        except dbException.DBError:
            raise wsme.exc.ClientSideError(_("Failed to link storage to disk"))


def _create_stor(host, profile, diskPairs, function, tier_map,  # input
                 journalPairs, storPairs):                      # input & output

    for diskPair in diskPairs:
        hdisk = diskPair[0]
        pdisk = diskPair[1]

        if pdisk.foristorid not in storPairs.keys():
            for pstor in profile.stors:
                if pstor.id == pdisk.foristorid:
                    break
            else:
                msg = _("Corrupt storage profile: %s" % profile.hostname)
                raise wsme.exc.ClientSideError(msg)

            if pstor.function == function:
                try:
                    fields = ['function', 'capabilities',
                              'idisk_uuid', 'forihostid']
                    if pstor.function == constants.STOR_FUNCTION_OSD:
                        # OSDs have more attributes
                        fields += ['journal_location', 'journal_size']
                    data = dict((k, v) for k, v in pstor.as_dict().items()
                                if k in fields and v)
                    data['forihostid'] = host.id
                    data['idisk_uuid'] = hdisk.uuid
                    if pstor.function == constants.STOR_FUNCTION_OSD:
                        if pstor.journal_location == pstor.uuid:
                            # Journals are collocated, let _create handle this
                            data['journal_location'] = None
                        else:
                            # Journals are on a different drive than the OSD
                            # grab the uuid for the newly created journal stor
                            data['journal_location'] = \
                                journalPairs[pstor.journal_location]
                        data['journal_size_mib'] = pstor['journal_size_mib']

                        # Need a storage tier uuid
                        tier = pstor.get('tier_name')
                        if tier:
                            data['tier_uuid'] = tier_map[tier]
                        else:
                            data['tier_uuid'] = tier_map[
                                constants.SB_TIER_DEFAULT_NAMES[
                                    constants.SB_TIER_TYPE_CEPH]]

                    hstor = storage_api._create(data)
                except Exception as e:
                    LOG.exception(e)
                    raise wsme.exc.ClientSideError(_(
                            "Failed to create storage function. %s") % str(e))

                # Save pairs for later use
                if pstor.function == constants.STOR_FUNCTION_JOURNAL:
                    journalPairs[pstor.uuid] = hstor.uuid
                storPairs[pdisk.foristorid] = hstor.id


def _partition_profile_apply_to_host(host, profile):
    for disk in host.disks:
        profile_partitions = [
            p for p in profile.partitions
            if (disk.device_path in p.device_path or
                disk.device_node in p.device_node)]

        if not profile_partitions:
            LOG.info("No partitions for disk %s" % disk.device_path)
            continue

        profile_partitions_paths = []
        profile_partitions_names = []
        for p in profile.partitions:
            if disk.device_path in p.device_path:
                profile_partitions_paths.append(p.device_path)
            elif disk.device_node in p.device_node:
                profile_partitions_names.append(p.device_node)

        total_part_size = sum(p.size_mib for p in profile_partitions)

        # Check there is enough space on the host's disk to accommodate the
        # profile partitions.
        LOG.info("Disk av space: %s needed: %s" % (disk.available_mib,
                                                   total_part_size))
        if disk.available_mib < total_part_size:
            return (False,
                    _('Not enough free space on disk {0} for profile '
                      'partitions. At least {1} MiB are required.').format(
                        disk.device_path, total_part_size))

        # Check the partition requested by the profile is not already present
        # on the host's disk.
        disk_partitions = pecan.request.dbapi.partition_get_by_idisk(disk.uuid)
        for disk_part in disk_partitions:
            if (disk_part.device_path in profile_partitions_paths or
                    disk_part.device_node in profile_partitions_names):
                return (False,
                        _('Partition {0} already present on disk {1}').format(
                            disk_part.device_path, disk.device_path))

        # Check the partitions requested by the profile and the ones already
        # existing on the host are in order.
        if not cutils.partitions_are_in_order(disk_partitions,
                                              profile_partitions):
            return (False,
                    _('The partitions present in the local storage profile '
                      'cannot be created on disk %s on the requested order. ')
                    .format(disk.device_path))

        # Create the partitions.
        for p in profile_partitions:
            fields = ['size_mib', 'capabilities', 'type_guid', 'status']
            part_dict = {k: v for (k, v) in p.as_dict().items()
                         if k in fields}
            part_dict['forihostid'] = host.id
            part_dict['idisk_id'] = disk.id
            part_dict['idisk_uuid'] = disk.uuid
            partition_api._create(part_dict, iprofile=True)

    return True, None


def check_localstorageprofile_applicable(host, profile):
    """Semantic checks for whether local storage profile is applicable to host.

       Host level administrative checks are already performed earlier in ihost.
    """

    subfunctions = host.subfunctions
    if constants.WORKER not in subfunctions:
        raise wsme.exc.ClientSideError(_("%s with subfunctions: %s "
            "profile %s: Local storage profiles are applicable only to "
            "hosts with 'worker' subfunction." %
            (host.hostname, host.subfunctions, profile.hostname)))

    if not profile.disks:
        raise wsme.exc.ClientSideError(_("Profile (%s) has no disks" %
                                         profile.hostname))
    if not host.disks:
        raise wsme.exc.ClientSideError(_("Host (%s) has no disks" %
                                         host.hostname))
    num_host_disks = len(host.disks)
    num_profile_disks = len(profile.disks)
    if num_host_disks < num_profile_disks:
        raise wsme.exc.ClientSideError(
            "%s profile %s: Number of host disks %s is less than profile "
            "disks %s" %
            (host.hostname, profile.hostname, num_host_disks,
             num_profile_disks))


@cutils.synchronized(lvg_api.LOCK_NAME)
def localstorageprofile_apply_to_host(host, profile):
    """Apply local storage profile to a host
    """
    profile.disks = pecan.request.dbapi.idisk_get_by_ihost(profile.uuid)
    profile.partitions = pecan.request.dbapi.partition_get_by_ihost(
        profile.uuid)
    profile.ilvgs = pecan.request.dbapi.ilvg_get_by_ihost(profile.uuid)
    profile.ipvs = pecan.request.dbapi.ipv_get_by_ihost(profile.uuid)

    host.disks = pecan.request.dbapi.idisk_get_by_ihost(host.uuid)
    host.partitions = pecan.request.dbapi.partition_get_by_ihost(host.uuid)
    host.ipvs = pecan.request.dbapi.ipv_get_by_ihost(host.uuid)

    check_localstorageprofile_applicable(host, profile)

    # Create mapping between Disk Profile and Host
    # if for each disk in the profile, there exists a disk in the host
    # with same path value and more than or equal profile disk's size
    diskPairs = []
    disksUsed = []
    for pdisk in profile.disks:
        match = False
        for hdisk in host.disks:
            if ((hdisk.device_path == pdisk.device_path or
                    hdisk.device_node == pdisk.device_node) and
                    ((hdisk.size_mib is None and pdisk.size_mib is None) or
                     (hdisk.size_mib and pdisk.size_mib and
                      hdisk.size_mib >= pdisk.size_mib))):
                match = True
                diskPairs.append((hdisk, pdisk))
                disksUsed.append(hdisk.id)
                break
        if match:
            # matched, continue to next pdisk
            continue
        else:
            msg = _("Can not apply this profile to host. Please "
                    "check if host's disks match profile criteria.")
            raise wsme.exc.ClientSideError(msg)

    # Delete host's stors that will be replaced
    for disk in host.disks:
        # There could be some disks that are on host but not in profile
        if disk.id in disksUsed:
            for ipv in host.ipvs:
                # If this pv was attached to a disk identified in the profile
                # reject applying profile
                if ipv.id == disk.foripvid:
                    # combo case: there may be already cgts-vg
                    if ipv.lvm_vg_name == constants.LVG_NOVA_LOCAL:
                        msg = _(
                            "A physical volume %s is already associated. "
                            "Please delete physical volume before applying "
                            "profile" % ipv.uuid)
                        raise wsme.exc.ClientSideError(msg)

            # data = {'foripvid': None}
            # try:
            #     pecan.request.dbapi.idisk_update(disk.uuid, data)
            mydisk = pecan.request.dbapi.idisk_get(disk.uuid)
            if mydisk.foripvid:
                LOG.warn("mydisk %s foripvid %s" %
                   (mydisk.uuid, mydisk.foripvid))
            # except Exception as e:
            #     LOG.exception(e)
            #     raise wsme.exc.ClientSideError(_("Failed to unlink physical "
            #         "volume from disk %s" % disk.uuid))

    # Apply partition profile
    result, msg = _partition_profile_apply_to_host(host, profile)
    if not result:
        raise wsme.exc.ClientSideError(msg)

    # Create new host's physical volumes and link them to ihost's disks
    host_id = host.id
    ipvPairs = {}

    # Add the hilvg entry from pilvg
    pilvg = None
    for ilvg in profile.ilvgs:
        if ilvg.lvm_vg_name == constants.LVG_NOVA_LOCAL:
            pilvg = ilvg
            LOG.info("pilvg found: %s" % ilvg.uuid)
            break

    if not pilvg:
        raise wsme.exc.ClientSideError(
            _("No nova-local in profile logical volume"))

    LOG.info("pilvg=%s" % pilvg.as_dict())
    try:
        lvgfields = ['capabilities', 'lvm_vg_name']
        lvgdict = {k: v for (k, v) in pilvg.as_dict().items()
                   if k in lvgfields}
        lvgdict['forihostid'] = host_id

        newlvg = lvg_api._create(lvgdict, applyprofile=True)
    except Exception as e:
        LOG.exception(e)
        raise wsme.exc.ClientSideError(_("Failed to create storage "
                                         "logical volume"))
    LOG.info("newlvg=%s" % newlvg.as_dict())  # TODO: LOG.debug

    hpartitions = pecan.request.dbapi.partition_get_by_ihost(host.uuid)

    for pipv in profile.ipvs:
        found_pv = False
        pv_type = pipv.pv_type
        if pv_type == constants.PV_TYPE_DISK:
            for diskPair in diskPairs:
                hdisk = diskPair[0]
                pdisk = diskPair[1]
                if pdisk.foripvid == pipv.id:
                    disk_or_part_uuid = hdisk.uuid
                    device_update_function = pecan.request.dbapi.idisk_update
                    found_pv = True
                    break
        else:
            for profile_part in profile.partitions:
                if pipv.id == profile_part.foripvid:
                    disk_or_part_uuid = next(
                        hp.uuid for hp in hpartitions
                        if (hp.device_path == profile_part.device_path or
                            hp.device_node == profile_part.device_node))
                    device_update_function = \
                        pecan.request.dbapi.partition_update
                    found_pv = True
                    break

        if not found_pv:
            msg = _("Corrupt storage profile: %s" % profile.hostname)
            raise wsme.exc.ClientSideError(msg)

        try:
            pvfields = ['disk_or_part_device_path',
                        'lvm_vg_name']
            # 'lvm_pv_name', from Agent: not in profile

            pvdict = (dict((k, v) for k, v in pipv.as_dict().items()
                      if k in pvfields and v))
            pvdict['forihostid'] = host_id
            pvdict['disk_or_part_uuid'] = disk_or_part_uuid
            pvdict['forilvgid'] = newlvg.id
            pvdict['pv_state'] = constants.LVG_ADD
            pvdict['pv_type'] = pv_type
            hipv = pv_api._create(pvdict, iprofile=True)
        except Exception as e:
            LOG.exception(e)
            raise wsme.exc.ClientSideError(_("Failed to create storage "
                                             "physical volume"))

        LOG.info("new hipv=%s" % hipv.as_dict())  # TODO: LOG.debug

        ipvPairs[pdisk.foripvid] = hipv.id

        pdata = {'foripvid': ipvPairs[pdisk.foripvid]}
        try:
            device_update_function(disk_or_part_uuid, pdata)
        except dbException.DBError:
            raise wsme.exc.ClientSideError(_(
                "Failed to link storage to device %s" % disk_or_part_uuid))


def memoryprofile_applicable(host, profile):
    # If profile has more nodes than in host
    if not len(host.memory) >= len(profile.memory):
        LOG.warn("Host memory %s not same as profile memory=%s" %
                 (len(host.memory), len(profile.memory)))
        return False
    if len(host.nodes) != len(profile.nodes):
        LOG.warn("Host nodes %s not same as profile nodes=%s" %
                 (len(host.nodes), len(profile.nodes)))
        return False
    if constants.WORKER not in host.subfunctions:
        LOG.warn("Profile cannot be applied to non-worker host")
        return False
    return True


@cutils.synchronized(memory_api.LOCK_NAME)
def memoryprofile_apply_to_host(host, profile):
    # Prequisite checks
    profile.memory = pecan.request.dbapi.imemory_get_by_ihost(profile.uuid)
    profile.nodes = pecan.request.dbapi.inode_get_by_ihost(profile.uuid)
    if not profile.memory or not profile.nodes:
        raise wsme.exc.ClientSideError(_("Profile (%s) has no memory or processors"
                                         % profile.hostname))

    host.memory = pecan.request.dbapi.imemory_get_by_ihost(host.uuid)
    host.nodes = pecan.request.dbapi.inode_get_by_ihost(host.uuid)
    if not host.memory or not host.nodes:
        raise wsme.exc.ClientSideError(_("Host (%s) has no memory or processors"
                                         % host.hostname))

    # Check for applicability
    if not memoryprofile_applicable(host, profile):
        raise wsme.exc.ClientSideError(_("Can not apply this profile to host"))

    # Create mapping between memory profile and host
    # for each node in the profile, there exists a node in the host
    for hmem in host.memory:
        for pmem in profile.memory:
            host_inode = pecan.request.dbapi.inode_get(hmem.forinodeid)
            profile_inode = pecan.request.dbapi.inode_get(pmem.forinodeid)
            if int(host_inode.numa_node) == int(profile_inode.numa_node):
                data = {'vm_hugepages_nr_2M_pending': pmem.vm_hugepages_nr_2M_pending,
                        'vm_hugepages_nr_1G_pending': pmem.vm_hugepages_nr_1G_pending,
                        'platform_reserved_mib': pmem.platform_reserved_mib,
                        'vswitch_hugepages_reqd': pmem.vswitch_hugepages_reqd,
                        'vswitch_hugepages_size_mib': pmem.vswitch_hugepages_size_mib}
                try:
                    memory_api._update(hmem.uuid, data)
                except wsme.exc.ClientSideError as cse:
                    LOG.exception(cse)
                    raise wsme.exc.ClientSideError(_("Failed to update memory. %s" % (cse.message)))
                except Exception as e:
                    LOG.exception(e)
                    raise wsme.exc.ClientSideError(_("Failed to update memory"))
                continue
