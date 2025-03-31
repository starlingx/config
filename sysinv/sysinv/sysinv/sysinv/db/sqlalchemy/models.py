# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- encoding: utf-8 -*-
#
# Copyright 2013 Hewlett-Packard Development Company, L.P.
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
# Copyright (c) 2013-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
SQLAlchemy models for sysinv data.
"""

import json

from six.moves.urllib.parse import urlparse
from oslo_config import cfg
from oslo_db.sqlalchemy import models

from sqlalchemy import Column, ForeignKey, Integer, BigInteger, Boolean
from sqlalchemy import Enum, UniqueConstraint, String, Table, Text, Float
from sqlalchemy import DateTime, LargeBinary
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.ext.declarative import declared_attr
from sqlalchemy.types import TypeDecorator, VARCHAR
from sqlalchemy.orm import relationship, backref

from sysinv.common import constants

UUID_LENGTH = 36

sql_opts = [
    cfg.StrOpt('mysql_engine',
               default='InnoDB',
               help='MySQL engine')
]
cfg.CONF.register_opts(sql_opts, 'database')


def table_args():
    engine_name = urlparse(cfg.CONF.database_connection).scheme
    if engine_name == 'mysql':
        return {'mysql_engine': cfg.CONF.mysql_engine,
                'mysql_charset': "utf8"}
    return None


class JSONEncodedDict(TypeDecorator):
    """Represents an immutable structure as a json-encoded string."""

    impl = VARCHAR

    def process_bind_param(self, value, dialect):
        if value is not None:
            value = json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            value = json.loads(value)
        return value


class SysinvBase(models.TimestampMixin,
                 models.ModelBase):

    metadata = None

    def as_dict(self):
        d = {}
        for c in self.__table__.columns:
            d[c.name] = self[c.name]
        return d

    @classmethod
    def get_query(cls):
        return None


Base = declarative_base(cls=SysinvBase)


class isystem(Base):
    __tablename__ = 'i_system'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36), unique=True)

    name = Column(String(255), unique=True)
    system_type = Column(String(255))
    system_mode = Column(String(255))
    description = Column(String(255))
    capabilities = Column(JSONEncodedDict)
    contact = Column(String(255))
    location = Column(String(255))
    latitude = Column(String(30))
    longitude = Column(String(30))
    services = Column(Integer, default=72)
    software_version = Column(String(255))
    timezone = Column(String(255))
    security_profile = Column(String(255))
    region_name = Column(Text)
    service_project_name = Column(Text)
    distributed_cloud_role = Column(String(255))
    security_feature = Column(String(255))


class ihost(Base):

    recordTypeEnum = Enum('standard',
                          'sprofile',
                          'reserve1',
                          'reserve2',
                          name='recordtypeEnum')

    invprovStateEnum = Enum('unprovisioned',
                            'inventoried',
                            'configured',
                            'provisioning',
                            'provisioned',
                            'upgrading',
                            'reserve1',
                            'reserve2',
                            name='invprovisionStateEnum')

    invPersonalityEnum = Enum('controller',
                              'worker',
                              'network',
                              'storage',
                              'reserve1',
                              'reserve2',
                              'edgeworker',
                              name='invPersonalityEnum')

    adminEnum = Enum('locked',
                     'unlocked',
                     'reserve1',
                     'reserve2',
                     name='administrativeEnum')

    operEnum = Enum('disabled',
                    'enabled',
                    'reserve1',
                    'reserve2',
                    name='operationalEnum')

    availEnum = Enum('available',
                     'intest',
                     'degraded',
                     'failed',
                     'power-off',
                     'offline',
                     'offduty',
                     'online',
                     'dependency',
                     'not-installed',
                     'reserv1',
                     'reserve2',
                     name='availabilityEnum')

    actionEnum = Enum('none',
                      'lock',
                      'force-lock',
                      'unlock',
                      'reset',
                      'swact',
                      'force-swact',
                      'reboot',
                      'power-on',
                      'power-off',
                      'reinstall',
                      'reserve1',
                      'reserve2',
                      name='actionEnum')

    __tablename__ = 'i_host'
    id = Column(Integer, primary_key=True, nullable=False)
    hostname = Column(String(255), unique=True, index=True)
    recordtype = Column(recordTypeEnum, default="standard")
    reserved = Column(Boolean, default=False)

    uuid = Column(String(36), unique=True)

    invprovision = Column(invprovStateEnum)
    # created_at = Column(String(255))
    # updated_at = Column(String(255))
    # MAC 01:34:67:9A:CD:FG  (need 16 bytes; convention here String(255))

    mgmt_mac = Column(String(255), unique=True)

    sw_version = Column(String(128))

    # board management IP address, MAC, type and username
    bm_ip = Column(String(255))
    bm_mac = Column(String(255))
    bm_type = Column(String(255))
    bm_username = Column(String(255))

    personality = Column(invPersonalityEnum)
    kernel_running = Column(String(64))
    kernel_config_status = Column(String(255), default="")
    subfunctions = Column(String(255))
    subfunction_oper = Column(operEnum, default="disabled")
    subfunction_avail = Column(availEnum, default="not-installed")
    serialid = Column(String(255))
    location = Column(JSONEncodedDict)
    administrative = Column(adminEnum, default="locked")
    operational = Column(operEnum, default="disabled")
    availability = Column(availEnum, default="offline")
    action = Column(actionEnum, default="none")
    ihost_action = Column(String(255))
    action_state = Column(String(255))
    inv_state = Column(String(255))
    mtce_info = Column(String(255))
    install_state = Column(String(255))
    install_state_info = Column(String(255))
    vim_progress_status = Column(String(255))
    task = Column(String(64))
    uptime = Column(Integer, default=0)
    capabilities = Column(JSONEncodedDict)
    config_status = Column(String(255))
    config_applied = Column(String(255))
    config_target = Column(String(255))
    apparmor = Column(String(64), default="disabled")
    apparmor_config_status = Column(String(255), default="")

    clock_synchronization = Column(String(32), default=constants.NTP)

    boot_device = Column(String(255), default="/dev/sda")
    rootfs_device = Column(String(255), default="/dev/sda")
    hw_settle = Column(String(4), default="0")
    install_output = Column(String(255), default="text")
    console = Column(String(255), default="ttyS0,115200")
    tboot = Column(String(64), default="")
    vsc_controllers = Column(String(255))
    ttys_dcd = Column(Boolean)
    iscsi_initiator_name = Column(String(64))
    nvme_host_id = Column(String(36))
    nvme_host_nqn = Column(String(224))

    device_image_update = Column(String(64))
    reboot_needed = Column(Boolean, nullable=False, default=False)
    max_cpu_mhz_configured = Column(String(64))  # in MHz
    min_cpu_mhz_allowed = Column(String(64))  # in MHz
    max_cpu_mhz_allowed = Column(String(64))  # in MHz

    cstates_available = Column(String(255))

    forisystemid = Column(Integer,
                          ForeignKey('i_system.id', ondelete='CASCADE'))
    peer_id = Column(Integer,
                     ForeignKey('peers.id'))

    system = relationship("isystem", lazy="joined", join_depth=1)

    kube_host_upgrade = relationship("KubeHostUpgrade", uselist=False)

    ptp_instances = relationship(
        "PtpInstances",
        secondary="ptp_instance_maps",
        primaryjoin="ihost.id == foreign(PtpInstanceMaps.host_id)",
        secondaryjoin="PtpInstances.id == "
                      "foreign(PtpInstanceMaps.ptp_instance_id)",
        back_populates="hosts", lazy="joined", join_depth=1)


class inode(Base):
    __tablename__ = 'i_node'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36), unique=True)

    numa_node = Column(Integer)
    capabilities = Column(JSONEncodedDict)

    forihostid = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))

    host = relationship("ihost", backref="nodes", lazy="joined", join_depth=1)

    UniqueConstraint('numa_node', 'forihostid', name='u_hostnuma')


class icpu(Base):
    __tablename__ = 'i_icpu'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36), unique=True)
    # numa_node = Column(Integer, unique=True) API only attribute via join
    # numa_node = Column(Integer)

    cpu = Column(Integer)
    core = Column(Integer)
    thread = Column(Integer)
    cpu_family = Column(String(255))
    cpu_model = Column(String(255))
    allocated_function = Column(String(255))
    # coprocessors = Column(JSONEncodedDict)
    # JSONEncodedDict e.g. {'Crypto':'CaveCreek'}
    capabilities = Column(JSONEncodedDict)
    forihostid = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))
    forinodeid = Column(Integer, ForeignKey('i_node.id', ondelete='CASCADE'))

    host = relationship("ihost", backref="cpus", lazy="joined", join_depth=1)
    node = relationship("inode", backref="cpus", lazy="joined", join_depth=1)

    UniqueConstraint('cpu', 'forihostid', name='u_hostcpu')


class imemory(Base):
    __tablename__ = 'i_imemory'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36), unique=True)

    memtotal_mib = Column(Integer)
    memavail_mib = Column(Integer)
    platform_reserved_mib = Column(Integer)
    node_memtotal_mib = Column(Integer)

    hugepages_configured = Column(Boolean, default=False)

    vswitch_hugepages_size_mib = Column(Integer)
    vswitch_hugepages_reqd = Column(Integer)
    vswitch_hugepages_nr = Column(Integer)
    vswitch_hugepages_avail = Column(Integer)

    vm_pending_as_percentage = Column(Boolean, default=False)
    vm_hugepages_nr_2M_pending = Column(Integer)
    vm_hugepages_nr_1G_pending = Column(Integer)
    vm_hugepages_nr_2M = Column(Integer)
    vm_hugepages_nr_1G = Column(Integer)
    vm_hugepages_nr_4K = Column(Integer)
    vm_hugepages_avail_2M = Column(Integer)
    vm_hugepages_avail_1G = Column(Integer)
    vm_hugepages_2M_percentage = Column(Integer)
    vm_hugepages_1G_percentage = Column(Integer)

    vm_hugepages_use_1G = Column(Boolean, default=False)
    vm_hugepages_possible_2M = Column(Integer)
    vm_hugepages_possible_1G = Column(Integer)
    capabilities = Column(JSONEncodedDict)

    forihostid = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))
    forinodeid = Column(Integer, ForeignKey('i_node.id'))

    host = relationship("ihost", backref="memory", lazy="joined", join_depth=1)
    node = relationship("inode", backref="memory", lazy="joined", join_depth=1)

    UniqueConstraint('forihostid', 'forinodeid', name='u_hostnode')


interfaces_to_interfaces = Table("interfaces_to_interfaces", Base.metadata,
    Column("used_by_id", Integer, ForeignKey("interfaces.id", ondelete='CASCADE'), primary_key=True),
    Column("uses_id", Integer, ForeignKey("interfaces.id", ondelete='CASCADE'), primary_key=True)
)


class Interfaces(Base):
    __tablename__ = 'interfaces'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36))
    forihostid = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))
    iftype = Column(String(255))

    ifname = Column(String(255))
    ifclass = Column(String(255))
    ifcapabilities = Column(JSONEncodedDict)
    farend = Column(JSONEncodedDict)
    sriov_numvfs = Column(Integer)
    sriov_vf_driver = Column(String(255))
    ptp_role = Column(String(255), default='none')  # TODO: deprecate it

    used_by = relationship(
        "Interfaces",
        secondary=interfaces_to_interfaces,
        primaryjoin=id == interfaces_to_interfaces.c.used_by_id,
        secondaryjoin=id == interfaces_to_interfaces.c.uses_id,
        backref=backref("uses", lazy="joined", join_depth=1),
        cascade="all",
        lazy="joined",
        join_depth=1)

    host = relationship("ihost", backref="interfaces",
                        lazy="joined", cascade="all")

    addresses = relationship("Addresses",
                             backref=backref("interface", lazy="joined"),
                             cascade="all")

    routes = relationship("Routes",
                          backref=backref("interface", lazy="joined"),
                          cascade="all")

    address_modes = relationship("AddressModes", lazy="joined",
                                 backref=backref("interface", lazy="joined"),
                                 cascade="all")

    ptp_interfaces = relationship(
        "PtpInterfaces",
        secondary="ptp_interface_maps",
        primaryjoin="Interfaces.id == foreign(PtpInterfaceMaps.interface_id)",
        secondaryjoin="PtpInterfaces.id == "
                      "foreign(PtpInterfaceMaps.ptp_interface_id)",
        back_populates="interfaces", lazy="joined", join_depth=1)

    UniqueConstraint('ifname', 'forihostid', name='u_interfacenameihost')

    __mapper_args__ = {
        'polymorphic_identity': 'interface',
        'polymorphic_on': iftype
    }


class EthernetCommon(object):
    @declared_attr
    def id(cls):  # pylint: disable=no-self-argument
        return Column(Integer, ForeignKey('interfaces.id', ondelete="CASCADE"), primary_key=True, nullable=False)

    imac = Column(String(255))
    imtu = Column(Integer)


class EthernetInterfaces(EthernetCommon, Interfaces):
    __tablename__ = 'ethernet_interfaces'

    __mapper_args__ = {
        'polymorphic_identity': 'ethernet',
    }


class AeInterfaces(EthernetCommon, Interfaces):
    __tablename__ = 'ae_interfaces'

    aemode = Column(String(255))  # e.g. balanced, active_standby
    aedict = Column(JSONEncodedDict)  # e.g. 802.3ad parameters
    txhashpolicy = Column(String(255))  # e.g. L2, L2L3, L3L4
    schedpolicy = Column(String(255))
    primary_reselect = Column(String(32))  # e.g. always, better, failure

    __mapper_args__ = {
        'polymorphic_identity': 'ae',
    }


class VlanInterfaces(EthernetCommon, Interfaces):
    __tablename__ = 'vlan_interfaces'

    vlan_id = Column(Integer)
    vlan_type = Column(String(255))

    __mapper_args__ = {
        'polymorphic_identity': 'vlan',
    }


class SriovVFInterfaces(EthernetCommon, Interfaces):
    __tablename__ = 'vf_interfaces'

    __mapper_args__ = {
        'polymorphic_identity': 'vf',
    }


class VirtualInterfaces(EthernetCommon, Interfaces):
    __tablename__ = 'virtual_interfaces'

    __mapper_args__ = {
        'polymorphic_identity': 'virtual',
    }


class Ports(Base):
    __tablename__ = 'ports'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36))
    host_id = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))
    node_id = Column(Integer, ForeignKey('i_node.id'))
    # might need to be changed to relationship/backref with interface table
    interface_id = Column(Integer, ForeignKey('interfaces.id', ondelete='SET NULL'))
    type = Column(String(255))

    name = Column(String(255))
    namedisplay = Column(String(255))
    pciaddr = Column(String(255))
    pclass = Column(String(255))
    pvendor = Column(String(255))
    pdevice = Column(String(255))
    psvendor = Column(String(255))
    psdevice = Column(String(255))
    dpdksupport = Column(Boolean, default=False)
    numa_node = Column(Integer)
    dev_id = Column(Integer)
    sriov_totalvfs = Column(Integer)
    sriov_numvfs = Column(Integer)
    sriov_vf_driver = Column(String(255))
    sriov_vf_pdevice_id = Column(String(4))
    # Each PCI Address is 12 char, 1020 char is enough for 64 devices
    sriov_vfs_pci_address = Column(String(1020))
    driver = Column(String(255))
    capabilities = Column(JSONEncodedDict)
    # JSON{'speed':1000,'MTU':9600, 'duplex':'', 'autonegotiation':'false'}

    node = relationship("inode", backref="ports", lazy="joined", join_depth=1)
    host = relationship("ihost", backref="ports", lazy="joined", join_depth=1)
    interface = relationship("Interfaces", backref="port",
                             lazy="joined", join_depth=1)

    UniqueConstraint('pciaddr', 'dev_id', 'host_id', name='u_pciaddrdevihost')

    __mapper_args__ = {
        'polymorphic_identity': 'port',
        'polymorphic_on': type
        # with_polymorphic is only supported in sqlalchemy.orm >= 0.8
        # 'with_polymorphic': '*'
    }


class EthernetPorts(Ports):
    __tablename__ = 'ethernet_ports'

    id = Column(Integer, ForeignKey('ports.id'), primary_key=True, nullable=False)

    mac = Column(String(255))
    mtu = Column(Integer)
    speed = Column(Integer)
    link_mode = Column(String(255))
    duplex = Column(String(255))
    autoneg = Column(String(255))
    bootp = Column(String(255))

    UniqueConstraint('mac', name='u_macihost')

    __mapper_args__ = {
        'polymorphic_identity': 'ethernet'
    }


"""
class SerialPorts(ports):
    __tablename__ = 'ethernet_ports'

    id = Column(Integer, ForeignKey('ports.id', primary_key=True, nullable=False)
    uuid = Column(String(36))

    __mapper_args__ = {
        'polymorphic_identity':'serial'
    }

class USBPorts(ports):
    __tablename__ = 'ethernet_ports'

    id = Column(Integer, ForeignKey('ports.id', primary_key=True, nullable=False)
    uuid = Column(String(36))

    __mapper_args__ = {
        'polymorphic_identity':'usb'
    }
"""


class ilvg(Base):
    __tablename__ = 'i_lvg'

    vgStateEnum = Enum('unprovisioned',
                       'adding',
                       'provisioned',
                       'removing',
                       'reserve1',
                       'reserve2',
                       name='vgStateEnum')

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36), unique=True)
    vg_state = Column(vgStateEnum, default="unprovisioned")

    # VG Data from vgdisplay/vgs
    lvm_vg_name = Column(String(64))
    lvm_vg_uuid = Column(String(64))
    lvm_vg_access = Column(String(64))
    lvm_max_lv = Column(Integer)
    lvm_cur_lv = Column(Integer)
    lvm_max_pv = Column(Integer)
    lvm_cur_pv = Column(Integer)
    lvm_vg_size = Column(BigInteger)
    lvm_vg_total_pe = Column(Integer)
    lvm_vg_free_pe = Column(Integer)

    # capabilities not used yet: JSON{'':"", '':''}
    capabilities = Column(JSONEncodedDict)

    forihostid = Column(Integer, ForeignKey('i_host.id',
                                            ondelete='CASCADE'))

    host = relationship("ihost", backref="lvgs", lazy="joined", join_depth=1)

    UniqueConstraint('lvm_vg_name', 'forihostid', name='u_vgnamehost')


class ipv(Base):
    pvTypeEnum = Enum('disk',
                      'partition',
                      'reserve1',
                      'reserve2',
                      name='physicalVolTypeEnum')

    __tablename__ = 'i_pv'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36), unique=True)
    pv_state = Column(String(32), default="unprovisioned")

    # Physical volume is a full disk or disk partition
    pv_type = Column(pvTypeEnum, default="disk")

    # Disk or Disk Partition information
    disk_or_part_uuid = Column(String(36))
    disk_or_part_device_node = Column(String(64))
    disk_or_part_device_path = Column(String(255))

    # PV Data from pvdisplay
    lvm_pv_name = Column(String(64))
    lvm_vg_name = Column(String(64))
    lvm_pv_uuid = Column(String(64))
    lvm_pv_size = Column(BigInteger)
    lvm_pe_total = Column(Integer)
    lvm_pe_alloced = Column(Integer)

    # capabilities not used yet: JSON{'':"", '':''}
    capabilities = Column(JSONEncodedDict)

    forihostid = Column(Integer, ForeignKey('i_host.id',
                                            ondelete='CASCADE'))

    forilvgid = Column(Integer, ForeignKey('i_lvg.id',
                                            ondelete='CASCADE'))

    host = relationship("ihost", backref="pvs", lazy="joined", join_depth=1)
    lvg = relationship("ilvg", backref="pv", lazy="joined", join_depth=1)

    UniqueConstraint('lvm_pv_name', 'forihostid', name='u_nodehost')


class istor(Base):
    __tablename__ = 'i_istor'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36))

    osdid = Column(Integer)
    idisk_uuid = Column(String(255))
    state = Column(String(255))
    function = Column(String(255))

    capabilities = Column(JSONEncodedDict)

    forihostid = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))
    host = relationship("ihost", backref="stors", lazy="joined", join_depth=1)

    fortierid = Column(Integer, ForeignKey('storage_tiers.id'))
    # 'tier' one-to-many backref created from StorageTier 'stors'

    journal = relationship("journal", lazy="joined",
                           backref=backref("i_istor", lazy="joined"),
                           foreign_keys="[journal.foristorid]",
                           cascade="all")

    UniqueConstraint('osdid', 'forihostid', name='u_osdhost')


class idisk(Base):
    __tablename__ = 'i_idisk'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36))

    device_node = Column(String(255))
    device_num = Column(Integer)
    device_type = Column(String(255))
    device_id = Column(String(255))
    device_path = Column(String(255))
    device_wwn = Column(String(255))
    size_mib = Column(Integer)
    available_mib = Column(Integer)
    rpm = Column(String(255))
    serial_id = Column(String(255))

    capabilities = Column(JSONEncodedDict)

    forihostid = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))
    foristorid = Column(Integer, ForeignKey('i_istor.id', ondelete='CASCADE'))
    foripvid = Column(Integer, ForeignKey('i_pv.id'))

    host = relationship("ihost", backref="disks", lazy="joined", join_depth=1)
    stor = relationship("istor", lazy="joined", join_depth=1)
    pv = relationship("ipv", lazy="joined", join_depth=1)

    UniqueConstraint('device_path', 'forihostid', name='u_devhost')


class partition(Base):
    __tablename__ = 'partition'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36))

    start_mib = Column(Integer)
    end_mib = Column(Integer)
    size_mib = Column(Integer)
    device_node = Column(String(64))
    device_path = Column(String(255))
    type_guid = Column(String(36))
    type_name = Column(String(255))

    idisk_id = Column(Integer, ForeignKey('i_idisk.id', ondelete='CASCADE'))
    idisk_uuid = Column(String(36))

    # capabilities not used yet: JSON{'':"", '':''}
    capabilities = Column(JSONEncodedDict)

    foripvid = Column(Integer, ForeignKey('i_pv.id'))
    forihostid = Column(Integer, ForeignKey('i_host.id'))
    status = Column(Integer)

    disk = relationship("idisk", lazy="joined", join_depth=1)
    pv = relationship("ipv", lazy="joined", join_depth=1)
    host = relationship("ihost", backref="partitions", lazy="joined",
                        join_depth=1)


class journal(Base):
    __tablename__ = 'journal'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36))

    device_path = Column(String(255))
    size_mib = Column(Integer)

    onistor_uuid = Column(String(36))
    foristorid = Column(Integer, ForeignKey('i_istor.id', ondelete='CASCADE'))


class iuser(Base):
    __tablename__ = 'i_user'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))

    root_sig = Column(String(255))
    passwd_expiry_days = Column(Integer)
    passwd_hash = Column(String(255))
    reserved_1 = Column(String(255))
    reserved_2 = Column(String(255))
    reserved_3 = Column(String(255))

    forisystemid = Column(Integer,
                          ForeignKey('i_system.id', ondelete='CASCADE'))

    system = relationship("isystem", lazy="joined", join_depth=1)


class idns(Base):
    __tablename__ = 'i_dns'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))

    nameservers = Column(String(255))  # csv list of nameservers

    forisystemid = Column(Integer,
                          ForeignKey('i_system.id', ondelete='CASCADE'))

    system = relationship("isystem", lazy="joined", join_depth=1)


class intp(Base):
    __tablename__ = 'i_ntp'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))

    ntpservers = Column(String(255))  # csv list of ntp servers

    forisystemid = Column(Integer,
                          ForeignKey('i_system.id', ondelete='CASCADE'))

    system = relationship("isystem", lazy="joined", join_depth=1)


class PTP(Base):
    __tablename__ = 'ptp'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))

    mode = Column(String(16), default='hardware')
    transport = Column(String(4), default='l2')
    mechanism = Column(String(4), default='e2e')

    system_id = Column(Integer,
                       ForeignKey('i_system.id', ondelete='CASCADE'))

    system = relationship("isystem", lazy="joined", join_depth=1)


class PtpParameters(Base):
    __tablename__ = "ptp_parameters"

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(UUID_LENGTH), unique=True)

    name = Column(String(255), nullable=False)
    value = Column(String(255))

    ptp_parameter_owners = relationship(
        "PtpParameterOwners",
        secondary="ptp_parameter_ownerships",
        primaryjoin="PtpParameters.uuid == "
                    "foreign(PtpParameterOwnerships.parameter_uuid)",
        secondaryjoin="PtpParameterOwners.uuid == "
                      "foreign(PtpParameterOwnerships.owner_uuid)",
        back_populates="ptp_parameters", lazy="joined", join_depth=1)


class PtpParameterOwners(Base):
    __tablename__ = "ptp_parameter_owners"

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(UUID_LENGTH), unique=True)
    type = Column(String(255), nullable=False)

    # capabilities not used yet: JSON{'':"", '':''}
    capabilities = Column(JSONEncodedDict)

    ptp_parameters = relationship(
        "PtpParameters",
        secondary="ptp_parameter_ownerships",
        primaryjoin="PtpParameterOwners.uuid == "
                    "foreign(PtpParameterOwnerships.owner_uuid)",
        secondaryjoin="PtpParameters.uuid == "
                      "foreign(PtpParameterOwnerships.parameter_uuid)",
        back_populates="ptp_parameter_owners", lazy="joined", join_depth=1)

    __mapper_args__ = {
        'polymorphic_identity': 'ptp_parameter_owner',
        'polymorphic_on': type,
        'with_polymorphic': '*'
    }


class PtpInstances(PtpParameterOwners):
    __tablename__ = "ptp_instances"

    id = Column(Integer, ForeignKey('ptp_parameter_owners.id'),
                primary_key=True,
                nullable=False)
    name = Column(String(255), unique=True, nullable=False)
    service = Column(String(255))

    hosts = relationship(
        "ihost",
        secondary="ptp_instance_maps",
        primaryjoin="PtpInstances.id == "
                    "foreign(PtpInstanceMaps.ptp_instance_id)",
        secondaryjoin="ihost.id == foreign(PtpInstanceMaps.host_id)",
        back_populates="ptp_instances", lazy="joined", join_depth=1)

    __mapper_args__ = {
        'polymorphic_identity': constants.PTP_PARAMETER_OWNER_INSTANCE
    }


class PtpInterfaces(PtpParameterOwners):
    __tablename__ = "ptp_interfaces"

    id = Column(Integer, ForeignKey('ptp_parameter_owners.id'),
                primary_key=True,
                nullable=False)
    name = Column(String(255), unique=True)
    ptp_instance_id = Column(Integer,
                             ForeignKey('ptp_instances.id',
                                        ondelete='CASCADE'),
                             nullable=False)

    ptp_instance = relationship("PtpInstances", lazy="joined", join_depth=1,
                                primaryjoin="PtpInterfaces.ptp_instance_id == "
                                            "PtpInstances.id")

    interfaces = relationship(
        "Interfaces",
        secondary="ptp_interface_maps",
        primaryjoin="PtpInterfaces.id == "
                    "foreign(PtpInterfaceMaps.ptp_interface_id)",
        secondaryjoin="Interfaces.id == "
                      "foreign(PtpInterfaceMaps.interface_id)",
        back_populates="ptp_interfaces", lazy="joined", join_depth=1)

    __mapper_args__ = {
        'polymorphic_identity': constants.PTP_PARAMETER_OWNER_INTERFACE
    }


class PtpParameterOwnerships(Base):
    """
    This is a bridge table used to model the many-to-many relationship between
    PTP parameters and their owners: PTP instances and PTP interfaces.
    """
    __tablename__ = "ptp_parameter_ownerships"

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(UUID_LENGTH), unique=True)

    parameter_uuid = Column(String(UUID_LENGTH),
                            ForeignKey('ptp_parameters.uuid',
                                       ondelete='CASCADE'),
                            nullable=False)
    owner_uuid = Column(String(UUID_LENGTH),
                        ForeignKey('ptp_parameter_owners.uuid',
                                   ondelete='CASCADE'),
                        nullable=False)

    parameter = relationship("PtpParameters", lazy="joined", join_depth=1)
    owner = relationship("PtpParameterOwners", lazy="joined", join_depth=1)

    UniqueConstraint('parameter_uuid', 'owner_uuid', name='u_paramowner')


class PtpInstanceMaps(Base):
    """
    This is a bridge table used to model the many-to-many relationship between
    PTP instances (the services) and the hosts they run.
    """
    __tablename__ = "ptp_instance_maps"

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(UUID_LENGTH), unique=True)

    host_id = Column(Integer,
                     ForeignKey('i_host.id', ondelete='CASCADE'),
                     nullable=False)
    ptp_instance_id = Column(
        Integer, ForeignKey('ptp_instances.id', ondelete='CASCADE'),
        nullable=False)

    host = relationship("ihost", lazy="joined", join_depth=1)
    instance = relationship("PtpInstances", lazy="joined", join_depth=1)

    UniqueConstraint('host_id', 'ptp_instance_id', name='u_hostinstance')


class PtpInterfaceMaps(Base):
    """
    This is a bridge table used to model the many-to-many relationship between
    PTP interfaces (PTP services and parameters) and the interfaces they run.
    """
    __tablename__ = "ptp_interface_maps"

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(UUID_LENGTH), unique=True)

    interface_id = Column(Integer,
                          ForeignKey('interfaces.id', ondelete='CASCADE'),
                          nullable=False)
    ptp_interface_id = Column(
        Integer, ForeignKey('ptp_interfaces.id', ondelete='CASCADE'),
        nullable=False)

    interface = relationship("Interfaces", lazy="joined", join_depth=1)
    ptp_interface = relationship("PtpInterfaces", lazy="joined", join_depth=1)

    UniqueConstraint('interface_id', 'ptp_interface_id',
                     name='u_ifaceptpiface')


class StorageTier(Base):
    __tablename__ = 'storage_tiers'

    id = Column(Integer, primary_key=True, nullable=True)
    uuid = Column(String(36))

    name = Column(String(255))
    type = Column(String(64))
    status = Column(String(64))
    capabilities = Column(JSONEncodedDict)

    forbackendid = Column(Integer,
                          ForeignKey('storage_ceph.id', ondelete='CASCADE'))
    # 'stor_backend' one-to-one backref created from StorageCeph 'tier'

    forclusterid = Column(Integer,
                          ForeignKey('clusters.id', ondelete='CASCADE'))
    # 'cluster' one-to-many backref created from Clusters 'tiers'

    stors = relationship("istor", lazy="joined",
                         backref=backref("tier", lazy="joined"),
                         foreign_keys="[istor.fortierid]",
                         cascade="all")


class StorageBackend(Base):
    __tablename__ = 'storage_backend'

    id = Column(Integer, primary_key=True, nullable=True)
    uuid = Column(String(36))

    backend = Column(String(255))
    name = Column(String(255), unique=True, index=True)
    state = Column(String(255))
    task = Column(String(255))
    services = Column(String(255))
    capabilities = Column(JSONEncodedDict)

    forisystemid = Column(Integer,
                          ForeignKey('i_system.id', ondelete='CASCADE'))

    system = relationship("isystem", lazy="joined", join_depth=1)

    __mapper_args__ = {
        'polymorphic_identity': 'storage_backend',
        'polymorphic_on': backend
    }


class StorageCeph(StorageBackend):
    __tablename__ = 'storage_ceph'

    id = Column(Integer, ForeignKey('storage_backend.id'), primary_key=True,
                nullable=False)

    cinder_pool_gib = Column(Integer)
    glance_pool_gib = Column(Integer)
    ephemeral_pool_gib = Column(Integer)
    object_pool_gib = Column(Integer)
    kube_pool_gib = Column(Integer)
    object_gateway = Column(Boolean, default=False)
    network = Column(String(255), default=constants.NETWORK_TYPE_MGMT)
    tier_id = Column(Integer,
                     ForeignKey('storage_tiers.id'))

    tier = relationship("StorageTier", lazy="joined", uselist=False,
                         backref=backref("stor_backend", lazy="joined"),
                         foreign_keys="[StorageTier.forbackendid]",
                         cascade="all")

    __mapper_args__ = {
        'polymorphic_identity': 'ceph',
    }


class StorageLvm(StorageBackend):
    __tablename__ = 'storage_lvm'

    id = Column(Integer, ForeignKey('storage_backend.id'), primary_key=True,
                nullable=False)

    __mapper_args__ = {
        'polymorphic_identity': 'lvm',
    }


class StorageFile(StorageBackend):
    __tablename__ = 'storage_file'

    id = Column(Integer, ForeignKey('storage_backend.id'), primary_key=True,
                nullable=False)

    __mapper_args__ = {
        'polymorphic_identity': 'file',
    }


class StorageExternal(StorageBackend):
    __tablename__ = 'storage_external'

    id = Column(Integer, ForeignKey('storage_backend.id'), primary_key=True,
                nullable=False)

    __mapper_args__ = {
        'polymorphic_identity': 'external',
    }


class StorageCephExternal(StorageBackend):
    __tablename__ = 'storage_ceph_external'

    id = Column(Integer, ForeignKey('storage_backend.id'), primary_key=True,
                nullable=False)
    ceph_conf = Column(JSONEncodedDict)

    __mapper_args__ = {
        'polymorphic_identity': 'ceph-external',
    }


class StorageCephRook(StorageBackend):
    __tablename__ = 'storage_ceph_rook'

    id = Column(Integer, ForeignKey('storage_backend.id'), primary_key=True,
                nullable=False)
    ceph_conf = Column(JSONEncodedDict)

    __mapper_args__ = {
        'polymorphic_identity': 'ceph-rook',
    }


class CephMon(Base):
    __tablename__ = 'ceph_mon'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))
    device_path = Column(String(255))
    ceph_mon_gib = Column(Integer)
    state = Column(String(255))
    task = Column(String(255))
    forihostid = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))

    host = relationship("ihost", lazy="joined", join_depth=1)


class ControllerFs(Base):
    __tablename__ = 'controller_fs'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))

    name = Column(String(64))
    size = Column(Integer)
    logical_volume = Column(String(64))
    replicated = Column(Boolean, default=False)
    state = Column(String(255))
    capabilities = Column(JSONEncodedDict)

    forisystemid = Column(Integer,
                          ForeignKey('i_system.id', ondelete='CASCADE'))

    system = relationship("isystem", lazy="joined", join_depth=1)


class drbdconfig(Base):
    __tablename__ = 'drbdconfig'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))

    link_util = Column(Integer)
    num_parallel = Column(Integer)
    rtt_ms = Column(Float)

    forisystemid = Column(Integer,
                          ForeignKey('i_system.id', ondelete='CASCADE'))

    system = relationship("isystem", lazy="joined", join_depth=1)


class remotelogging(Base):
    logTransportEnum = Enum('udp',
                            'tcp',
                            'tls',
                            name='logTransportEnum')

    __tablename__ = 'remotelogging'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))
    enabled = Column(Boolean, default=False)
    transport = Column(logTransportEnum, default='udp')
    ip_address = Column(String(50), unique=True)
    port = Column(Integer, default=514)
    key_file = Column(String(255))

    system_id = Column(Integer,
                       ForeignKey('i_system.id', ondelete='CASCADE'))

    system = relationship("isystem", lazy="joined", join_depth=1)


class Services(Base):
    __tablename__ = 'services'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True)
    enabled = Column(Boolean, default=False)
    region_name = Column(Text)
    capabilities = Column(JSONEncodedDict)


class Routes(Base):
    __tablename__ = 'routes'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36))
    family = Column(Integer, nullable=False)
    network = Column(String(50), nullable=False)
    prefix = Column(Integer, nullable=False)
    gateway = Column(String(50), nullable=False)
    metric = Column(Integer, default=1, nullable=False)

    interface_id = Column(Integer,
                          ForeignKey('interfaces.id', ondelete='CASCADE'))

    UniqueConstraint('family', 'network', 'prefix', 'gateway',
                     'interface_id',
                     name='u_family@network@prefix@gateway@interface')


class AddressPools(Base):
    __tablename__ = 'address_pools'

    id = Column('id', Integer, primary_key=True, nullable=False)
    uuid = Column('uuid', String(36), unique=True)
    name = Column('name', String(128), unique=True, nullable=False)
    family = Column('family', Integer, nullable=False)
    network = Column('network', String(50), nullable=False)
    prefix = Column('prefix', Integer, nullable=False)
    order = Column('order', String(32), nullable=False)
    controller0_address_id = Column('controller0_address_id', Integer,
                                    ForeignKey('addresses.id', ondelete="CASCADE"),
                                    nullable=True)
    controller1_address_id = Column('controller1_address_id', Integer,
                                    ForeignKey('addresses.id', ondelete="CASCADE"),
                                    nullable=True)
    floating_address_id = Column('floating_address_id', Integer,
                                 ForeignKey('addresses.id', ondelete="CASCADE"),
                                 nullable=True)
    gateway_address_id = Column('gateway_address_id', Integer,
                                ForeignKey('addresses.id', ondelete="CASCADE"),
                                nullable=True)

    ranges = relationship("AddressPoolRanges", lazy="joined",
                          backref=backref("address_pool", lazy="joined"),
                          cascade="all, delete-orphan")
    controller0_address = relationship(
        "Addresses", lazy="joined", join_depth=1,
        foreign_keys=[controller0_address_id])

    controller1_address = relationship(
        "Addresses", lazy="joined", join_depth=1,
        foreign_keys=[controller1_address_id])

    floating_address = relationship(
        "Addresses", lazy="joined", join_depth=1,
        foreign_keys=[floating_address_id])

    gateway_address = relationship(
        "Addresses", lazy="joined", join_depth=1,
        foreign_keys=[gateway_address_id])

    @classmethod
    def get_query(cls):
        sql = """
              select address_pools.id, address_pools.uuid, address_pools.name, address_pools.network,
              address_pools.prefix, address_pools.family, 'address_pools.order',
              controller0_address_id, addresses0.address as controller0_address, controller1_address_id,
              floating_address_id, gateway_address_id
              from address_pools
              left outer join addresses as addresses0 on addresses0.id = controller0_address_id
              left outer join addresses as addresses1 on addresses1.id = controller1_address_id
              left outer join addresses as addressesf on addressesf.id = floating_address_id
              """
        return sql


class AddressPoolRanges(Base):
    __tablename__ = 'address_pool_ranges'

    id = Column('id', Integer, primary_key=True, nullable=False)
    uuid = Column('uuid', String(36), unique=True)
    start = Column('start', String(50), nullable=False)
    end = Column('end', String(50), nullable=False)

    address_pool_id = Column(Integer,
                             ForeignKey('address_pools.id',
                                        ondelete='CASCADE'))


class Addresses(Base):
    __tablename__ = 'addresses'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36))
    family = Column(Integer, nullable=False)
    address = Column(String(50), nullable=False)
    prefix = Column(Integer, nullable=False)
    enable_dad = Column('enable_dad', Boolean(), default=True)
    name = Column(String(255))

    interface_id = Column(Integer,
                          ForeignKey('interfaces.id', ondelete='SET NULL'),
                          nullable=True)

    address_pool_id = Column(Integer,
                             ForeignKey('address_pools.id',
                                        ondelete='CASCADE'),
                             nullable=True)

    address_pool = relationship("AddressPools", lazy="joined",
                                foreign_keys="Addresses.address_pool_id")

    UniqueConstraint('family', 'address', 'interface_id',
                     name='u_address@family@interface')


class AddressModes(Base):
    __tablename__ = 'address_modes'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36))
    family = Column(Integer, nullable=False)
    mode = Column(String(32), nullable=False)

    interface_id = Column(Integer,
                          ForeignKey('interfaces.id', ondelete='CASCADE'))

    address_pool_id = Column(Integer,
                             ForeignKey('address_pools.id',
                                        ondelete='CASCADE'))

    address_pool = relationship("AddressPools", lazy="joined")

    UniqueConstraint('family', 'interface_id',
                     name='u_family@interface')


class Networks(Base):
    __tablename__ = 'networks'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36), unique=True)
    name = Column(String(255), unique=True)
    type = Column(String(255), unique=True)
    dynamic = Column(Boolean, nullable=False)

    address_pool_id = Column(Integer,
                             ForeignKey('address_pools.id',
                                        ondelete='CASCADE'),
                             nullable=True)

    primary_pool_family = Column(String(4))

    address_pool = relationship("AddressPools", lazy="joined",
                                backref=backref("networks", cascade="all, delete"))


class NetworkAddressPools(Base):
    __tablename__ = 'network_addresspools'
    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36), unique=True)

    address_pool_id = Column(Integer, ForeignKey('address_pools.id', ondelete='CASCADE'))
    network_id = Column(Integer, ForeignKey('networks.id', ondelete='CASCADE'))

    address_pool = relationship("AddressPools", lazy="joined",
                                backref=backref("network_addresspools",
                                                cascade="all, delete"))
    network = relationship("Networks", lazy="joined",
                           backref=backref("network_addresspools",
                                           cascade="all, delete"))

    UniqueConstraint('network_id', 'address_pool_id', name='u_network_id@address_pool_id')


class InterfaceNetworks(Base):
    __tablename__ = 'interface_networks'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36), unique=True)

    interface_id = Column(Integer, ForeignKey('interfaces.id', ondelete='CASCADE'))
    network_id = Column(Integer, ForeignKey('networks.id', ondelete='CASCADE'))

    interface = relationship("Interfaces", lazy="joined",
                             backref=backref("interface_networks",
                                             lazy="joined"))
    network = relationship("Networks", lazy="joined",
                           backref=backref("interface_networks", cascade="all, delete"))
    UniqueConstraint('interface_id', 'network_id', name='u_interface_id@network_id')


class DataNetworks(Base):
    __tablename__ = 'datanetworks'
    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36), unique=True)
    name = Column(String(255), unique=True)
    network_type = Column(String(255))
    description = Column(String(255))
    mtu = Column(Integer)

    __mapper_args__ = {
        'polymorphic_identity': 'datanetwork',
        'polymorphic_on': network_type,
        'with_polymorphic': '*',
    }


class DataNetworksCommon(object):
    @declared_attr
    def id(cls):  # pylint: disable=no-self-argument
        return Column(Integer,
                      ForeignKey('datanetworks.id', ondelete="CASCADE"),
                      primary_key=True, nullable=False)


class DataNetworksFlat(DataNetworksCommon, DataNetworks):
    __tablename__ = 'datanetworks_flat'

    __mapper_args__ = {
        'polymorphic_identity': 'flat',
    }


class DataNetworksVlan(DataNetworksCommon, DataNetworks):
    __tablename__ = 'datanetworks_vlan'

    __mapper_args__ = {
        'polymorphic_identity': 'vlan',
    }


class DataNetworksVXlan(DataNetworksCommon, DataNetworks):
    __tablename__ = 'datanetworks_vxlan'

    # IP address of the multicast group
    multicast_group = Column(String(64), nullable=True)

    # Destination DP port for all instances
    port_num = Column(Integer, nullable=False)

    # Time-to-live value for all instances
    ttl = Column(Integer, nullable=False)

    # defines dynamic learning with multicast enable/disabled
    mode = Column(String(32), nullable=False,
                  default=constants.DATANETWORK_MODE_DYNAMIC)

    __mapper_args__ = {
        'polymorphic_identity': 'vxlan',
    }


class InterfaceDataNetworks(Base):
    __tablename__ = 'interface_datanetworks'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36), unique=True)

    interface_id = Column(
        Integer, ForeignKey('interfaces.id', ondelete='CASCADE'))
    datanetwork_id = Column(
        Integer, ForeignKey('datanetworks.id', ondelete='CASCADE'))

    interface = relationship(
        "Interfaces", lazy="joined", backref=backref("interface_datanetworks", lazy="joined"))
    datanetwork = relationship(
        "DataNetworks", lazy="joined", backref="interface_datanetworks")
    UniqueConstraint(
        'interface_id', 'datanetwork_id', name='u_interface_id@datanetwork_id')


class SensorGroups(Base):
    __tablename__ = 'i_sensorgroups'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36))
    host_id = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))

    sensortype = Column(String(255))
    datatype = Column(String(255))  # polymorphic
    sensorgroupname = Column(String(255))
    path = Column(String(255))
    description = Column(String(255))

    state = Column(String(255))
    possible_states = Column(String(255))
    algorithm = Column(String(255))
    audit_interval_group = Column(Integer)
    record_ttl = Column(Integer)

    actions_minor_group = Column(String(255))
    actions_major_group = Column(String(255))
    actions_critical_group = Column(String(255))

    suppress = Column(Boolean, default=False)

    capabilities = Column(JSONEncodedDict)

    actions_critical_choices = Column(String(255))
    actions_major_choices = Column(String(255))
    actions_minor_choices = Column(String(255))

    host = relationship("ihost", lazy="joined", join_depth=1)

    # probably shouldnt be joined in this way?
    # sensors = relationship("Sensors",
    #                        backref="sensorgroup",
    #                        cascade="all")

    UniqueConstraint('sensorgroupname', 'path', 'host_id',
                     name='u_sensorgroupname_path_host_id')

    __mapper_args__ = {
        'polymorphic_identity': 'sensorgroup',
        'polymorphic_on': datatype
    }


class SensorGroupsCommon(object):
    @declared_attr
    def id(cls):  # pylint: disable=no-self-argument
        return Column(Integer,
                      ForeignKey('i_sensorgroups.id', ondelete="CASCADE"),
                      primary_key=True, nullable=False)


class SensorGroupsDiscrete(SensorGroupsCommon, SensorGroups):
    __tablename__ = 'i_sensorgroups_discrete'

    # sensorgroup_discrete_type = Column(String(255))  # polymorphic

    __mapper_args__ = {
        'polymorphic_identity': 'discrete',
    }


class SensorGroupsAnalog(SensorGroupsCommon, SensorGroups):
    __tablename__ = 'i_sensorgroups_analog'

    # sensorgroup_analog_type = Column(String(255))  # polymorphic

    unit_base_group = Column(String(255))
    unit_modifier_group = Column(String(255))
    unit_rate_group = Column(String(255))

    t_minor_lower_group = Column(String(255))
    t_minor_upper_group = Column(String(255))
    t_major_lower_group = Column(String(255))
    t_major_upper_group = Column(String(255))
    t_critical_lower_group = Column(String(255))
    t_critical_upper_group = Column(String(255))

    __mapper_args__ = {
        'polymorphic_identity': 'analog',
    }


class Sensors(Base):
    __tablename__ = 'i_sensors'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36))
    host_id = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))

    # might need to be changed to relationship/backref with sensorgroup table
    # a sensorgroup could have many sensors
    sensorgroup_id = Column(Integer,
                            ForeignKey('i_sensorgroups.id',
                                       ondelete='SET NULL'))
    sensortype = Column(String(255))  # "watchdog", "temperature".
    datatype = Column(String(255))  # "discrete" or "analog"

    sensorname = Column(String(255))
    path = Column(String(255))

    status = Column(String(255))
    state = Column(String(255))
    state_requested = Column(String(255))

    sensor_action_requested = Column(String(255))

    audit_interval = Column(Integer)
    algorithm = Column(String(255))
    actions_minor = Column(String(255))
    actions_major = Column(String(255))
    actions_critical = Column(String(255))

    suppress = Column(Boolean, default=False)

    capabilities = Column(JSONEncodedDict)

    host = relationship("ihost", lazy="joined", join_depth=1)
    sensorgroup = relationship("SensorGroups", lazy="joined", join_depth=1)

    UniqueConstraint('sensorname', 'path', 'host_id',
                     name='u_sensorname_path_host_id')

    __mapper_args__ = {
        'polymorphic_identity': 'sensor',
        'polymorphic_on': datatype
        # with_polymorphic is only supported in sqlalchemy.orm >= 0.8
        # 'with_polymorphic': '*'
    }


class SensorsDiscrete(Sensors):
    __tablename__ = 'i_sensors_discrete'

    id = Column(Integer, ForeignKey('i_sensors.id'),
                primary_key=True, nullable=False)

    __mapper_args__ = {
        'polymorphic_identity': 'discrete'
    }


class SensorsAnalog(Sensors):
    __tablename__ = 'i_sensors_analog'

    id = Column(Integer, ForeignKey('i_sensors.id'),
                primary_key=True, nullable=False)

    unit_base = Column(String(255))
    unit_modifier = Column(String(255))
    unit_rate = Column(String(255))

    t_minor_lower = Column(String(255))
    t_minor_upper = Column(String(255))
    t_major_lower = Column(String(255))
    t_major_upper = Column(String(255))
    t_critical_lower = Column(String(255))
    t_critical_upper = Column(String(255))

    __mapper_args__ = {
        'polymorphic_identity': 'analog'
    }


class PciDevice(Base):
    __tablename__ = 'pci_devices'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36))
    host_id = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))
    name = Column(String(255))
    pciaddr = Column(String(255))
    pclass_id = Column(String(6))
    pvendor_id = Column(String(4))
    pdevice_id = Column(String(4))
    pclass = Column(String(255))
    pvendor = Column(String(255))
    pdevice = Column(String(255))
    psvendor = Column(String(255))
    psdevice = Column(String(255))
    numa_node = Column(Integer)
    sriov_totalvfs = Column(Integer)
    sriov_numvfs = Column(Integer)
    sriov_vfs_pci_address = Column(String(1020))
    sriov_vf_driver = Column(String(255))
    sriov_vf_pdevice_id = Column(String(4))
    driver = Column(String(255))
    enabled = Column(Boolean)
    extra_info = Column(Text)

    host = relationship("ihost", lazy="joined", join_depth=1)
    fpga = relationship("FpgaDevice", lazy="joined", uselist=False, join_depth=1)
    UniqueConstraint('pciaddr', 'host_id', name='u_pciaddrhost')


class FpgaDevice(Base):
    __tablename__ = 'fpga_devices'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36))
    host_id = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))
    pci_id = Column(Integer, ForeignKey('pci_devices.id', ondelete='CASCADE'))
    pciaddr = Column(String(32))
    bmc_build_version = Column(String(32))
    bmc_fw_version = Column(String(32))
    retimer_a_version = Column(String(32))
    retimer_b_version = Column(String(32))
    root_key = Column(String(128))
    revoked_key_ids = Column(String(512))
    boot_page = Column(String(16))
    bitstream_id = Column(String(32))

    host = relationship("ihost", lazy="joined", join_depth=1)
    pcidevice = relationship("PciDevice", lazy="joined", join_depth=1)
    UniqueConstraint('pciaddr', 'host_id', name='u_pciaddrhost')


class FpgaPorts(Base):
    __tablename__ = 'fpga_ports'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36), unique=True)

    port_id = Column(Integer, ForeignKey('ports.id', ondelete='CASCADE'))
    fpga_id = Column(Integer,
                     ForeignKey('fpga_devices.id', ondelete='CASCADE'))

    ports = relationship("Ports", lazy="joined", join_depth=1)
    fpga_device = relationship("FpgaDevice", lazy="joined",
                               backref="fpga_ports", join_depth=1)
    UniqueConstraint('port_id', 'fpga_id', name='u_port_id@fpga_id')


class DeviceImage(Base):
    __tablename__ = 'device_images'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))

    bitstream_type = Column(String(255))
    pci_vendor = Column(String(4))
    pci_device = Column(String(4))
    name = Column(String(255))
    description = Column(String(255))
    image_version = Column(String(255))
    applied = Column(Boolean, nullable=False, default=False)
    capabilities = Column(JSONEncodedDict)
    __mapper_args__ = {
        'polymorphic_identity': 'deviceimage',
        'polymorphic_on': bitstream_type,
        'with_polymorphic': '*',
    }


class DeviceImageCommon(object):
    @declared_attr
    def id(cls):  # pylint: disable=no-self-argument
        return Column(Integer,
                      ForeignKey('device_images.id', ondelete="CASCADE"),
                      primary_key=True, nullable=False)


class DeviceImageRootKey(DeviceImageCommon, DeviceImage):
    __tablename__ = 'device_images_rootkey'

    key_signature = Column(String(255), nullable=True)
    __mapper_args__ = {
        'polymorphic_identity': 'root-key',
    }


class DeviceImageFunctional(DeviceImageCommon, DeviceImage):
    __tablename__ = 'device_images_functional'

    bitstream_id = Column(String(255), nullable=True)
    bmc = Column(Boolean, nullable=False, default=False)
    retimer_included = Column(Boolean, nullable=False, default=False)

    __mapper_args__ = {
        'polymorphic_identity': 'functional',
    }


class DeviceImageKeyRevocation(DeviceImageCommon, DeviceImage):
    __tablename__ = 'device_images_keyrevocation'

    revoke_key_id = Column(Integer, nullable=True)

    __mapper_args__ = {
        'polymorphic_identity': 'key-revocation',
    }


class DeviceLabel(Base):
    __tablename__ = 'device_labels'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))
    host_id = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))
    pcidevice_id = Column(Integer, ForeignKey('pci_devices.id',
                                              ondelete='CASCADE'))
    capabilities = Column(JSONEncodedDict)

    host = relationship("ihost", lazy="joined", join_depth=1)
    pcidevice = relationship("PciDevice", lazy="joined", join_depth=1)
    label_key = Column(String(384))
    label_value = Column(String(128))


class DeviceImageLabel(Base):
    __tablename__ = 'device_image_labels'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36), unique=True)

    image_id = Column(
        Integer, ForeignKey('device_images.id', ondelete='CASCADE'))
    label_id = Column(
        Integer, ForeignKey('device_labels.id', ondelete='CASCADE'))
    status = Column(String(128))
    capabilities = Column(JSONEncodedDict)

    image = relationship(
        "DeviceImage", lazy="joined", backref="device_image_labels")
    label = relationship(
        "DeviceLabel", lazy="joined", backref="device_image_labels")
    UniqueConstraint('image_id', 'label_id', name='u_image_id@label_id')


class DeviceImageState(Base):
    __tablename__ = 'device_image_state'

    id = Column(Integer, primary_key=True, nullable=False)
    uuid = Column(String(36), unique=True)

    host_id = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))
    pcidevice_id = Column(
        Integer, ForeignKey('pci_devices.id', ondelete='CASCADE'))
    image_id = Column(
        Integer, ForeignKey('device_images.id', ondelete='CASCADE'))
    status = Column(String(128))
    update_start_time = Column(DateTime(timezone=False))
    capabilities = Column(JSONEncodedDict)

    host = relationship("ihost", lazy="joined", join_depth=1)
    pcidevice = relationship(
        "PciDevice", lazy="joined", backref="device_image_state")
    image = relationship(
        "DeviceImage", lazy="joined", backref="device_image_state")


class Restore(Base):
    __tablename__ = 'backup_restore'

    id = Column('id', Integer, primary_key=True, nullable=False)
    uuid = Column('uuid', String(36), unique=True)
    state = Column('state', String(128), nullable=False)
    capabilities = Column(JSONEncodedDict)


class ServiceParameter(Base):
    __tablename__ = 'service_parameter'

    id = Column('id', Integer, primary_key=True, nullable=False)
    uuid = Column('uuid', String(36))
    service = Column('service', String(16), nullable=False)
    section = Column('section', String(128), nullable=False)
    name = Column('name', String(255), nullable=False)
    value = Column('value', String(255), nullable=False)
    personality = Column('personality', String(255))
    resource = Column('resource', String(255))
    UniqueConstraint('name', 'section', 'service',
                     'personality', 'resource',
                     name='u_service_section_name_personality_resource')


class Clusters(Base):
    __tablename__ = 'clusters'

    id = Column('id', Integer, primary_key=True, nullable=False)
    uuid = Column('uuid', String(36), unique=True)
    cluster_uuid = Column('cluster_uuid', String(36), unique=True)
    type = Column('type', String(255))
    name = Column('name', String(255), unique=True, nullable=False)
    capabilities = Column(JSONEncodedDict)

    system_id = Column(Integer, ForeignKey('i_system.id', ondelete='CASCADE'))

    system = relationship("isystem", lazy="joined", join_depth=1)

    peers = relationship("Peers", lazy="joined",
                          backref=backref("cluster", lazy="joined"),
                          cascade="all, delete-orphan")

    tiers = relationship("StorageTier", lazy="joined",
                         backref=backref("cluster", lazy="joined"),
                         foreign_keys="[StorageTier.forclusterid]",
                         cascade="all")


class Peers(Base):
    __tablename__ = 'peers'

    id = Column('id', Integer, primary_key=True, nullable=False)
    uuid = Column('uuid', String(36), unique=True)
    name = Column('name', String(255))
    status = Column('status', String(255))
    info = Column(JSONEncodedDict)
    capabilities = Column(JSONEncodedDict)

    hosts = relationship("ihost", lazy="joined",
                          backref="peer",
                          cascade="all, delete-orphan")

    cluster_id = Column(Integer,
                        ForeignKey('clusters.id',
                                   ondelete='CASCADE'))


class LldpAgents(Base):
    __tablename__ = 'lldp_agents'

    id = Column('id', Integer, primary_key=True, nullable=False)
    uuid = Column('uuid', String(36))
    host_id = Column('host_id', Integer, ForeignKey('i_host.id',
                                                    ondelete='CASCADE'))
    port_id = Column('port_id', Integer, ForeignKey('ports.id',
                                                    ondelete='CASCADE'))
    status = Column('status', String(255))

    lldp_tlvs = relationship("LldpTlvs",
                             backref=backref("lldpagents", lazy="subquery"),
                             cascade="all")

    host = relationship("ihost", lazy="joined", join_depth=1)
    port = relationship("Ports", lazy="joined", join_depth=1)


class LldpNeighbours(Base):
    __tablename__ = 'lldp_neighbours'

    id = Column('id', Integer, primary_key=True, nullable=False)
    uuid = Column('uuid', String(36))
    host_id = Column('host_id', Integer, ForeignKey('i_host.id',
                                                    ondelete='CASCADE'))
    port_id = Column('port_id', Integer, ForeignKey('ports.id',
                                                    ondelete='CASCADE'))
    msap = Column('msap', String(511))

    lldp_tlvs = relationship(
        "LldpTlvs",
        backref=backref("lldpneighbours", lazy="subquery"),
        cascade="all")

    host = relationship("ihost", lazy="joined", join_depth=1)
    port = relationship("Ports", lazy="joined", join_depth=1)

    UniqueConstraint('msap', 'port_id', name='u_msap_port_id')


class LldpTlvs(Base):
    __tablename__ = 'lldp_tlvs'

    id = Column('id', Integer, primary_key=True, nullable=False)
    agent_id = Column('agent_id', Integer, ForeignKey('lldp_agents.id',
                      ondelete='CASCADE'), nullable=True)
    neighbour_id = Column('neighbour_id', Integer,
                          ForeignKey('lldp_neighbours.id', ondelete='CASCADE'),
                          nullable=True)
    type = Column('type', String(255))
    value = Column('value', String(255))

    lldp_agent = relationship("LldpAgents",
                              backref=backref("lldptlvs", lazy="subquery"),
                              cascade="all",
                              lazy="joined")

    lldp_neighbour = relationship(
        "LldpNeighbours",
        backref=backref("lldptlvs", lazy="subquery"),
        cascade="all",
        lazy="joined")

    UniqueConstraint('type', 'agent_id',
                     name='u_type@agent')

    UniqueConstraint('type', 'neighbour_id',
                     name='u_type@neighbour')


class sdn_controller(Base):
    __tablename__ = 'sdn_controller'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))

    ip_address = Column(String(255))
    port = Column(Integer)
    transport = Column(String(255))
    state = Column(String(255))


class tpmconfig(Base):
    __tablename__ = 'tpmconfig'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))
    tpm_path = Column(String(255))


class tpmdevice(Base):
    __tablename__ = 'tpmdevice'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))
    state = Column(String(255))
    binary = Column(LargeBinary())
    tpm_data = Column(JSONEncodedDict)
    capabilities = Column(JSONEncodedDict)

    host_id = Column(Integer, ForeignKey('i_host.id',
                                         ondelete='CASCADE'))
    host = relationship("ihost", lazy="joined", join_depth=1)


class certificate(Base):
    __tablename__ = 'certificate'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))

    certtype = Column(String(64))
    issuer = Column(String(255))
    signature = Column(String(255))
    start_date = Column(DateTime(timezone=False))
    expiry_date = Column(DateTime(timezone=False))
    capabilities = Column(JSONEncodedDict)
    subject = Column(String(255))
    hash_subject = Column(String(64))


class HelmOverrides(Base):
    __tablename__ = 'helm_overrides'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    namespace = Column(String(255), nullable=False)
    user_overrides = Column(Text, nullable=True)
    system_overrides = Column(JSONEncodedDict, nullable=True)
    app_id = Column(Integer, ForeignKey('kube_app.id', ondelete='CASCADE'))
    kube_app = relationship("KubeApp", lazy="joined", join_depth=1)
    UniqueConstraint('name', 'namespace', 'app_id', name='u_app_name_namespace')


class Label(Base):
    __tablename__ = 'label'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))
    host_id = Column(Integer, ForeignKey('i_host.id',
                                         ondelete='CASCADE'))
    host = relationship("ihost", lazy="joined", join_depth=1)
    label_key = Column(String(384))
    label_value = Column(String(128))
    UniqueConstraint('host_id', 'label_key', name='u_host_id@label_key')


class KubeApp(Base):
    __tablename__ = 'kube_app'

    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    app_version = Column(String(255), nullable=False)
    manifest_name = Column(String(255), nullable=False)
    manifest_file = Column(String(255), nullable=False)
    status = Column(String(255), nullable=False)
    progress = Column(String(255), nullable=True)
    active = Column(Boolean, nullable=False, default=False)
    recovery_attempts = Column(Integer, nullable=False, default=0)
    mode = Column(String(255), nullable=True)
    app_metadata = Column(JSONEncodedDict)
    app_bundle_id = Column(Integer, ForeignKey('kube_app_bundle.id',
                                               ondelete='SET NULL'))
    UniqueConstraint('name', 'app_version', name='u_app_name_version')


class KubeAppReleases(Base):
    __tablename__ = 'kube_app_releases'

    id = Column(Integer, primary_key=True)
    release = Column(String(255), nullable=True)
    namespace = Column(String(255), nullable=True)
    version = Column(Integer)
    app_id = Column(Integer, ForeignKey('kube_app.id', ondelete='CASCADE'))
    kube_app = relationship("KubeApp", lazy="joined", join_depth=1)
    UniqueConstraint('release', 'namespace', 'app_id', name='u_app_release_namespace')


class KubeHostUpgrade(Base):
    __tablename__ = 'kube_host_upgrade'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))

    target_version = Column(String(255), nullable=False)
    status = Column(String(128), nullable=False)
    reserved_1 = Column(String(255))
    reserved_2 = Column(String(255))
    reserved_3 = Column(String(255))
    reserved_4 = Column(String(255))

    host_id = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))


class KubeUpgrade(Base):
    __tablename__ = 'kube_upgrade'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))

    from_version = Column(String(255), nullable=False)
    to_version = Column(String(255), nullable=False)
    state = Column(String(128), nullable=False)
    recovery_attempts = Column(Integer, nullable=False, default=0)
    reserved_1 = Column(String(255))
    reserved_2 = Column(String(255))
    reserved_3 = Column(String(255))
    reserved_4 = Column(String(255))


class HostFs(Base):
    __tablename__ = 'host_fs'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36))

    name = Column(String(64))
    size = Column(Integer)
    logical_volume = Column(String(64))
    state = Column(String(255))
    capabilities = Column(JSONEncodedDict)

    forihostid = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))

    host = relationship("ihost", lazy="joined", join_depth=1)


class KubeRootCAUpdate(Base):
    __tablename__ = 'kube_rootca_update'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True)
    from_rootca_cert = Column(String(255))
    to_rootca_cert = Column(String(255))
    state = Column(String(255))
    capabilities = Column(JSONEncodedDict)
    reserved_1 = Column(String(255))
    reserved_2 = Column(String(255))
    reserved_3 = Column(String(255))


class KubeRootCAHostUpdate(Base):
    __tablename__ = 'kube_rootca_host_update'

    id = Column(Integer, primary_key=True)
    uuid = Column(String(36), unique=True)
    effective_rootca_cert = Column(String(255))
    target_rootca_cert = Column(String(255))
    state = Column(String(255))
    host_id = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))
    capabilities = Column(JSONEncodedDict)
    reserved_1 = Column(String(255))
    reserved_2 = Column(String(255))
    reserved_3 = Column(String(255))

    host = relationship("ihost", lazy="joined", join_depth=1)


class KubeCmdVersions(Base):
    __tablename__ = 'kube_cmd_versions'

    id = Column(Integer, primary_key=True)
    kubeadm_version = Column(String(255), nullable=False)
    kubelet_version = Column(String(255), nullable=False)
    UniqueConstraint('kubeadm_version', 'kubelet_version',
                     name='u_kubeadm_version_kubelet_version')


class RuntimeConfig(Base):
    runtimeConfigStateEnum = Enum(
        constants.RUNTIME_CONFIG_STATE_PENDING,
        constants.RUNTIME_CONFIG_STATE_APPLIED,
        constants.RUNTIME_CONFIG_STATE_FAILED,
        constants.RUNTIME_CONFIG_STATE_RETRIED,
        name="runtimeConfigStateEnum"
    )

    __tablename__ = 'runtime_config'

    id = Column(Integer, primary_key=True)
    config_uuid = Column(String(UUID_LENGTH), nullable=False)
    config_dict = Column(String(767), nullable=False)
    state = Column(runtimeConfigStateEnum, default=constants.RUNTIME_CONFIG_STATE_PENDING)
    forihostid = Column(Integer, ForeignKey('i_host.id', ondelete='CASCADE'))
    reserved_1 = Column(String(255))
    UniqueConstraint('config_uuid', 'forihostid',
                     name='u_config_uuid_forihostid')


class KubeAppBundle(Base):
    KubeAppBundleTimingEnum = Enum(
        constants.APP_METADATA_TIMING_PRE,
        constants.APP_METADATA_TIMING_POST,
        name="KubeAppBundleTimingEnum"
    )

    __tablename__ = 'kube_app_bundle'
    id = Column(Integer, primary_key=True)
    name = Column(String(255), nullable=False)
    version = Column(String(255), nullable=False)
    file_path = Column(String(255), nullable=False)
    auto_update = Column(Boolean, nullable=False,
                         default=constants.APP_METADATA_AUTO_UPDATE_DEFAULT_VALUE)
    k8s_auto_update = Column(Boolean, nullable=False, default=True)
    k8s_timing = Column(KubeAppBundleTimingEnum,
                        nullable=False,
                        default=constants.APP_METADATA_TIMING_DEFAULT_VALUE)
    k8s_minimum_version = Column(String(16), nullable=False)
    k8s_maximum_version = Column(String(16), nullable=True)
    reserved = Column(JSONEncodedDict, nullable=True)
    UniqueConstraint('name', 'version', name='u_bundle_name_version')
    UniqueConstraint('file_path', name='u_bundle_file_path')
