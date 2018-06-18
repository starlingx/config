# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from migrate.changeset import UniqueConstraint
from sqlalchemy import Boolean, Integer, DateTime, BigInteger, Float
from sqlalchemy import Enum, Text, ForeignKey
from sqlalchemy import Column, MetaData, String, Table
from sqlalchemy.dialects import postgresql

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    Table('i_system',
        meta,
        Column('id', Integer,
            primary_key=True, nullable=False),
        mysql_engine=ENGINE, mysql_charset=CHARSET)

    i_host = Table('i_host',
                   meta,
                   Column('id', Integer,
                          primary_key=True, nullable=False),
                   mysql_engine=ENGINE, mysql_charset=CHARSET,
                   autoload=True)

    if migrate_engine.url.get_dialect() is postgresql.dialect:
        old_provisionEnum = Enum('unprovisioned',
                             'inventoried',
                             'configured',
                             'provisioned',
                             'reserve1',
                             'reserve2',
                             name='invprovisionStateEnum')

        provisionEnum = Enum('unprovisioned',
                             'inventoried',
                             'configured',
                             'provisioning',
                             'provisioned',
                             'reserve1',
                             'reserve2',
                             name='invprovisionStateEnum')

        inv_provision_col = i_host.c.invprovision
        inv_provision_col.alter(Column('invprovision', String(60)))
        old_provisionEnum.drop(bind=migrate_engine, checkfirst=False)
        provisionEnum.create(bind=migrate_engine, checkfirst=False)
        migrate_engine.execute('ALTER TABLE i_host ALTER COLUMN invprovision TYPE "invprovisionStateEnum" '
                   'USING invprovision::text::"invprovisionStateEnum"')

    Table('i_node',
        meta,
        Column('id', Integer,
            primary_key=True, nullable=False),
        mysql_engine=ENGINE, mysql_charset=CHARSET)

    i_alarm_history = Table(
        'i_alarm_history',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(255), unique=True, index=True),
        Column('alarm_id', String(255), index=True),
        Column('alarm_state', String(255)),
        Column('entity_type_id', String(255), index=True),
        Column('entity_instance_id', String(255), index=True),
        Column('timestamp', DateTime(timezone=False)),
        Column('severity', String(255), index=True),
        Column('reason_text', String(255)),
        Column('alarm_type', String(255), index=True),
        Column('probable_cause', String(255)),
        Column('proposed_repair_action', String(255)),
        Column('service_affecting', Boolean),
        Column('suppression', Boolean),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_alarm_history.create()

    i_customer_log = Table(
        'i_customer_log',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(255), unique=True, index=True),
        Column('log_id', String(255), index=True),
        Column('entity_type_id', String(255), index=True),
        Column('entity_instance_id', String(255), index=True),
        Column('timestamp', DateTime(timezone=False)),
        Column('severity', String(255), index=True),
        Column('reason_text', String(255)),
        Column('log_type', String(255), index=True),
        Column('probable_cause', String(255)),
        Column('service_affecting', Boolean),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_customer_log.create()

    i_infra = Table(
        'i_infra',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('infra_subnet', String(255)),

        Column('infra_start', String(255)),
        Column('infra_end', String(255)),

        Column('forisystemid', Integer,
               ForeignKey('i_system.id', ondelete='CASCADE')),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_infra.create()

    interfaces = Table(
        'interfaces',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),

        Column('uuid', String(36), unique=True),
        Column('forihostid', Integer, ForeignKey('i_host.id',
                                                 ondelete='CASCADE')),
        Column('iftype', String(255)),
        Column('ifname', String(255)),
        Column('networktype', String(255)),

        Column('sriov_numvfs', Integer),
        Column('ifcapabilities', Text),
        Column('farend', Text),

        UniqueConstraint('ifname', 'forihostid', name='u_interfacenameihost'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    interfaces.create()

    interfaces_to_interfaces = Table(
        'interfaces_to_interfaces',
        meta,
        Column("used_by_id", Integer,
               ForeignKey("interfaces.id", ondelete='CASCADE'),
               primary_key=True),
        Column("uses_id", Integer,
               ForeignKey("interfaces.id", ondelete='CASCADE'),
               primary_key=True),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    interfaces_to_interfaces.create()

    ethernet_interfaces = Table(
        'ethernet_interfaces',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, ForeignKey('interfaces.id', ondelete="CASCADE"),
               primary_key=True, nullable=False),

        Column('imac', String(255)),
        Column('imtu', Integer),
        Column('providernetworks', String(255)),
        Column('providernetworksdict', Text),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    ethernet_interfaces.create()

    ae_interfaces = Table(
        'ae_interfaces',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, ForeignKey('interfaces.id', ondelete="CASCADE"),
               primary_key=True, nullable=False),

        Column('aemode', String(255)),
        Column('aedict', Text),
        Column('txhashpolicy', String(255)),
        Column('schedpolicy', String(255)),

        Column('imac', String(255)),
        Column('imtu', Integer),
        Column('providernetworks', String(255)),
        Column('providernetworksdict', Text),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    ae_interfaces.create()

    vlan_interfaces = Table(
        'vlan_interfaces',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, ForeignKey('interfaces.id', ondelete="CASCADE"),
               primary_key=True, nullable=False),

        Column('vlan_id', String(255)),
        Column('vlan_type', String(255)),

        Column('imac', String(255)),
        Column('imtu', Integer),
        Column('providernetworks', String(255)),
        Column('providernetworksdict', Text),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    vlan_interfaces.create()

    ports = Table(
        'ports',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('host_id', Integer, ForeignKey('i_host.id',
                                              ondelete='CASCADE')),
        Column('node_id', Integer, ForeignKey('i_node.id',
                                              ondelete='SET NULL')),
        Column('interface_id', Integer, ForeignKey('interfaces.id',
                                                   ondelete='SET NULL')),
        Column('type', String(255)),
        Column('name', String(255)),
        Column('namedisplay', String(255)),
        Column('pciaddr', String(255)),
        Column('dev_id', Integer),
        Column('sriov_totalvfs', Integer),
        Column('sriov_numvfs', Integer),
        Column('sriov_vfs_pci_address', String(1020)),
        Column('driver', String(255)),

        Column('pclass', String(255)),
        Column('pvendor', String(255)),
        Column('pdevice', String(255)),
        Column('psvendor', String(255)),
        Column('psdevice', String(255)),
        Column('dpdksupport', Boolean, default=False),
        Column('numa_node', Integer),
        Column('capabilities', Text),

        UniqueConstraint('pciaddr', 'dev_id', 'host_id',
                         name='u_pciaddr_dev_host_id'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    ports.create()

    ethernet_ports = Table(
        'ethernet_ports',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, ForeignKey('ports.id', ondelete="CASCADE"),
               primary_key=True, nullable=False),

        Column('mac', String(255)),
        Column('mtu', Integer),
        Column('speed', Integer),
        Column('link_mode', String(255)),
        Column('duplex', String(255)),
        Column('autoneg', String(255)),
        Column('bootp', String(255)),
        Column('capabilities', Text),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    ethernet_ports.create()

    address_pools = Table(
        'address_pools',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),

        Column('uuid', String(36), unique=True),
        Column('name', String(128), unique=True, nullable=False),
        Column('family', Integer, nullable=False),
        Column('network', String(50), nullable=False),
        Column('prefix', Integer, nullable=False),
        Column('order', String(32), nullable=False),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    address_pools.create()

    address_pool_ranges = Table(
        'address_pool_ranges',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),

        Column('uuid', String(36), unique=True),
        Column('start', String(50), nullable=False),
        Column('end', String(50), nullable=False),

        Column('address_pool_id', Integer,
               ForeignKey('address_pools.id', ondelete="CASCADE"),
               nullable=False),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    address_pool_ranges.create()

    addresses = Table(
        'addresses',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),

        Column('uuid', String(36), unique=True),
        Column('name', String(255)),
        Column('family', Integer, nullable=False),
        Column('address', String(50), nullable=False),
        Column('prefix', Integer, nullable=False),
        Column('enable_dad', Boolean(), default=True),

        Column('interface_id', Integer,
               ForeignKey('interfaces.id', ondelete="CASCADE"),
               nullable=True),

        Column('address_pool_id', Integer,
               ForeignKey('address_pools.id', ondelete="CASCADE"),
               nullable=True),

        UniqueConstraint('family', 'address', 'interface_id',
                         name='u_address@family@interface'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    addresses.create()

    address_modes = Table(
        'address_modes',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),

        Column('uuid', String(36), unique=True),
        Column('family', Integer, nullable=False),
        Column('mode', String(32), nullable=False),

        Column('interface_id', Integer,
               ForeignKey('interfaces.id', ondelete="CASCADE"),
               nullable=False),

        Column('address_pool_id', Integer,
               ForeignKey('address_pools.id', ondelete="CASCADE"),
               nullable=True),

        UniqueConstraint('family', 'interface_id', name='u_family@interface'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    address_modes.create()

    routes = Table(
        'routes',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),

        Column('uuid', String(36), unique=True),
        Column('family', Integer, nullable=False),
        Column('network', String(50), nullable=False),
        Column('prefix', Integer, nullable=False),
        Column('gateway', String(50), nullable=False),
        Column('metric', Integer, default=1, nullable=False),

        Column('interface_id', Integer,
               ForeignKey('interfaces.id', ondelete="CASCADE"),
               nullable=False),

        UniqueConstraint('family', 'network', 'prefix', 'gateway',
                         'interface_id',
                         name='u_family@network@prefix@gateway@host'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    routes.create()

    networks = Table(
        'networks',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),

        Column('uuid', String(36), unique=True),
        Column('type', String(255), unique=True),
        Column('mtu', Integer, nullable=False),
        Column('link_capacity', Integer),
        Column('dynamic', Boolean, nullable=False),
        Column('vlan_id', Integer),

        Column('address_pool_id', Integer,
               ForeignKey('address_pools.id', ondelete='CASCADE'),
               nullable=False),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    networks.create()

    i_port = Table('i_port', meta, autoload=True)
    i_port.create_column(Column('sriov_totalvfs', Integer))
    i_port.create_column(Column('sriov_numvfs', Integer))
    i_port.create_column(Column('sriov_vfs_pci_address', String(1020)))
    i_port.create_column(Column('driver', String(255)))
    i_interface = Table('i_interface', meta, autoload=True)
    i_interface.create_column(Column('sriov_numvfs', Integer))

    i_port = Table('i_port', meta, autoload=True)
    i_port.create_column(Column('dpdksupport', Boolean, default=False))

    i_interface = Table('i_interface', meta, autoload=True)
    i_interface.create_column(Column('aedict', Text))

    pvTypeEnum = Enum('disk',
                      'partition',
                      'reserve1',
                      'reserve2',
                      native_enum=False,
                      name='physicalVolTypeEnum')

    pvStateEnum = Enum('unprovisioned',
                       'adding',
                       'provisioned',
                       'removing',
                       'reserve1',
                       'reserve2',
                       native_enum=False,
                       name='pvStateEnum')

    vgStateEnum = Enum('unprovisioned',
                       'adding',
                       'provisioned',
                       'removing',
                       'reserve1',
                       'reserve2',
                       native_enum=False,
                       name='vgStateEnum')

    i_lvg = Table(
        'i_lvg',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('vg_state', vgStateEnum, default="unprovisioned"),

        Column('lvm_vg_name', String(64)),
        Column('lvm_vg_uuid', String(64)),
        Column('lvm_vg_access', String(64)),
        Column('lvm_max_lv', Integer),
        Column('lvm_cur_lv', Integer),
        Column('lvm_max_pv', Integer),
        Column('lvm_cur_pv', Integer),
        Column('lvm_vg_size', BigInteger),
        Column('lvm_vg_total_pe', Integer),
        Column('lvm_vg_free_pe', Integer),

        Column('capabilities', Text),
        Column('forihostid', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_lvg.create()

    i_pv = Table(
        'i_pv',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('pv_state', pvStateEnum, default="unprovisioned"),

        Column('pv_type', pvTypeEnum, default="disk"),
        Column('idisk_uuid', String()),
        Column('idisk_device_node', String(64)),

        Column('lvm_pv_name', String(64)),
        Column('lvm_vg_name', String(64)),
        Column('lvm_pv_uuid', String(64)),
        Column('lvm_pv_size', BigInteger),
        Column('lvm_pe_total', Integer),
        Column('lvm_pe_alloced', Integer),

        Column('capabilities', Text),
        Column('forihostid', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),
        Column('forilvgid', Integer,
               ForeignKey('i_lvg.id', ondelete='CASCADE')),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_pv.create()

    i_idisk = Table('i_idisk', meta, autoload=True)
    foripvid = Column('foripvid', Integer, ForeignKey('i_pv.id'))
    foripvid.create(i_idisk)

    sensorgroups = Table(
        'i_sensorgroups',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),

        Column('uuid', String(36), unique=True),
        Column('host_id', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),

        Column('sensorgroupname', String(255)),
        Column('path', String(255)),
        Column('datatype', String(255)),  # polymorphic 'analog'/'discrete
        Column('sensortype', String(255)),
        Column('description', String(255)),
        Column('state', String(255)),  # enabled or disabled
        Column('possible_states', String(255)),
        Column('audit_interval_group', Integer),
        Column('record_ttl', Integer),

        Column('algorithm', String(255)),
        Column('actions_critical_choices', String(255)),
        Column('actions_major_choices', String(255)),
        Column('actions_minor_choices', String(255)),
        Column('actions_minor_group', String(255)),
        Column('actions_major_group', String(255)),
        Column('actions_critical_group', String(255)),

        Column('suppress', Boolean),  # True, disables the action

        Column('capabilities', Text),

        UniqueConstraint('sensorgroupname', 'path', 'host_id',
                         name='u_sensorgroupname_path_hostid'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    sensorgroups.create()

    # polymorphic on datatype 'discrete'
    sensorgroups_discrete = Table(
        'i_sensorgroups_discrete',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer,
               ForeignKey('i_sensorgroups.id', ondelete="CASCADE"),
               primary_key=True, nullable=False),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    sensorgroups_discrete.create()

    # polymorphic on datatype 'analog'
    sensorgroups_analog = Table(
        'i_sensorgroups_analog',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer,
               ForeignKey('i_sensorgroups.id', ondelete="CASCADE"),
               primary_key=True, nullable=False),

        Column('unit_base_group', String(255)),      # revolutions
        Column('unit_modifier_group', String(255)),  # 100
        Column('unit_rate_group', String(255)),      # minute

        Column('t_minor_lower_group', String(255)),
        Column('t_minor_upper_group', String(255)),
        Column('t_major_lower_group', String(255)),
        Column('t_major_upper_group', String(255)),
        Column('t_critical_lower_group', String(255)),
        Column('t_critical_upper_group', String(255)),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    sensorgroups_analog.create()

    sensors = Table(
        'i_sensors',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('host_id', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),

        Column('sensorgroup_id', Integer,
               ForeignKey('i_sensorgroups.id', ondelete='SET NULL')),

        Column('sensorname', String(255)),
        Column('path', String(255)),

        Column('datatype', String(255)),  # polymorphic on datatype
        Column('sensortype', String(255)),

        Column('status', String(255)),  # ok, minor, major, critical, disabled
        Column('state', String(255)),  # enabled, disabled
        Column('state_requested', String(255)),

        Column('sensor_action_requested', String(255)),

        Column('audit_interval', Integer),
        Column('algorithm', String(255)),
        Column('actions_minor', String(255)),
        Column('actions_major', String(255)),
        Column('actions_critical', String(255)),

        Column('suppress', Boolean),  # True, disables the action

        Column('capabilities', Text),

        UniqueConstraint('sensorname', 'path', 'host_id',
                         name='u_sensorname_path_host_id'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    sensors.create()

    # discrete sensor
    sensors_discrete = Table(
        'i_sensors_discrete',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer,
               ForeignKey('i_sensors.id', ondelete="CASCADE"),
               primary_key=True, nullable=False),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    sensors_discrete.create()

    # analog sensor
    sensors_analog = Table(
        'i_sensors_analog',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer,
               ForeignKey('i_sensors.id', ondelete="CASCADE"),
               primary_key=True, nullable=False),

        Column('unit_base', String(255)),      # revolutions
        Column('unit_modifier', String(255)),  # 10^2
        Column('unit_rate', String(255)),      # minute

        Column('t_minor_lower', String(255)),
        Column('t_minor_upper', String(255)),
        Column('t_major_lower', String(255)),
        Column('t_major_upper', String(255)),
        Column('t_critical_lower', String(255)),
        Column('t_critical_upper', String(255)),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    sensors_analog.create()

    pci_devices = Table(
        'pci_devices',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(255), unique=True, index=True),
        Column('host_id', Integer, ForeignKey('i_host.id',
                                              ondelete='CASCADE')),
        Column('name', String(255)),
        Column('pciaddr', String(255)),
        Column('pclass_id', String(6)),
        Column('pvendor_id', String(4)),
        Column('pdevice_id', String(4)),
        Column('pclass', String(255)),
        Column('pvendor', String(255)),
        Column('pdevice', String(255)),
        Column('psvendor', String(255)),
        Column('psdevice', String(255)),
        Column('numa_node', Integer),
        Column('driver', String(255)),
        Column('sriov_totalvfs', Integer),
        Column('sriov_numvfs', Integer),
        Column('sriov_vfs_pci_address', String(1020)),
        Column('enabled', Boolean),
        Column('extra_info', Text),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    pci_devices.create()

    loads = Table(
        'loads',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36)),

        Column('state', String(255)),

        Column('software_version', String(255)),
        Column('compatible_version', String(255)),

        Column('required_patches', String(2047)),

        UniqueConstraint('software_version'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    loads.create()

    # loads = Table('loads', meta, Column('id', Integer, primary_key=True,
    #                                     nullable=False))
    software_upgrade = Table(
        'software_upgrade',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('state', String(128), nullable=False),
        Column('from_load', Integer, ForeignKey('loads.id',
                                                ondelete="CASCADE"),
               nullable=False),
        Column('to_load', Integer, ForeignKey('loads.id', ondelete="CASCADE"),
               nullable=False),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    software_upgrade.create()

    host_upgrade = Table(
        'host_upgrade',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('forihostid', Integer, ForeignKey('i_host.id',
                                                 ondelete='CASCADE')),
        Column('software_load', Integer, ForeignKey('loads.id'),
               nullable=False),
        Column('target_load', Integer, ForeignKey('loads.id'),
               nullable=False),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    host_upgrade.create()

    drbdconfig = Table(
        'drbdconfig',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('link_util', Integer),
        Column('num_parallel', Integer),
        Column('rtt_ms', Float),

        Column('forisystemid', Integer,
               ForeignKey('i_system.id', ondelete='CASCADE')),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    drbdconfig.create()

    i_host.create_column(Column('ihost_action', String(255)))
    i_host.create_column(Column('vim_progress_status', String(255)))
    i_host.create_column(Column('subfunctions', String(255)))
    i_host.create_column(Column('subfunction_oper', String(255),
                                default="disabled"))
    i_host.create_column(Column('subfunction_avail', String(255),
                                default="not-installed"))
    i_host.create_column(Column('boot_device', String(255)))
    i_host.create_column(Column('rootfs_device', String(255)))
    i_host.create_column(Column('install_output', String(255)))
    i_host.create_column(Column('console', String(255)))
    i_host.create_column(Column('vsc_controllers', String(255)))
    i_host.create_column(Column('ttys_dcd', Boolean))

    # 005_add_hugepage_attributes.py
    i_memory = Table('i_imemory', meta, autoload=True)
    i_memory.drop_column('vm_hugepages_size_mib')
    i_memory.drop_column('vm_hugepages_nr')
    i_memory.drop_column('vm_hugepages_avail')

    i_memory.create_column(Column('vm_hugepages_nr_2M', Integer))
    i_memory.create_column(Column('vm_hugepages_nr_1G', Integer))
    i_memory.create_column(Column('vm_hugepages_use_1G', Boolean))
    i_memory.create_column(Column('vm_hugepages_possible_2M', Integer))
    i_memory.create_column(Column('vm_hugepages_possible_1G', Integer))
    # 012_hugepage_enhancements.py
    i_memory.create_column(Column('vm_hugepages_nr_2M_pending', Integer))
    i_memory.create_column(Column('vm_hugepages_nr_1G_pending', Integer))
    i_memory.create_column(Column('vm_hugepages_avail_2M', Integer))
    i_memory.create_column(Column('vm_hugepages_avail_1G', Integer))
    # 014_hugepage_4K_memory.py
    i_memory.create_column(Column('vm_hugepages_nr_4K', Integer))
    # 016_compute_memory.py
    i_memory.create_column(Column('node_memtotal_mib', Integer))

    i_extoam = Table('i_extoam', meta, autoload=True)
    i_extoam.create_column(Column('oam_start_ip', String(255)))
    i_extoam.create_column(Column('oam_end_ip', String(255)))

    i_storconfig = Table('i_storconfig', meta, autoload=True)
    i_storconfig.create_column(Column('glance_backend', String(255)))
    i_storconfig.create_column(Column('glance_gib', Integer, default=0))
    i_storconfig.create_column(Column('img_conversions_gib', String(255)))

    table_names = ['i_extoam', 'i_infra']
    for name in table_names:
        table = Table(name, meta, autoload=True)
        table.drop()

    serviceEnum = Enum('identity',
                       name='serviceEnum')

    service_parameter = Table(
        'service_parameter',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('service', serviceEnum),
        Column('section', String(255)),
        Column('name', String(255)),
        Column('value', String(255)),
        UniqueConstraint('service', 'section', 'name',
                         name='u_servicesectionname'),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    service_parameter.create()


def downgrade(migrate_engine):

    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
