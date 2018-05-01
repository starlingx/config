# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


from sqlalchemy import Column, MetaData, String, Table, UniqueConstraint
from sqlalchemy import Boolean, Integer, Enum, Text, ForeignKey, DateTime
from sqlalchemy.dialects import postgresql

ENGINE = 'InnoDB'
CHARSET = 'utf8'

# To migrate db to a new version you will have to modify all the enums to include:
# native_enum=False
# For example:
#     recordTypeEnum = Enum('standard',
#                          'profile',
#                          'sprofile',
#                          'reserve1',
#                          'reserve2',
#                           native_enum=False
#                           name='recordtypeEnum')
#
# This uses VARCHAR + check constraints for all backends because the current enums in the
# db cannot be overwritten with enums of the same name. To add attributes to the current
# enums without migrating the 'reserve1' and 'reserve2' values can be updated.  If creating
# a standalone column ( create_column method ) only then do the enums need to be explicitly
# created as shown below before calling create_column:
#
#     if migrate_engine.url.get_dialect() is postgresql.dialect:
#         enum1.create(migrate_engine, checkfirst=False)


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Enum definitions
    recordTypeEnum = Enum('standard',
                          'profile',
                          'sprofile',
                          'reserve1',
                          'reserve2',
                          name='recordtypeEnum')

    personalityEnum = Enum('controller',
                           'compute',
                           'network',
                           'storage',
                           'profile',
                           'reserve1',
                           'reserve2',
                           name='invPersonalityEnum')

    adminEnum = Enum('locked',
                      'unlocked',
                      'reserve1',
                      'reserve2',
                      name='administrativeEnum')

    operationalEnum = Enum('disabled',
                           'enabled',
                           'reserve1',
                           'reserve2',
                           name='operationalEnum')

    availabilityEnum = Enum('available',
                            'intest',
                            'degraded',
                            'failed',
                            'power-off',
                            'offline',
                            'offduty',
                            'online',
                            'dependency',
                            'not-installed',
                            'reserve1',
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

    typeEnum = Enum('snmpv2c_trap',
                    'reserve1',
                    'reserve2',
                    name='snmpVersionEnum')

    transportEnum = Enum('udp',
                         'reserve1',
                         'reserve2',
                         name='snmpTransportType')

    accessEnum = Enum('ro',
                      'rw',
                      'reserve1',
                      'reserve2',
                      name='accessEnum')

    provisionEnum = Enum('unprovisioned',
                         'inventoried',
                         'configured',
                         'provisioned',
                         'reserve1',
                         'reserve2',
                         name='invprovisionStateEnum')

    i_system = Table(
        'i_system',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        # system name
        Column('name', String(255), unique=True),
        Column('description', String(255), unique=True),
        Column('capabilities', Text),
        Column('contact', String(255)),
        Column('location', String(255)),
        Column('services', Integer, default=72),
        Column('software_version', String(255)),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_system.create()

    i_Host = Table(
        'i_host',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        # Host is reserved while it runs a blocking operation ; like Lock
        Column('reserved', Boolean),
        Column('recordtype', recordTypeEnum, default="standard"),

        Column('uuid', String(36), unique=True),

        Column('id', Integer, primary_key=True, nullable=False),  # autoincr
        Column('hostname', String(255), unique=True, index=True),

        Column('mgmt_mac', String(255), unique=True),
        # MAC 01:34:67:9A:CD:FG  (only need 16 bytes)
        Column('mgmt_ip', String(255), unique=True),

        # Board Management database members
        Column('bm_ip', String(255)),
        Column('bm_mac', String(255)),
        Column('bm_type', String(255)),
        Column('bm_username', String(255)),
        Column('personality', personalityEnum),
        Column('serialid', String(255)),
        Column('location', Text),
        Column('administrative', adminEnum, default="locked"),
        Column('operational', operationalEnum, default="disabled"),
        Column('availability', availabilityEnum, default="offline"),
        Column('action', actionEnum, default="none"),
        Column('task', String(64)),
        Column('uptime', Integer),
        Column('capabilities', Text),
        Column('config_status', String(255)),
        Column('config_applied', String(255)),
        Column('config_target', String(255)),
        Column('forisystemid', Integer,
               ForeignKey('i_system.id', ondelete='CASCADE')),


        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    i_Host.create()

    if migrate_engine.url.get_dialect() is postgresql.dialect:
        # Need to explicitly create Postgres enums during migrations
        provisionEnum.create(migrate_engine, checkfirst=False)

    invprovision = Column('invprovision', provisionEnum, default="unprovisioned")
    i_Host.create_column(invprovision)

    i_node = Table(
        'i_node',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        # numaNode from /sys/devices/system/node/nodeX/cpulist or cpumap
        Column('numa_node', Integer),
        Column('capabilities', Text),

        Column('forihostid', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),
        UniqueConstraint('numa_node', 'forihostid', name='u_hostnuma'),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_node.create()

    i_cpu = Table(
        'i_icpu',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        # Column('numa_node', Integer, unique=True), API attribute
        Column('cpu', Integer),
        Column('core', Integer),
        Column('thread', Integer),
        Column('cpu_family', String(255)),
        Column('cpu_model', String(255)),
        Column('allocated_function', String(255)),
        # JSONEncodedDict e.g. {'Crypto':'CaveCreek'}
        Column('capabilities', Text),

        Column('forihostid', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),
        Column('forinodeid', Integer,
               ForeignKey('i_node.id', ondelete='CASCADE')),
        UniqueConstraint('cpu', 'forihostid', name='u_hostcpu'),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_cpu.create()

    i_memory = Table(
        'i_imemory',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer,
               primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        # per NUMA: /sys/devices/system/node/node<x>/meminfo
        Column('memtotal_mib', Integer),
        Column('memavail_mib', Integer),
        Column('platform_reserved_mib', Integer),

        Column('hugepages_configured', Boolean),

        Column('avs_hugepages_size_mib', Integer),
        Column('avs_hugepages_reqd', Integer),
        Column('avs_hugepages_nr', Integer),
        Column('avs_hugepages_avail', Integer),

        Column('vm_hugepages_size_mib', Integer),
        Column('vm_hugepages_nr', Integer),
        Column('vm_hugepages_avail', Integer),

        Column('capabilities', Text),

        # psql requires unique FK
        Column('forihostid', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),
        Column('forinodeid', Integer, ForeignKey('i_node.id')),
        UniqueConstraint('forihostid', 'forinodeid', name='u_hostnode'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_memory.create()

    i_interface = Table(
        'i_interface',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36)),

        Column('ifname', String(255)),
        Column('iftype', String(255)),
        Column('imac', String(255), unique=True),
        Column('imtu', Integer),
        Column('networktype', String(255)),
        Column('aemode', String(255)),
        Column('txhashpolicy', String(255)),
        Column('providernetworks', String(255)),
        Column('providernetworksdict', Text),
        Column('schedpolicy', String(255)),
        Column('ifcapabilities', Text),
        # JSON{'speed':1000, 'MTU':9600, 'duplex':'','autoneg':'false'}
        Column('farend', Text),

        Column('forihostid', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),
        UniqueConstraint('ifname', 'forihostid', name='u_ifnameihost'),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_interface.create()

    i_port = Table(
        'i_port',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36)),

        Column('pname', String(255)),
        Column('pnamedisplay', String(255)),
        Column('pciaddr', String(255)),
        Column('pclass', String(255)),
        Column('pvendor', String(255)),
        Column('pdevice', String(255)),
        Column('psvendor', String(255)),
        Column('psdevice', String(255)),
        Column('numa_node', Integer),
        Column('mac', String(255)),
        Column('mtu', Integer),
        Column('speed', Integer),
        Column('link_mode', String(255)),
        Column('autoneg', String(255)),
        Column('bootp', String(255)),
        Column('capabilities', Text),
        # JSON{'speed':1000, 'MTU':9600, 'duplex':'','autoneg':'false'}

        Column('forihostid', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),
        Column('foriinterfaceid', Integer,
               ForeignKey('i_interface.id')),  # keep if unassign interface
        UniqueConstraint('pciaddr', 'forihostid', name='u_pciaddrihost'),
        Column('forinodeid', Integer,
               ForeignKey('i_node.id', ondelete='CASCADE')),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_port.create()

    i_stor = Table(
        'i_istor',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('osdid', Integer),
        Column('idisk_uuid', String(255)),
        Column('state', String(255)),
        Column('function', String(255)),
        Column('capabilities', Text),

        Column('forihostid', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),

        # UniqueConstraint('name', 'forihostid', name='u_namehost'),
        UniqueConstraint('osdid', 'forihostid', name='u_osdhost'),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_stor.create()

    i_disk = Table(
        'i_idisk',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('device_node', String(255)),
        Column('device_num', Integer),
        Column('device_type', String(255)),
        Column('size_mib', Integer),
        Column('serial_id', String(255)),
        Column('capabilities', Text),

        Column('forihostid', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),
        Column('foristorid', Integer,
               ForeignKey('i_istor.id')),  # keep if stor deleted


        # JKUNG is unique required for name ?
        UniqueConstraint('device_node', 'forihostid', name='u_devhost'),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_disk.create()

    i_ServiceGroup = Table(
        'i_servicegroup',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('servicename', String(255), unique=True),
        Column('state', String(255), default="unknown"),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_ServiceGroup.create()

    i_Service = Table(
        'i_service',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),  # autoincr
        Column('uuid', String(36), unique=True),

        Column('servicename', String(255)),
        Column('hostname', String(255)),
        Column('forihostid', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),

        Column('activity', String),  # active/standby
        Column('state', String),
        Column('reason', Text),  # JSON encodedlist of string

        UniqueConstraint('servicename', 'hostname',
                         name='u_servicehost'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_Service.create()

    i_trap = Table(
        'i_trap_destination',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('ip_address', String(40), unique=True, index=True),
        Column('community', String(255)),
        Column('port', Integer, default=162),
        Column('type', typeEnum, default='snmpv2c_trap'),

        Column('transport', transportEnum, default='udp'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_trap.create()

    i_community = Table(
        'i_community',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('community', String(255), unique=True, index=True),
        Column('view', String(255), default='.1'),
        Column('access', accessEnum, default='ro'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_community.create()

    i_alarm = Table(
        'i_alarm',
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
        Column('inhibit_alarms', Boolean),
        Column('masked', Boolean),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
                    )
    i_alarm.create()

    i_user = Table(
        'i_user',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('root_sig', String(255)),
        Column('reserved_1', String(255)),
        Column('reserved_2', String(255)),
        Column('reserved_3', String(255)),

        Column('forisystemid', Integer,
               ForeignKey('i_system.id', ondelete='CASCADE')),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_user.create()

    i_dns = Table(
        'i_dns',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('nameservers', String(255)),  # csv list of nameservers

        Column('forisystemid', Integer,
               ForeignKey('i_system.id', ondelete='CASCADE')),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_dns.create()

    i_ntp = Table(
        'i_ntp',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('ntpservers', String(255)),  # csv list of ntp servers

        Column('forisystemid', Integer,
               ForeignKey('i_system.id', ondelete='CASCADE')),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_ntp.create()

    i_extoam = Table(
        'i_extoam',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('oam_subnet', String(255)),
        Column('oam_gateway_ip', String(255)),
        Column('oam_floating_ip', String(255)),
        Column('oam_c0_ip', String(255)),
        Column('oam_c1_ip', String(255)),

        Column('forisystemid', Integer,
               ForeignKey('i_system.id', ondelete='CASCADE')),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_extoam.create()

    i_pm = Table(
        'i_pm',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('retention_secs', String(255)),  # retention period in secs
        Column('reserved_1', String(255)),
        Column('reserved_2', String(255)),
        Column('reserved_3', String(255)),

        Column('forisystemid', Integer,
               ForeignKey('i_system.id', ondelete='CASCADE')),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_pm.create()

    i_storconfig = Table(
        'i_storconfig',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('cinder_backend', String(255)),  # not configurable
        Column('database_gib', String(255)),
        Column('image_gib', String(255)),
        Column('backup_gib', String(255)),
        Column('cinder_device', String(255)),  # not configurable
        Column('cinder_gib', String(255)),

        Column('forisystemid', Integer,
               ForeignKey('i_system.id', ondelete='CASCADE')),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_storconfig.create()


def downgrade(migrate_engine):
    raise NotImplementedError('Downgrade from Initial is unsupported.')

    # meta = MetaData()
    # meta.bind = migrate_engine

    # t = Table('i_Host', meta, autoload=True)
    # t.drop()
    # t = Table('i_cpu', meta, autoload=True)
    # t.drop()
    # t = Table('i_memory', meta, autoload=True)
    # t.drop()
    # t = Table('i_port', meta, autoload=True)
    # t.drop()
    # t = Table('i_disk', meta, autoload=True)
    # t.drop()
