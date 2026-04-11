#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""intial revision

Revision ID: e41f158124dc
Revises:
Create Date: 2025-10-07 04:20:35.229119

"""
from typing import Sequence
from typing import Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'e41f158124dc'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Create enums
    recordtype_enum = postgresql.ENUM('standard', 'profile', 'sprofile', 'reserve1', 'reserve2', name='recordtypeEnum')
    personality_enum = postgresql.ENUM(
        'controller', 'worker', 'network', 'storage', 'profile',
        'reserve1', 'reserve2', name='invPersonalityEnum')
    admin_enum = postgresql.ENUM('locked', 'unlocked', 'reserve1', 'reserve2', name='administrativeEnum')
    operational_enum = postgresql.ENUM('disabled', 'enabled', 'reserve1', 'reserve2', name='operationalEnum')
    availability_enum = postgresql.ENUM(
        'available', 'intest', 'degraded', 'failed', 'power-off',
        'offline', 'offduty', 'online', 'dependency', 'not-installed',
        'reserve1', 'reserve2', name='availabilityEnum')
    action_enum = postgresql.ENUM(
        'none', 'lock', 'force-lock', 'unlock', 'reset', 'swact',
        'force-swact', 'reboot', 'power-on', 'power-off', 'reinstall',
        'reserve1', 'reserve2', name='actionEnum')
    snmp_version_enum = postgresql.ENUM('snmpv2c_trap', 'reserve1', 'reserve2', name='snmpVersionEnum')
    transport_enum = postgresql.ENUM('udp', 'reserve1', 'reserve2', name='snmpTransportType')
    access_enum = postgresql.ENUM('ro', 'rw', 'reserve1', 'reserve2', name='accessEnum')
    provision_enum = postgresql.ENUM(
        'unprovisioned', 'inventoried', 'configured', 'provisioned',
        'reserve1', 'reserve2', name='invprovisionStateEnum')
    provision_enum.create(op.get_bind())

    # Create i_system table
    op.create_table('i_system',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('name', sa.String(255), unique=True),
        sa.Column('description', sa.String(255), unique=True),
        sa.Column('capabilities', sa.Text()),
        sa.Column('contact', sa.String(255)),
        sa.Column('location', sa.String(255)),
        sa.Column('services', sa.Integer(), default=72),
        sa.Column('software_version', sa.String(255)),
    )

    # Create i_host table
    op.create_table('i_host',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('reserved', sa.Boolean()),
        sa.Column('recordtype', recordtype_enum, default='standard'),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('hostname', sa.String(255), unique=True, index=True),
        sa.Column('mgmt_mac', sa.String(255), unique=True),
        sa.Column('mgmt_ip', sa.String(255), unique=True),
        sa.Column('bm_ip', sa.String(255)),
        sa.Column('bm_mac', sa.String(255)),
        sa.Column('bm_type', sa.String(255)),
        sa.Column('bm_username', sa.String(255)),
        sa.Column('personality', personality_enum),
        sa.Column('serialid', sa.String(255)),
        sa.Column('location', sa.Text()),
        sa.Column('administrative', admin_enum, default='locked'),
        sa.Column('operational', operational_enum, default='disabled'),
        sa.Column('availability', availability_enum, default='offline'),
        sa.Column('action', action_enum, default='none'),
        sa.Column('task', sa.String(64)),
        sa.Column('uptime', sa.Integer()),
        sa.Column('capabilities', sa.Text()),
        sa.Column('config_status', sa.String(255)),
        sa.Column('config_applied', sa.String(255)),
        sa.Column('config_target', sa.String(255)),
        sa.Column('forisystemid', sa.Integer(), sa.ForeignKey('i_system.id', ondelete='CASCADE')),
    )

    # Add invprovision column to i_host table
    op.add_column('i_host', sa.Column('invprovision', provision_enum, default='unprovisioned'))

    # Create i_node table
    op.create_table('i_node',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('numa_node', sa.Integer()),
        sa.Column('capabilities', sa.Text()),
        sa.Column('forihostid', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.UniqueConstraint('numa_node', 'forihostid', name='u_hostnuma'),
    )

    # Create i_icpu table
    op.create_table('i_icpu',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('cpu', sa.Integer()),
        sa.Column('core', sa.Integer()),
        sa.Column('thread', sa.Integer()),
        sa.Column('cpu_family', sa.String(255)),
        sa.Column('cpu_model', sa.String(255)),
        sa.Column('allocated_function', sa.String(255)),
        sa.Column('capabilities', sa.Text()),
        sa.Column('forihostid', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('forinodeid', sa.Integer(), sa.ForeignKey('i_node.id', ondelete='CASCADE')),
        sa.UniqueConstraint('cpu', 'forihostid', name='u_hostcpu'),
    )

    # Create i_imemory table
    op.create_table('i_imemory',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('memtotal_mib', sa.Integer()),
        sa.Column('memavail_mib', sa.Integer()),
        sa.Column('platform_reserved_mib', sa.Integer()),
        sa.Column('hugepages_configured', sa.Boolean()),
        sa.Column('avs_hugepages_size_mib', sa.Integer()),
        sa.Column('avs_hugepages_reqd', sa.Integer()),
        sa.Column('avs_hugepages_nr', sa.Integer()),
        sa.Column('avs_hugepages_avail', sa.Integer()),
        sa.Column('vm_hugepages_size_mib', sa.Integer()),
        sa.Column('vm_hugepages_nr', sa.Integer()),
        sa.Column('vm_hugepages_avail', sa.Integer()),
        sa.Column('capabilities', sa.Text()),
        sa.Column('forihostid', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('forinodeid', sa.Integer(), sa.ForeignKey('i_node.id')),
        sa.UniqueConstraint('forihostid', 'forinodeid', name='u_hostnode'),
    )

    # Create i_interface table
    op.create_table('i_interface',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36)),
        sa.Column('ifname', sa.String(255)),
        sa.Column('iftype', sa.String(255)),
        sa.Column('imac', sa.String(255), unique=True),
        sa.Column('imtu', sa.Integer()),
        sa.Column('networktype', sa.String(255)),
        sa.Column('aemode', sa.String(255)),
        sa.Column('txhashpolicy', sa.String(255)),
        sa.Column('providernetworks', sa.String(255)),
        sa.Column('providernetworksdict', sa.Text()),
        sa.Column('schedpolicy', sa.String(255)),
        sa.Column('ifcapabilities', sa.Text()),
        sa.Column('farend', sa.Text()),
        sa.Column('forihostid', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.UniqueConstraint('ifname', 'forihostid', name='u_ifnameihost'),
    )

    # Create i_port table
    op.create_table('i_port',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36)),
        sa.Column('pname', sa.String(255)),
        sa.Column('pnamedisplay', sa.String(255)),
        sa.Column('pciaddr', sa.String(255)),
        sa.Column('pclass', sa.String(255)),
        sa.Column('pvendor', sa.String(255)),
        sa.Column('pdevice', sa.String(255)),
        sa.Column('psvendor', sa.String(255)),
        sa.Column('psdevice', sa.String(255)),
        sa.Column('numa_node', sa.Integer()),
        sa.Column('mac', sa.String(255)),
        sa.Column('mtu', sa.Integer()),
        sa.Column('speed', sa.Integer()),
        sa.Column('link_mode', sa.String(255)),
        sa.Column('autoneg', sa.String(255)),
        sa.Column('bootp', sa.String(255)),
        sa.Column('capabilities', sa.Text()),
        sa.Column('forihostid', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('foriinterfaceid', sa.Integer(), sa.ForeignKey('i_interface.id')),
        sa.Column('forinodeid', sa.Integer(), sa.ForeignKey('i_node.id', ondelete='CASCADE')),
        sa.UniqueConstraint('pciaddr', 'forihostid', name='u_pciaddrihost'),
    )

    # Create i_istor table
    op.create_table('i_istor',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('osdid', sa.Integer()),
        sa.Column('idisk_uuid', sa.String(255)),
        sa.Column('state', sa.String(255)),
        sa.Column('function', sa.String(255)),
        sa.Column('capabilities', sa.Text()),
        sa.Column('forihostid', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.UniqueConstraint('osdid', 'forihostid', name='u_osdhost'),
    )

    # Create i_idisk table
    op.create_table('i_idisk',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('device_node', sa.String(255)),
        sa.Column('device_num', sa.Integer()),
        sa.Column('device_type', sa.String(255)),
        sa.Column('size_mib', sa.Integer()),
        sa.Column('serial_id', sa.String(255)),
        sa.Column('capabilities', sa.Text()),
        sa.Column('forihostid', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('foristorid', sa.Integer(), sa.ForeignKey('i_istor.id')),
        sa.UniqueConstraint('device_node', 'forihostid', name='u_devhost'),
    )

    # Create i_servicegroup table
    op.create_table('i_servicegroup',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('servicename', sa.String(255), unique=True),
        sa.Column('state', sa.String(255), default='unknown'),
    )

    # Create i_service table
    op.create_table('i_service',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('servicename', sa.String(255)),
        sa.Column('hostname', sa.String(255)),
        sa.Column('forihostid', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('activity', sa.String()),
        sa.Column('state', sa.String()),
        sa.Column('reason', sa.Text()),
        sa.UniqueConstraint('servicename', 'hostname', name='u_servicehost'),
    )

    # Create i_trap_destination table
    op.create_table('i_trap_destination',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('ip_address', sa.String(40), unique=True, index=True),
        sa.Column('community', sa.String(255)),
        sa.Column('port', sa.Integer(), default=162),
        sa.Column('type', snmp_version_enum, default='snmpv2c_trap'),
        sa.Column('transport', transport_enum, default='udp'),
    )

    # Create i_community table
    op.create_table('i_community',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('community', sa.String(255), unique=True, index=True),
        sa.Column('view', sa.String(255), default='.1'),
        sa.Column('access', access_enum, default='ro'),
    )

    # Create i_user table
    op.create_table('i_user',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('root_sig', sa.String(255)),
        sa.Column('reserved_1', sa.String(255)),
        sa.Column('reserved_2', sa.String(255)),
        sa.Column('reserved_3', sa.String(255)),
        sa.Column('forisystemid', sa.Integer(), sa.ForeignKey('i_system.id', ondelete='CASCADE')),
    )

    # Create i_dns table
    op.create_table('i_dns',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('nameservers', sa.String(255)),
        sa.Column('forisystemid', sa.Integer(), sa.ForeignKey('i_system.id', ondelete='CASCADE')),
    )

    # Create i_ntp table
    op.create_table('i_ntp',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('ntpservers', sa.String(255)),
        sa.Column('forisystemid', sa.Integer(), sa.ForeignKey('i_system.id', ondelete='CASCADE')),
    )

    # Create i_extoam table
    op.create_table('i_extoam',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('oam_subnet', sa.String(255)),
        sa.Column('oam_gateway_ip', sa.String(255)),
        sa.Column('oam_floating_ip', sa.String(255)),
        sa.Column('oam_c0_ip', sa.String(255)),
        sa.Column('oam_c1_ip', sa.String(255)),
        sa.Column('forisystemid', sa.Integer(), sa.ForeignKey('i_system.id', ondelete='CASCADE')),
    )

    # Create i_pm table
    op.create_table('i_pm',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('retention_secs', sa.String(255)),
        sa.Column('reserved_1', sa.String(255)),
        sa.Column('reserved_2', sa.String(255)),
        sa.Column('reserved_3', sa.String(255)),
        sa.Column('forisystemid', sa.Integer(), sa.ForeignKey('i_system.id', ondelete='CASCADE')),
    )

    # Create i_storconfig table
    op.create_table('i_storconfig',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('cinder_backend', sa.String(255)),
        sa.Column('database_gib', sa.String(255)),
        sa.Column('image_gib', sa.String(255)),
        sa.Column('backup_gib', sa.String(255)),
        sa.Column('cinder_device', sa.String(255)),
        sa.Column('cinder_gib', sa.String(255)),
        sa.Column('forisystemid', sa.Integer(), sa.ForeignKey('i_system.id', ondelete='CASCADE')),
    )


def downgrade() -> None:
    raise NotImplementedError('Downgrade from Initial is unsupported.')
