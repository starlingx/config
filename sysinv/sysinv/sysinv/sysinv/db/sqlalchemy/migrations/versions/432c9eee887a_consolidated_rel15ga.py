#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""consolidated rel15ga

Revision ID: 432c9eee887a
Revises: e41f158124dc
Create Date: 2025-10-07 05:47:26.638123

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '432c9eee887a'
down_revision: Union[str, None] = 'e41f158124dc'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None



def upgrade():
    # Create i_system table (already exists from 001_init, but ensuring it exists)
    # This is a no-op if table already exists

    # Handle PostgreSQL enum modification for i_host.invprovision
    bind = op.get_bind()
    if bind.dialect.name == 'postgresql':
        # Alter existing enum to add 'provisioning' state
        op.execute("ALTER TYPE \"invprovisionStateEnum\" ADD VALUE 'provisioning' AFTER 'configured'")

    # Create i_node table (already exists from 001_init)

    # Create alarm history table
    op.create_table('i_alarm_history',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(255), unique=True, index=True),
        sa.Column('alarm_id', sa.String(255), index=True),
        sa.Column('alarm_state', sa.String(255)),
        sa.Column('entity_type_id', sa.String(255), index=True),
        sa.Column('entity_instance_id', sa.String(255), index=True),
        sa.Column('timestamp', sa.DateTime(timezone=False)),
        sa.Column('severity', sa.String(255), index=True),
        sa.Column('reason_text', sa.String(255)),
        sa.Column('alarm_type', sa.String(255), index=True),
        sa.Column('probable_cause', sa.String(255)),
        sa.Column('proposed_repair_action', sa.String(255)),
        sa.Column('service_affecting', sa.Boolean()),
        sa.Column('suppression', sa.Boolean()),
    )

    # Create customer log table
    op.create_table('i_customer_log',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(255), unique=True, index=True),
        sa.Column('log_id', sa.String(255), index=True),
        sa.Column('entity_type_id', sa.String(255), index=True),
        sa.Column('entity_instance_id', sa.String(255), index=True),
        sa.Column('timestamp', sa.DateTime(timezone=False)),
        sa.Column('severity', sa.String(255), index=True),
        sa.Column('reason_text', sa.String(255)),
        sa.Column('log_type', sa.String(255), index=True),
        sa.Column('probable_cause', sa.String(255)),
        sa.Column('service_affecting', sa.Boolean()),
    )

    # Create infra table
    op.create_table('i_infra',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('infra_subnet', sa.String(255)),
        sa.Column('infra_start', sa.String(255)),
        sa.Column('infra_end', sa.String(255)),
        sa.Column('forisystemid', sa.Integer(), sa.ForeignKey('i_system.id', ondelete='CASCADE')),
    )

    # Create interfaces table
    op.create_table('interfaces',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('forihostid', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('iftype', sa.String(255)),
        sa.Column('ifname', sa.String(255)),
        sa.Column('networktype', sa.String(255)),
        sa.Column('sriov_numvfs', sa.Integer()),
        sa.Column('ifcapabilities', sa.Text()),
        sa.Column('farend', sa.Text()),
        sa.UniqueConstraint('ifname', 'forihostid', name='u_interfacenameihost'),
    )

    # Create interfaces to interfaces junction table
    op.create_table('interfaces_to_interfaces',
        sa.Column('used_by_id', sa.Integer(), sa.ForeignKey('interfaces.id', ondelete='CASCADE'), primary_key=True),
        sa.Column('uses_id', sa.Integer(), sa.ForeignKey('interfaces.id', ondelete='CASCADE'), primary_key=True),
    )

    # Create ethernet interfaces table
    op.create_table('ethernet_interfaces',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), sa.ForeignKey('interfaces.id', ondelete='CASCADE'), primary_key=True, nullable=False),
        sa.Column('imac', sa.String(255)),
        sa.Column('imtu', sa.Integer()),
        sa.Column('providernetworks', sa.String(255)),
        sa.Column('providernetworksdict', sa.Text()),
    )

    # Create ae interfaces table
    op.create_table('ae_interfaces',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), sa.ForeignKey('interfaces.id', ondelete='CASCADE'), primary_key=True, nullable=False),
        sa.Column('aemode', sa.String(255)),
        sa.Column('aedict', sa.Text()),
        sa.Column('txhashpolicy', sa.String(255)),
        sa.Column('schedpolicy', sa.String(255)),
        sa.Column('imac', sa.String(255)),
        sa.Column('imtu', sa.Integer()),
        sa.Column('providernetworks', sa.String(255)),
        sa.Column('providernetworksdict', sa.Text()),
    )

    # Create vlan interfaces table
    op.create_table('vlan_interfaces',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), sa.ForeignKey('interfaces.id', ondelete='CASCADE'), primary_key=True, nullable=False),
        sa.Column('vlan_id', sa.String(255)),
        sa.Column('vlan_type', sa.String(255)),
        sa.Column('imac', sa.String(255)),
        sa.Column('imtu', sa.Integer()),
        sa.Column('providernetworks', sa.String(255)),
        sa.Column('providernetworksdict', sa.Text()),
    )

    # Create ports table
    op.create_table('ports',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('node_id', sa.Integer(), sa.ForeignKey('i_node.id', ondelete='SET NULL')),
        sa.Column('interface_id', sa.Integer(), sa.ForeignKey('interfaces.id', ondelete='SET NULL')),
        sa.Column('type', sa.String(255)),
        sa.Column('name', sa.String(255)),
        sa.Column('namedisplay', sa.String(255)),
        sa.Column('pciaddr', sa.String(255)),
        sa.Column('dev_id', sa.Integer()),
        sa.Column('sriov_totalvfs', sa.Integer()),
        sa.Column('sriov_numvfs', sa.Integer()),
        sa.Column('sriov_vfs_pci_address', sa.String(1020)),
        sa.Column('driver', sa.String(255)),
        sa.Column('pclass', sa.String(255)),
        sa.Column('pvendor', sa.String(255)),
        sa.Column('pdevice', sa.String(255)),
        sa.Column('psvendor', sa.String(255)),
        sa.Column('psdevice', sa.String(255)),
        sa.Column('dpdksupport', sa.Boolean(), default=False),
        sa.Column('numa_node', sa.Integer()),
        sa.Column('capabilities', sa.Text()),
        sa.UniqueConstraint('pciaddr', 'dev_id', 'host_id', name='u_pciaddr_dev_host_id'),
    )

    # Create ethernet ports table
    op.create_table('ethernet_ports',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), sa.ForeignKey('ports.id', ondelete='CASCADE'), primary_key=True, nullable=False),
        sa.Column('mac', sa.String(255)),
        sa.Column('mtu', sa.Integer()),
        sa.Column('speed', sa.Integer()),
        sa.Column('link_mode', sa.String(255)),
        sa.Column('duplex', sa.String(255)),
        sa.Column('autoneg', sa.String(255)),
        sa.Column('bootp', sa.String(255)),
        sa.Column('capabilities', sa.Text()),
    )

    # Create address pools table
    op.create_table('address_pools',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('name', sa.String(128), unique=True, nullable=False),
        sa.Column('family', sa.Integer(), nullable=False),
        sa.Column('network', sa.String(50), nullable=False),
        sa.Column('prefix', sa.Integer(), nullable=False),
        sa.Column('order', sa.String(32), nullable=False),
    )

    # Create address pool ranges table
    op.create_table('address_pool_ranges',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('start', sa.String(50), nullable=False),
        sa.Column('end', sa.String(50), nullable=False),
        sa.Column('address_pool_id', sa.Integer(), sa.ForeignKey('address_pools.id', ondelete='CASCADE'), nullable=False),
    )

    # Create addresses table
    op.create_table('addresses',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('name', sa.String(255)),
        sa.Column('family', sa.Integer(), nullable=False),
        sa.Column('address', sa.String(50), nullable=False),
        sa.Column('prefix', sa.Integer(), nullable=False),
        sa.Column('enable_dad', sa.Boolean(), default=True),
        sa.Column('interface_id', sa.Integer(), sa.ForeignKey('interfaces.id', ondelete='CASCADE'), nullable=True),
        sa.Column('address_pool_id', sa.Integer(), sa.ForeignKey('address_pools.id', ondelete='CASCADE'), nullable=True),
        sa.UniqueConstraint('family', 'address', 'interface_id', name='u_address@family@interface'),
    )

    # Create address modes table
    op.create_table('address_modes',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('family', sa.Integer(), nullable=False),
        sa.Column('mode', sa.String(32), nullable=False),
        sa.Column('interface_id', sa.Integer(), sa.ForeignKey('interfaces.id', ondelete='CASCADE'), nullable=False),
        sa.Column('address_pool_id', sa.Integer(), sa.ForeignKey('address_pools.id', ondelete='CASCADE'), nullable=True),
        sa.UniqueConstraint('family', 'interface_id', name='u_family@interface'),
    )

    # Create routes table
    op.create_table('routes',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('family', sa.Integer(), nullable=False),
        sa.Column('network', sa.String(50), nullable=False),
        sa.Column('prefix', sa.Integer(), nullable=False),
        sa.Column('gateway', sa.String(50), nullable=False),
        sa.Column('metric', sa.Integer(), default=1, nullable=False),
        sa.Column('interface_id', sa.Integer(), sa.ForeignKey('interfaces.id', ondelete='CASCADE'), nullable=False),
        sa.UniqueConstraint('family', 'network', 'prefix', 'gateway', 'interface_id', name='u_family@network@prefix@gateway@host'),
    )

    # Create networks table
    op.create_table('networks',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('type', sa.String(255), unique=True),
        sa.Column('mtu', sa.Integer(), nullable=False),
        sa.Column('link_capacity', sa.Integer()),
        sa.Column('dynamic', sa.Boolean(), nullable=False),
        sa.Column('vlan_id', sa.Integer()),
        sa.Column('address_pool_id', sa.Integer(), sa.ForeignKey('address_pools.id', ondelete='CASCADE'), nullable=False),
    )

    # Add columns to existing i_port table
    op.add_column('i_port', sa.Column('sriov_totalvfs', sa.Integer()))
    op.add_column('i_port', sa.Column('sriov_numvfs', sa.Integer()))
    op.add_column('i_port', sa.Column('sriov_vfs_pci_address', sa.String(1020)))
    op.add_column('i_port', sa.Column('driver', sa.String(255)))
    op.add_column('i_port', sa.Column('dpdksupport', sa.Boolean(), default=False))

    # Add columns to existing i_interface table
    op.add_column('i_interface', sa.Column('sriov_numvfs', sa.Integer()))
    op.add_column('i_interface', sa.Column('aedict', sa.Text()))

    # Create enums for physical volumes and volume groups
    pv_type_enum = postgresql.ENUM('disk', 'partition', 'reserve1', 'reserve2', name='physicalVolTypeEnum')

    pv_state_enum = postgresql.ENUM('unprovisioned', 'adding', 'provisioned', 'removing', 'reserve1', 'reserve2', name='pvStateEnum')

    vg_state_enum = postgresql.ENUM('unprovisioned', 'adding', 'provisioned', 'removing', 'reserve1', 'reserve2', name='vgStateEnum')

    # Create i_lvg table
    op.create_table('i_lvg',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('vg_state', vg_state_enum, default='unprovisioned'),
        sa.Column('lvm_vg_name', sa.String(64)),
        sa.Column('lvm_vg_uuid', sa.String(64)),
        sa.Column('lvm_vg_access', sa.String(64)),
        sa.Column('lvm_max_lv', sa.Integer()),
        sa.Column('lvm_cur_lv', sa.Integer()),
        sa.Column('lvm_max_pv', sa.Integer()),
        sa.Column('lvm_cur_pv', sa.Integer()),
        sa.Column('lvm_vg_size', sa.BigInteger()),
        sa.Column('lvm_vg_total_pe', sa.Integer()),
        sa.Column('lvm_vg_free_pe', sa.Integer()),
        sa.Column('capabilities', sa.Text()),
        sa.Column('forihostid', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
    )

    # Create i_pv table
    op.create_table('i_pv',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('pv_state', pv_state_enum, default='unprovisioned'),
        sa.Column('pv_type', pv_type_enum, default='disk'),
        sa.Column('idisk_uuid', sa.String()),
        sa.Column('idisk_device_node', sa.String(64)),
        sa.Column('lvm_pv_name', sa.String(64)),
        sa.Column('lvm_vg_name', sa.String(64)),
        sa.Column('lvm_pv_uuid', sa.String(64)),
        sa.Column('lvm_pv_size', sa.BigInteger()),
        sa.Column('lvm_pe_total', sa.Integer()),
        sa.Column('lvm_pe_alloced', sa.Integer()),
        sa.Column('capabilities', sa.Text()),
        sa.Column('forihostid', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('forilvgid', sa.Integer(), sa.ForeignKey('i_lvg.id', ondelete='CASCADE')),
    )

    # Add column to existing i_idisk table
    op.add_column('i_idisk', sa.Column('foripvid', sa.Integer(), sa.ForeignKey('i_pv.id')))

    # Create sensor groups table
    op.create_table('i_sensorgroups',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('sensorgroupname', sa.String(255)),
        sa.Column('path', sa.String(255)),
        sa.Column('datatype', sa.String(255)),
        sa.Column('sensortype', sa.String(255)),
        sa.Column('description', sa.String(255)),
        sa.Column('state', sa.String(255)),
        sa.Column('possible_states', sa.String(255)),
        sa.Column('audit_interval_group', sa.Integer()),
        sa.Column('record_ttl', sa.Integer()),
        sa.Column('algorithm', sa.String(255)),
        sa.Column('actions_critical_choices', sa.String(255)),
        sa.Column('actions_major_choices', sa.String(255)),
        sa.Column('actions_minor_choices', sa.String(255)),
        sa.Column('actions_minor_group', sa.String(255)),
        sa.Column('actions_major_group', sa.String(255)),
        sa.Column('actions_critical_group', sa.String(255)),
        sa.Column('suppress', sa.Boolean()),
        sa.Column('capabilities', sa.Text()),
        sa.UniqueConstraint('sensorgroupname', 'path', 'host_id', name='u_sensorgroupname_path_hostid'),
    )

    # Create discrete sensor groups table
    op.create_table('i_sensorgroups_discrete',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), sa.ForeignKey('i_sensorgroups.id', ondelete='CASCADE'), primary_key=True, nullable=False),
    )

    # Create analog sensor groups table
    op.create_table('i_sensorgroups_analog',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), sa.ForeignKey('i_sensorgroups.id', ondelete='CASCADE'), primary_key=True, nullable=False),
        sa.Column('unit_base_group', sa.String(255)),
        sa.Column('unit_modifier_group', sa.String(255)),
        sa.Column('unit_rate_group', sa.String(255)),
        sa.Column('t_minor_lower_group', sa.String(255)),
        sa.Column('t_minor_upper_group', sa.String(255)),
        sa.Column('t_major_lower_group', sa.String(255)),
        sa.Column('t_major_upper_group', sa.String(255)),
        sa.Column('t_critical_lower_group', sa.String(255)),
        sa.Column('t_critical_upper_group', sa.String(255)),
    )

    # Create sensors table
    op.create_table('i_sensors',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('sensorgroup_id', sa.Integer(), sa.ForeignKey('i_sensorgroups.id', ondelete='SET NULL')),
        sa.Column('sensorname', sa.String(255)),
        sa.Column('path', sa.String(255)),
        sa.Column('datatype', sa.String(255)),
        sa.Column('sensortype', sa.String(255)),
        sa.Column('status', sa.String(255)),
        sa.Column('state', sa.String(255)),
        sa.Column('state_requested', sa.String(255)),
        sa.Column('sensor_action_requested', sa.String(255)),
        sa.Column('audit_interval', sa.Integer()),
        sa.Column('algorithm', sa.String(255)),
        sa.Column('actions_minor', sa.String(255)),
        sa.Column('actions_major', sa.String(255)),
        sa.Column('actions_critical', sa.String(255)),
        sa.Column('suppress', sa.Boolean()),
        sa.Column('capabilities', sa.Text()),
        sa.UniqueConstraint('sensorname', 'path', 'host_id', name='u_sensorname_path_host_id'),
    )

    # Create discrete sensors table
    op.create_table('i_sensors_discrete',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), sa.ForeignKey('i_sensors.id', ondelete='CASCADE'), primary_key=True, nullable=False),
    )

    # Create analog sensors table
    op.create_table('i_sensors_analog',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), sa.ForeignKey('i_sensors.id', ondelete='CASCADE'), primary_key=True, nullable=False),
        sa.Column('unit_base', sa.String(255)),
        sa.Column('unit_modifier', sa.String(255)),
        sa.Column('unit_rate', sa.String(255)),
        sa.Column('t_minor_lower', sa.String(255)),
        sa.Column('t_minor_upper', sa.String(255)),
        sa.Column('t_major_lower', sa.String(255)),
        sa.Column('t_major_upper', sa.String(255)),
        sa.Column('t_critical_lower', sa.String(255)),
        sa.Column('t_critical_upper', sa.String(255)),
    )

    # Create pci devices table
    op.create_table('pci_devices',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(255), unique=True, index=True),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('name', sa.String(255)),
        sa.Column('pciaddr', sa.String(255)),
        sa.Column('pclass_id', sa.String(6)),
        sa.Column('pvendor_id', sa.String(4)),
        sa.Column('pdevice_id', sa.String(4)),
        sa.Column('pclass', sa.String(255)),
        sa.Column('pvendor', sa.String(255)),
        sa.Column('pdevice', sa.String(255)),
        sa.Column('psvendor', sa.String(255)),
        sa.Column('psdevice', sa.String(255)),
        sa.Column('numa_node', sa.Integer()),
        sa.Column('driver', sa.String(255)),
        sa.Column('sriov_totalvfs', sa.Integer()),
        sa.Column('sriov_numvfs', sa.Integer()),
        sa.Column('sriov_vfs_pci_address', sa.String(1020)),
        sa.Column('enabled', sa.Boolean()),
        sa.Column('extra_info', sa.Text()),
    )

    # Create loads table
    op.create_table('loads',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36)),
        sa.Column('state', sa.String(255)),
        sa.Column('software_version', sa.String(255)),
        sa.Column('compatible_version', sa.String(255)),
        sa.Column('required_patches', sa.String(2047)),
        sa.UniqueConstraint('software_version'),
    )

    # Create software upgrade table
    op.create_table('software_upgrade',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('state', sa.String(128), nullable=False),
        sa.Column('from_load', sa.Integer(), sa.ForeignKey('loads.id', ondelete='CASCADE'), nullable=False),
        sa.Column('to_load', sa.Integer(), sa.ForeignKey('loads.id', ondelete='CASCADE'), nullable=False),
    )

    # Create host upgrade table
    op.create_table('host_upgrade',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('forihostid', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('software_load', sa.Integer(), sa.ForeignKey('loads.id'), nullable=False),
        sa.Column('target_load', sa.Integer(), sa.ForeignKey('loads.id'), nullable=False),
    )

    # Create drbd config table
    op.create_table('drbdconfig',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('link_util', sa.Integer()),
        sa.Column('num_parallel', sa.Integer()),
        sa.Column('rtt_ms', sa.Float()),
        sa.Column('forisystemid', sa.Integer(), sa.ForeignKey('i_system.id', ondelete='CASCADE')),
    )

    # Add columns to existing i_host table
    op.add_column('i_host', sa.Column('ihost_action', sa.String(255)))
    op.add_column('i_host', sa.Column('vim_progress_status', sa.String(255)))
    op.add_column('i_host', sa.Column('subfunctions', sa.String(255)))
    op.add_column('i_host', sa.Column('subfunction_oper', sa.String(255), default='disabled'))
    op.add_column('i_host', sa.Column('subfunction_avail', sa.String(255), default='not-installed'))
    op.add_column('i_host', sa.Column('boot_device', sa.String(255)))
    op.add_column('i_host', sa.Column('rootfs_device', sa.String(255)))
    op.add_column('i_host', sa.Column('install_output', sa.String(255)))
    op.add_column('i_host', sa.Column('console', sa.String(255)))
    op.add_column('i_host', sa.Column('vsc_controllers', sa.String(255)))
    op.add_column('i_host', sa.Column('ttys_dcd', sa.Boolean()))

    # Modify i_memory table - drop old hugepage columns and add new ones
    op.drop_column('i_imemory', 'vm_hugepages_size_mib')
    op.drop_column('i_imemory', 'vm_hugepages_nr')
    op.drop_column('i_imemory', 'vm_hugepages_avail')

    # Add new hugepage columns
    op.add_column('i_imemory', sa.Column('vm_hugepages_nr_2M', sa.Integer()))
    op.add_column('i_imemory', sa.Column('vm_hugepages_nr_1G', sa.Integer()))
    op.add_column('i_imemory', sa.Column('vm_hugepages_use_1G', sa.Boolean()))
    op.add_column('i_imemory', sa.Column('vm_hugepages_possible_2M', sa.Integer()))
    op.add_column('i_imemory', sa.Column('vm_hugepages_possible_1G', sa.Integer()))
    op.add_column('i_imemory', sa.Column('vm_hugepages_nr_2M_pending', sa.Integer()))
    op.add_column('i_imemory', sa.Column('vm_hugepages_nr_1G_pending', sa.Integer()))
    op.add_column('i_imemory', sa.Column('vm_hugepages_avail_2M', sa.Integer()))
    op.add_column('i_imemory', sa.Column('vm_hugepages_avail_1G', sa.Integer()))
    op.add_column('i_imemory', sa.Column('vm_hugepages_nr_4K', sa.Integer()))
    op.add_column('i_imemory', sa.Column('node_memtotal_mib', sa.Integer()))

    # Add columns to existing i_extoam table
    op.add_column('i_extoam', sa.Column('oam_start_ip', sa.String(255)))
    op.add_column('i_extoam', sa.Column('oam_end_ip', sa.String(255)))

    # Add columns to existing i_storconfig table
    op.add_column('i_storconfig', sa.Column('glance_backend', sa.String(255)))
    op.add_column('i_storconfig', sa.Column('glance_gib', sa.Integer(), default=0))
    op.add_column('i_storconfig', sa.Column('img_conversions_gib', sa.String(255)))

    # Drop tables that are no longer needed
    op.drop_table('i_extoam')
    op.drop_table('i_infra')

    # Create service enum and service parameter table
    service_enum = postgresql.ENUM('identity', name='serviceEnum')

    op.create_table('service_parameter',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('service', service_enum),
        sa.Column('section', sa.String(255)),
        sa.Column('name', sa.String(255)),
        sa.Column('value', sa.String(255)),
        sa.UniqueConstraint('service', 'section', 'name', name='u_servicesectionname'),
    )


def downgrade():
    raise NotImplementedError('SysInv database downgrade is unsupported.')