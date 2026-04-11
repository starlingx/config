#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""consolidated r2509

Revision ID: f9e2c0db7040
Revises: 94ac364b558e
Create Date: 2025-10-09 00:00:59.888228

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

from datetime import datetime
from eventlet.green import subprocess
from oslo_log import log
from sqlalchemy.dialects import postgresql
from sqlalchemy import text
from sysinv.common import address_pool as caddress_pool
from sysinv.common import constants
from sysinv.common import kubernetes
from sysinv.common import utils as cutils
from sysinv.db.sqlalchemy.models import KubeAppBundle
from sysinv.db.sqlalchemy.models import UUID_LENGTH
from tsconfig.tsconfig import system_mode
import json
import tsconfig.tsconfig as tsconfig
import uuid


# revision identifiers, used by Alembic.
revision: str = 'f9e2c0db7040'
down_revision: Union[str, None] = '94ac364b558e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


LOG = log.getLogger(__name__)

def _populate_address_fields(connection):
    prefix_to_field_name = {
        constants.CONTROLLER_HOSTNAME: caddress_pool.FLOATING_ADDRESS_ID,
        constants.CONTROLLER_0_HOSTNAME: caddress_pool.CONTROLLER0_ADDRESS_ID,
        constants.CONTROLLER_1_HOSTNAME: caddress_pool.CONTROLLER1_ADDRESS_ID,
        constants.CONTROLLER_GATEWAY: caddress_pool.GATEWAY_ADDRESS_ID,
    }

    networks = connection.execute(text("SELECT * FROM networks")).fetchall()
    if len(networks) > 0:
        for net in networks:
            fields = {}
            for prefix, field_name in prefix_to_field_name.items():
                address_name = cutils.format_address_name(prefix, net.type)
                addr = connection.execute(text("SELECT * FROM addresses WHERE name = :name"),
                                        {'name': address_name}).fetchall()
                if len(addr) > 0:
                    fields[field_name] = addr[0].id
            if fields:
                update_sql = "UPDATE address_pools SET "
                update_parts = []
                params = {'pool_id': net.address_pool_id}
                for field_name, value in fields.items():
                    update_parts.append(f"{field_name} = :{field_name}")
                    params[field_name] = value
                update_sql += ", ".join(update_parts) + " WHERE id = :pool_id"
                connection.execute(text(update_sql), params)

def _update_addresses(connection):
    interfaces = connection.execute(text(
        "SELECT * FROM interfaces WHERE networktype = :oam OR networktype = :pxeboot"
    ), {'oam': constants.NETWORK_TYPE_OAM, 'pxeboot': constants.NETWORK_TYPE_PXEBOOT}).fetchall()

    simplex = (system_mode == constants.SYSTEM_MODE_SIMPLEX)

    for interface in interfaces:
        host = connection.execute(text("SELECT * FROM i_host WHERE id = :id"),
                                {'id': interface.forihostid}).fetchall()

        if not simplex:
            hostname = host[0].hostname
        else:
            hostname = constants.CONTROLLER

        address_name = cutils.format_address_name(hostname, interface.networktype)
        address = connection.execute(text("SELECT * FROM addresses WHERE name = :name"),
                                   {'name': address_name}).fetchall()
        if len(address) > 0:
            connection.execute(text("UPDATE addresses SET interface_id = :interface_id WHERE id = :id"),
                             {'interface_id': interface.id, 'id': address[0].id})

def _populate_tboot(connection):
    host_list = connection.execute(text("SELECT * FROM i_host WHERE uuid IS NOT NULL")).fetchall()
    if len(host_list) > 0:
        # tboot option must be selected at install time, otherwise it risks
        # disabling existing systems with secure boot.  Use empty string for
        # migrated hosts
        tboot_value = ''
        for host in host_list:
            connection.execute(text("UPDATE i_host SET tboot = :tboot WHERE uuid = :uuid"),
                             {'tboot': tboot_value, 'uuid': host.uuid})

def _populate_security_feature(connection):
    sys = connection.execute(text("SELECT * FROM i_system WHERE uuid IS NOT NULL")).fetchall()
    if len(sys) > 0:
        if sys[0].security_feature is None:
            # TODO - once we support R4/R5 kernel options, this should populate
            # data from R4/R5 version, rather than use default
            connection.execute(text("UPDATE i_system SET security_feature = :security_feature WHERE uuid = :uuid"),
                             {'security_feature': constants.SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_DEFAULT_OPTS,
                              'uuid': sys[0].uuid})

def _populate_ptp_table(connection):
    """This function inserts all the initial data about journals,
       into the ptp table.
    """
    sys = connection.execute(text("SELECT * FROM i_system WHERE uuid IS NOT NULL")).fetchall()
    if len(sys) > 0:
        ptp_uuid = str(uuid.uuid4())
        connection.execute(text(
            "INSERT INTO ptp (created_at, updated_at, deleted_at, uuid, enabled, mode, transport, mechanism, system_id) "
            "VALUES (:created_at, :updated_at, :deleted_at, :uuid, :enabled, :mode, :transport, :mechanism, :system_id)"
        ), {
            'created_at': datetime.now(),
            'updated_at': None,
            'deleted_at': None,
            'uuid': ptp_uuid,
            'enabled': False,
            'mode': 'hardware',
            'transport': 'l2',
            'mechanism': 'e2e',
            'system_id': sys[0].id
        })


def upgrade() -> None:
    # 061_ipm_migration.py
    """
    This database upgrade migrates the ipm retention_secs field
    to ceilometer, panko and aodh time to live service parameters
    and then deletes the existing obsoleted ipm table.
    """
    connection = op.get_bind()

    # Check if i_pm table exists
    inspector = sa.inspect(connection)
    if not inspector.has_table("i_pm"):
        return

    # Read retention_secs value from i_pm table
    try:
        result = connection.execute(text("SELECT retention_secs FROM i_pm WHERE retention_secs IS NOT NULL LIMIT 1"))
        row = result.fetchone()

        # Drop the i_pm table
        op.drop_table('i_pm')

        if row:
            ret_secs = row.retention_secs
            if ret_secs != constants.PM_TTL_DEFAULT:

                LOG.info("migrating i_pm retention_secs value:%s" % ret_secs)

                # Check if service_parameter table exists
                if inspector.has_table("service_parameter"):
                    # Insert service parameters for panko, ceilometer, and aodh
                    service_params = [
                        ('panko', 'database', 'event_time_to_live', ret_secs),
                        ('ceilometer', 'database', 'metering_time_to_live', ret_secs),
                        ('aodh', 'database', 'alarm_history_time_to_live', ret_secs)
                    ]

                    for service, section, name, value in service_params:
                        connection.execute(
                            text("INSERT INTO service_parameter (created_at, uuid, service, section, name, value) "
                                "VALUES (:created_at, :uuid, :service, :section, :name, :value)"),
                            {
                                'created_at': datetime.now(),
                                'uuid': str(uuid.uuid4()),
                                'service': service,
                                'section': section,
                                'name': name,
                                'value': value
                            }
                        )

    except Exception as e:
        LOG.warning("Error during i_pm migration: %s" % str(e))
        # Still try to drop the table if it exists
        try:
            op.drop_table('i_pm')
        except:
            pass

    # 062_service_parameter_extensions.py
    # Add personality and resource columns to service_parameter table
    op.add_column('service_parameter',
                  sa.Column('personality', sa.String(255)))
    op.add_column('service_parameter',
                  sa.Column('resource', sa.String(255)))

    # Remove the existing unique constraint
    op.drop_constraint('u_servicesectionname', 'service_parameter', type_='unique')

    # Add new unique constraint with personality and resource
    op.create_unique_constraint('u_service_section_name_personality_resource',
                                'service_parameter',
                                ['service', 'section', 'name', 'personality', 'resource'])

    # 063_address_pool.py
    # Create new columns
    op.add_column('address_pools',
                  sa.Column('controller0_address_id', sa.Integer()))
    op.add_column('address_pools',
                  sa.Column('controller1_address_id', sa.Integer()))
    op.add_column('address_pools',
                  sa.Column('floating_address_id', sa.Integer()))
    op.add_column('address_pools',
                  sa.Column('gateway_address_id', sa.Integer()))

    # Populate the new columns
    _populate_address_fields(connection)

    # Update controller oam and pxeboot addresses with their interface id
    _update_addresses(connection)

    # 064_certificate.py
    """Perform sysinv database upgrade for certificate"""
    op.create_table('certificate',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('certtype', sa.String(64)),
        sa.Column('issuer', sa.String(255)),
        sa.Column('signature', sa.String(255)),
        sa.Column('start_date', sa.DateTime()),
        sa.Column('expiry_date', sa.DateTime()),
        sa.Column('capabilities', sa.Text())
    )

    # 065_storage_tiers.py
    """This database upgrade creates a new storage_tiers table"""

    # Add name column to storage_backend table
    op.add_column('storage_backend',
                  sa.Column('name', sa.String(255)))

    # Create storage_tiers table
    op.create_table('storage_tiers',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True, index=True),
        sa.Column('name', sa.String(255), unique=True, index=True),
        sa.Column('type', sa.String(64)),
        sa.Column('status', sa.String(64)),
        sa.Column('capabilities', sa.Text()),
        sa.Column('forbackendid', sa.Integer(), sa.ForeignKey('storage_backend.id')),
        sa.Column('forclusterid', sa.Integer(), sa.ForeignKey('clusters.id'))
    )

    # Add tier_id column to storage_ceph table
    op.add_column('storage_ceph',
                  sa.Column('tier_id', sa.Integer(), sa.ForeignKey('storage_tiers.id')))

    # Add fortierid column to i_istor table
    op.add_column('i_istor',
                  sa.Column('fortierid', sa.Integer(), sa.ForeignKey('storage_tiers.id')))

    # 066_tpmdevice_add_tpm_data.py
    # Add tpm_data columns to tpmdevice table
    op.add_column('tpmdevice',
                  sa.Column('binary', sa.LargeBinary()))
    op.add_column('tpmdevice',
                  sa.Column('tpm_data', sa.Text()))
    op.add_column('tpmdevice',
                  sa.Column('capabilities', sa.Text()))

    # 067_tboot.py
    op.add_column('i_host',
                  sa.Column('tboot', sa.String(64)))

    _populate_tboot(connection)

    # 068_memory_column_rename.py
    op.alter_column('i_imemory', 'avs_hugepages_size_mib',
                    new_column_name='vswitch_hugepages_size_mib')
    op.alter_column('i_imemory', 'avs_hugepages_reqd',
                    new_column_name='vswitch_hugepages_reqd')
    op.alter_column('i_imemory', 'avs_hugepages_nr',
                    new_column_name='vswitch_hugepages_nr')
    op.alter_column('i_imemory', 'avs_hugepages_avail',
                    new_column_name='vswitch_hugepages_avail')

    # 069_security_feature.py
    op.add_column('i_system',
                  sa.Column('security_feature', sa.String(255)))

    _populate_security_feature(connection)

    # 071_storage_ceph_external.py
    """This database upgrade creates a new storage_ceph_external table"""
    op.create_table('storage_ceph_external',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(),
                  sa.ForeignKey('storage_backend.id', ondelete='CASCADE'),
                  primary_key=True, unique=True, nullable=False),
        sa.Column('ceph_conf', sa.String(255), unique=True, index=True)
    )

    # 072_remove_ceilometer_service_parameter.py
    """
    This database upgrade deletes the ceilometer metering_time_to_live
    service parameter.
    """
    LOG.info("Deleting ceilometer metering_time_to_live service parameter")

    inspector = sa.inspect(connection)

    if inspector.has_table("service_parameter"):
        connection.execute(text("DELETE FROM service_parameter WHERE service = 'ceilometer'"))

    # 073_kube_application.py
    """
    This database upgrade creates a new table for storing kubernetes
    application info.
    """
    op.create_table('kube_app',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(255), unique=True, nullable=False),
        sa.Column('app_version', sa.String(255), nullable=False),
        sa.Column('manifest_name', sa.String(255), nullable=False),
        sa.Column('manifest_file', sa.String(255), nullable=True),
        sa.Column('status', sa.String(255), nullable=False),
        sa.Column('progress', sa.String(255), nullable=True),
        sa.Column('active', sa.Boolean(), nullable=False, default=False)
    )

    # 074_ntp_enabled.py
    op.add_column('i_ntp',
                  sa.Column('enabled', sa.Boolean(), default=True))

    # 075_ptp.py
    # Create ptp table
    op.create_table('ptp',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('enabled', sa.Boolean(), default=False),
        sa.Column('mode', sa.String(16), default='hardware'),
        sa.Column('transport', sa.String(4), default='l2'),
        sa.Column('mechanism', sa.String(4), default='e2e'),
        sa.Column('system_id', sa.Integer(),
                  sa.ForeignKey('i_system.id', ondelete='CASCADE'),
                  nullable=True)
    )

    # Populate the new ptp table with the initial data
    _populate_ptp_table(connection)

    # 076_host_label.py
    """Perform sysinv database upgrade for host label"""
    op.create_table('label',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('host_id', sa.Integer(),
                  sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('label_key', sa.String(384)),
        sa.Column('label_value', sa.String(128)),
        sa.UniqueConstraint('host_id', 'label_key', name='u_host_id@label_key')
    )

    # 077_interface_network.py
    # Add name column to networks table
    op.add_column('networks',
                  sa.Column('name', sa.String(255)))

    # Create interface_networks table
    op.create_table('interface_networks',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('interface_id', sa.Integer(),
                  sa.ForeignKey('interfaces.id', ondelete='CASCADE')),
        sa.Column('network_id', sa.Integer(),
                  sa.ForeignKey('networks.id', ondelete='CASCADE')),
        sa.UniqueConstraint('interface_id', 'network_id', name='u_interface_id@network_id')
    )

    # 078_interface_class.py
    """Perform sysinv database upgrade for network interface"""
    op.add_column('interfaces',
                  sa.Column('ifclass', sa.String(255)))

    # 079_network_column_remove.py
    op.drop_column('networks', 'mtu')
    op.drop_column('networks', 'link_capacity')
    op.drop_column('networks', 'vlan_id')

    # 080_kube_ceph_pool.py
    op.add_column('storage_ceph',
                  sa.Column('kube_pool_gib', sa.Integer()))

    # 081_helm_overrides.py
    """
    This database upgrade creates a new table for storing helm chart
    user-specified override values.
    """
    op.create_table('helm_overrides',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('namespace', sa.String(255), nullable=False),
        sa.Column('user_overrides', sa.Text(), nullable=True),
        sa.Column('app_id', sa.Integer(),
                  sa.ForeignKey('kube_app.id', ondelete='CASCADE')),
        sa.UniqueConstraint('name', 'namespace', 'app_id', name='u_app_name_namespace')
    )

    # 082_helm_system_overrides.py
    """
    This database upgrade creates a new column for storing passwords
    on the helm chart override table.
    """
    op.add_column('helm_overrides',
                  sa.Column('system_overrides', sa.Text(), nullable=True))

    # 083_ceph_mon_tasks.py
    op.add_column('ceph_mon',
                  sa.Column('state', sa.String(255)))
    op.add_column('ceph_mon',
                  sa.Column('task', sa.String(255)))

    # 084_data_networks.py
    # Create datanetworks table
    op.create_table('datanetworks',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('name', sa.String(255), unique=True),
        sa.Column('network_type', sa.String(255)),
        sa.Column('description', sa.String(255)),
        sa.Column('mtu', sa.Integer(), nullable=False)
    )

    # Create datanetworks_flat table
    op.create_table('datanetworks_flat',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(),
                  sa.ForeignKey('datanetworks.id', ondelete='CASCADE'),
                  primary_key=True, nullable=False)
    )

    # Create datanetworks_vlan table
    op.create_table('datanetworks_vlan',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(),
                  sa.ForeignKey('datanetworks.id', ondelete='CASCADE'),
                  primary_key=True, nullable=False)
    )

    # Create datanetworks_vxlan table
    op.create_table('datanetworks_vxlan',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(),
                  sa.ForeignKey('datanetworks.id', ondelete='CASCADE'),
                  primary_key=True, nullable=False),
        sa.Column('multicast_group', sa.String(64), nullable=True),
        sa.Column('port_num', sa.Integer(), nullable=False),
        sa.Column('ttl', sa.Integer(), nullable=False),
        sa.Column('mode', sa.String(32), nullable=False,
                  default=constants.DATANETWORK_MODE_DYNAMIC)
    )

    # Create interface_datanetworks table
    op.create_table('interface_datanetworks',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('interface_id', sa.Integer(),
                  sa.ForeignKey('interfaces.id', ondelete='CASCADE')),
        sa.Column('datanetwork_id', sa.Integer(),
                  sa.ForeignKey('datanetworks.id', ondelete='CASCADE')),
        sa.UniqueConstraint('interface_id', 'datanetwork_id',
                            name='u_interface_id@datanetwork_id')
    )

    # Drop providernetworks columns from interface tables
    op.drop_column('ethernet_interfaces', 'providernetworks')
    op.drop_column('ethernet_interfaces', 'providernetworksdict')
    op.drop_column('ae_interfaces', 'providernetworks')
    op.drop_column('ae_interfaces', 'providernetworksdict')
    op.drop_column('vlan_interfaces', 'providernetworks')
    op.drop_column('vlan_interfaces', 'providernetworksdict')
    op.drop_column('virtual_interfaces', 'providernetworks')
    op.drop_column('virtual_interfaces', 'providernetworksdict')

    # 085_sriov_vf_driver.py
    op.add_column('interfaces',
                  sa.Column('sriov_vf_driver', sa.String(255)))
    op.add_column('ports',
                  sa.Column('sriov_vf_driver', sa.String(255)))

    # 086_kube_app_application_unique_constraint.py
    """
    This database upgrade drops the old unique constraint and creates
    new unique constraint for the kube_app table.
    """
    # Drop the old unique constraint on 'name' only
    op.drop_constraint(
        constraint_name='kube_app_name_key',  # replace with your actual constraint name
        table_name='kube_app',
        type_='unique'
    )

    # Create new unique constraint on 'name' and 'app_version'
    op.create_unique_constraint(
        constraint_name='u_app_name_version',
        table_name='kube_app',
        columns=['name', 'app_version']
    )

    # 087_kube_application_releases.py
    """
    This database upgrade creates a new table for storing kubernetes
    application releases info.
    """
    op.create_table('kube_app_releases',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('release', sa.String(255), nullable=True),
        sa.Column('namespace', sa.String(255), nullable=True),
        sa.Column('version', sa.Integer()),
        sa.Column('app_id', sa.Integer(),
                  sa.ForeignKey('kube_app.id', ondelete='CASCADE')),
        sa.UniqueConstraint('release', 'namespace', 'app_id',
                            name='u_app_release_namespace')
    )

    # 088_networktype_remove.py
    op.drop_column('interfaces', 'networktype')

    # 089_host_fs.py
    """
    This database upgrade creates a new host_fs table for storing
    filesystem info for a host.
    """
    op.create_table('host_fs',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('name', sa.String(255)),
        sa.Column('size', sa.Integer()),
        sa.Column('logical_volume', sa.String(64)),
        sa.Column('forihostid', sa.Integer(),
                  sa.ForeignKey('i_host.id', ondelete='CASCADE'))
    )

    # 090_inv_state.py
    """
    This database upgrade creates a new host inv_state attribute for
    storing the inventory state for a host.
    """
    op.add_column('i_host',
                  sa.Column('inv_state', sa.String(255)))

    # 091_kube_app_add_recovery_attempts.py
    # Add recovery_attempts column to kube_app table
    op.add_column('kube_app',
                  sa.Column('recovery_attempts', sa.Integer(), nullable=False, default=0))

    # 092_clock_synchronization.py
    """
    This database upgrade creates a new host clock_synchronization attribute
    for storing the clock_synchronization type (ntp/ptp) for a host.
    """
    # Add clock_synchronization column to i_host table
    op.add_column('i_host',
                  sa.Column('clock_synchronization', sa.String(32),
                           default=constants.NTP))

    # Remove enabled column from i_ntp table
    op.drop_column('i_ntp', 'enabled')

    # Remove enabled column from ptp table
    op.drop_column('ptp', 'enabled')

    # 093_kube_upgrade_tables.py
    """
    This database upgrade creates a new kube_upgrade and kube_host_upgrade
    tables for storing kubernetes upgrade info.
    """
    # Create kube_upgrade table
    op.create_table('kube_upgrade',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('from_version', sa.String(255)),
        sa.Column('to_version', sa.String(255)),
        sa.Column('state', sa.String(128)),
        sa.Column('reserved_1', sa.String(255)),
        sa.Column('reserved_2', sa.String(255)),
        sa.Column('reserved_3', sa.String(255)),
        sa.Column('reserved_4', sa.String(255))
    )

    # Create kube_host_upgrade table
    op.create_table('kube_host_upgrade',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('target_version', sa.String(255)),
        sa.Column('status', sa.String(128)),
        sa.Column('reserved_1', sa.String(255)),
        sa.Column('reserved_2', sa.String(255)),
        sa.Column('reserved_3', sa.String(255)),
        sa.Column('reserved_4', sa.String(255)),
        sa.Column('host_id', sa.Integer(),
                  sa.ForeignKey('i_host.id', ondelete='CASCADE'))
    )

    # 094_sriov_vf_device.py
    op.add_column('ports',
                  sa.Column('sriov_vf_pdevice_id', sa.String(4)))

    # 095_sriov_vf_interfaces.py
    op.create_table('vf_interfaces',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(),
                  sa.ForeignKey('interfaces.id', ondelete='CASCADE'),
                  primary_key=True, nullable=False),
        sa.Column('imac', sa.String(255)),
        sa.Column('imtu', sa.Integer()),
        sa.Column('sriov_numvfs', sa.Integer()),
        sa.Column('sriov_vf_driver', sa.String(255))
    )

    # 096_ptp_interface.py
    op.add_column('interfaces',
                  sa.Column('ptp_role', sa.String(255), default='none'))

    # 097_memory_column_add.py
    op.add_column('i_imemory',
                  sa.Column('vm_pending_as_percentage', sa.Boolean(), default=False))
    op.add_column('i_imemory',
                  sa.Column('vm_hugepages_2M_percentage', sa.Integer(), default=None))
    op.add_column('i_imemory',
                  sa.Column('vm_hugepages_1G_percentage', sa.Integer(), default=None))

    # 098_service_parameter_extensions.py
    # Increase the size of the value column
    op.alter_column('service_parameter', 'value',
                    type_=sa.String(4096))

    # 104_fpga_devices.py
    # Create fpga_devices table
    op.create_table('fpga_devices',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('host_id', sa.Integer(),
                  sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('pci_id', sa.Integer(),
                  sa.ForeignKey('pci_devices.id', ondelete='CASCADE')),
        sa.Column('pciaddr', sa.String(32)),
        sa.Column('bmc_build_version', sa.String(32)),
        sa.Column('bmc_fw_version', sa.String(32)),
        sa.Column('root_key', sa.String(128)),
        sa.Column('revoked_key_ids', sa.String(512)),
        sa.Column('boot_page', sa.String(16)),
        sa.Column('bitstream_id', sa.String(32)),
        sa.UniqueConstraint('pciaddr', 'host_id', name='u_pciaddrhost')
    )

    # Create fpga_ports table
    op.create_table('fpga_ports',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('port_id', sa.Integer(),
                  sa.ForeignKey('ports.id', ondelete='CASCADE')),
        sa.Column('fpga_id', sa.Integer(),
                  sa.ForeignKey('fpga_devices.id', ondelete='CASCADE')),
        sa.UniqueConstraint('port_id', 'fpga_id', name='u_port_id@fpga_id')
    )

    # Add new fields to pci_devices table
    op.add_column('pci_devices',
                  sa.Column('status', sa.String(128)))
    op.add_column('pci_devices',
                  sa.Column('needs_firmware_update', sa.Boolean(), default=False))

    # 105_device_images.py
    """
    This database upgrade creates a device_images, device_labels and
    device_image_state tables.
    """

    # Create device_images table
    op.create_table('device_images',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('bitstream_type', sa.String(255)),
        sa.Column('pci_vendor', sa.String(4)),
        sa.Column('pci_device', sa.String(4)),
        sa.Column('name', sa.String(255)),
        sa.Column('description', sa.String(255)),
        sa.Column('image_version', sa.String(255)),
        sa.Column('applied', sa.Boolean(), nullable=False, default=False),
        sa.Column('capabilities', sa.Text())
    )

    # Create device_images_rootkey table
    op.create_table('device_images_rootkey',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(),
                  sa.ForeignKey('device_images.id', ondelete='CASCADE'),
                  primary_key=True, nullable=False),
        sa.Column('key_signature', sa.String(255), nullable=False)
    )

    # Create device_images_functional table
    op.create_table('device_images_functional',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(),
                  sa.ForeignKey('device_images.id', ondelete='CASCADE'),
                  primary_key=True, nullable=False),
        sa.Column('bitstream_id', sa.String(255), nullable=False)
    )

    # Create device_images_keyrevocation table
    op.create_table('device_images_keyrevocation',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(),
                  sa.ForeignKey('device_images.id', ondelete='CASCADE'),
                  primary_key=True, nullable=False),
        sa.Column('revoke_key_id', sa.Integer(), nullable=False)
    )

    # Create device_labels table
    op.create_table('device_labels',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('host_id', sa.Integer(),
                  sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('pcidevice_id', sa.Integer(),
                  sa.ForeignKey('pci_devices.id', ondelete='CASCADE')),
        sa.Column('fpgadevice_id', sa.Integer(),
                  sa.ForeignKey('fpga_devices.id', ondelete='CASCADE')),
        sa.Column('label_key', sa.String(384)),
        sa.Column('label_value', sa.String(128)),
        sa.Column('capabilities', sa.Text()),
        sa.UniqueConstraint('pcidevice_id', 'label_key',
                            name='u_pcidevice_id@label_key')
    )

    # Create device_image_labels table
    op.create_table('device_image_labels',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('image_id', sa.Integer(),
                  sa.ForeignKey('device_images.id', ondelete='CASCADE')),
        sa.Column('label_id', sa.Integer(),
                  sa.ForeignKey('device_labels.id', ondelete='CASCADE')),
        sa.Column('status', sa.String(128)),
        sa.Column('capabilities', sa.Text()),
        sa.UniqueConstraint('image_id', 'label_id', name='u_image_id@label_id')
    )

    # Create device_image_state table
    op.create_table('device_image_state',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('host_id', sa.Integer(),
                  sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('pcidevice_id', sa.Integer(),
                  sa.ForeignKey('pci_devices.id', ondelete='CASCADE')),
        sa.Column('image_id', sa.Integer(),
                  sa.ForeignKey('device_images.id', ondelete='CASCADE')),
        sa.Column('status', sa.String(128)),
        sa.Column('update_start_time', sa.DateTime()),
        sa.Column('capabilities', sa.Text())
    )

    # Add columns to i_host table
    op.add_column('i_host',
                  sa.Column('device_image_update', sa.String(64)))
    op.add_column('i_host',
                  sa.Column('reboot_needed', sa.Boolean(), default=False))

    # 106_fpga_remove_columns.py
    """
    This database upgrade removes unused attributes
    from pci_devices and device_labels tables.
    """

    # Remove columns from pci_devices table
    op.drop_column('pci_devices', 'status')
    op.drop_column('pci_devices', 'needs_firmware_update')

    # Remove column from device_labels table
    op.drop_column('device_labels', 'fpgadevice_id')

    # Drop unique constraint from device_labels table
    op.drop_constraint('u_pcidevice_id@label_key', 'device_labels', type_='unique')

    # 107_device_vf_attrs.py
    op.add_column('pci_devices',
                  sa.Column('sriov_vf_driver', sa.String(255)))
    op.add_column('pci_devices',
                  sa.Column('sriov_vf_pdevice_id', sa.String(4)))

    # 108_kube_app_mode.py
    # Add mode column to kube_app table
    op.add_column('kube_app',
                  sa.Column('mode', sa.String(255), nullable=True))

    # 109_edgeworker_personality.py
    # Set to AUTOCOMMIT isolation level because
    # 'ALTER TYPE ... ADD' cannot run inside a transaction block
    # Only psycopg2 and pg8000 supports AUTOCOMMIT
    if ('postgresql+psycopg2' in str(connection.engine.url) or
            'postgresql+pg8000' in str(connection.engine.url)):
        connection.commit()
        ac_connection = connection.execution_options(isolation_level="AUTOCOMMIT")
        ac_connection.execute(text("ALTER TYPE \"invPersonalityEnum\" ADD VALUE 'edgeworker' AFTER 'reserve2'"))

    # 110_remove_snmp.py
    """
       This database upgrade removes host-based
       snmp related table (community and trapdest)
    """

    op.drop_table('i_community')
    op.drop_table('i_trap_destination')

    if connection.dialect.name == 'postgresql':
        # The enumerations are not defined in metadata, and therefore
        # are usually deleted when the table is dropped.
        # checkfirst=True means these will not drop if already dropped
        connection.execute(text('DROP TYPE IF EXISTS "snmpVersionEnum"'))
        connection.execute(text('DROP TYPE IF EXISTS "snmpTransportType"'))
        connection.execute(text('DROP TYPE IF EXISTS "accessEnum"'))

    # 111_storage_ceph_rook.py
    """
       This database upgrade creates a new storage_ceph_rook table
    """

    op.create_table(
        'storage_ceph_rook',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('id', sa.Integer,
                  sa.ForeignKey('storage_backend.id', ondelete="CASCADE"),
                  primary_key=True, unique=True, nullable=False),
        sa.Column('ceph_conf', sa.String(255), unique=True, index=True),
    )

    # 112_add_backup_restore_table.py
    op.create_table(
        'backup_restore',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('id', sa.Integer, primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('state', sa.String(128), nullable=False),
        sa.Column('capabilities', sa.Text),
    )

    # 113_kube_app_metadata.py
    # add app_metadata to kube_app table
    op.add_column('kube_app', sa.Column('app_metadata', sa.Text, nullable=True))

    # 114_system_geolocation.py
    """
        This database upgrade updates the i_system table by creating
        new columns to store GPS coordinates.
    """

    op.add_column('i_system', sa.Column('latitude', sa.String(30)))
    op.add_column('i_system', sa.Column('longitude', sa.String(30)))

    # 115_interface_primary_reselect.py
    op.add_column('ae_interfaces', sa.Column('primary_reselect', sa.String(32)))

    # 116_storage_ceph_network.py
    # add network to storage_ceph table
    op.add_column('storage_ceph',
                  sa.Column('network', sa.String(255),
                            nullable=True,
                            default=constants.NETWORK_TYPE_MGMT))
    op.alter_column('storage_ceph', 'network', nullable=False)

    # 117_kube_update_rootca_tables.py
    """
       This database upgrade creates a new kube_rootca_update
       table and a new kube_rootca_host_update table
    """

    # Define and create the kube_rootca_update table.
    op.create_table(
        'kube_rootca_update',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('id', sa.Integer, primary_key=True,
                  unique=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('from_rootca_cert', sa.String(255)),
        sa.Column('to_rootca_cert', sa.String(255)),
        sa.Column('state', sa.String(255)),
        sa.Column('capabilities', sa.Text),
        sa.Column('reserved_1', sa.String(255)),
        sa.Column('reserved_2', sa.String(255)),
        sa.Column('reserved_3', sa.String(255)),
    )

    op.create_table(
        'kube_rootca_host_update',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('id', sa.Integer, primary_key=True,
                  unique=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('target_rootca_cert', sa.String(255)),
        sa.Column('effective_rootca_cert', sa.String(255)),
        sa.Column('state', sa.String(255)),
        sa.Column('host_id', sa.Integer,
                  sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('capabilities', sa.Text),
        sa.Column('reserved_1', sa.String(255)),
        sa.Column('reserved_2', sa.String(255)),
        sa.Column('reserved_3', sa.String(255)),
    )

    # 118_kube_cmd_versions_table.py
    """
       This database upgrade creates a new kube_cmd_versions table
    """

    # Define and create the kube_cmd_versions table.
    op.create_table(
        'kube_cmd_versions',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('id', sa.Integer, primary_key=True,
                  unique=True, nullable=False),
        sa.Column('kubeadm_version', sa.String(255), nullable=False),
        sa.Column('kubelet_version', sa.String(255), nullable=False),
        sa.UniqueConstraint('kubeadm_version', 'kubelet_version',
                            name='u_kubeadm_version_kubelet_version'),
    )

    # Insert default kube cmd version
    connection.execute(
        sa.text("INSERT INTO kube_cmd_versions (kubeadm_version, kubelet_version) VALUES (:kubeadm, :kubelet)"),
        {'kubeadm': kubernetes.K8S_INITIAL_CMD_VERSION,
         'kubelet': kubernetes.K8S_INITIAL_CMD_VERSION}
    )

    # 119_device_image_retimer.py
    op.add_column('device_images_functional', sa.Column('retimer_included', sa.Boolean, default=False))


def downgrade() -> None:
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
