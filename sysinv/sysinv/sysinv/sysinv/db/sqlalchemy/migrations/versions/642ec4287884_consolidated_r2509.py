#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""consolidated r2509

Revision ID: 642ec4287884
Revises: f9e2c0db7040
Create Date: 2025-10-07 05:35:15.120621

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
revision: str = '642ec4287884'
down_revision: Union[str, None] = 'f9e2c0db7040'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:

    connection=op.get_bind()

    #120_ptp_instances.py
    op.create_table(
        'ptp_parameters',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('id', sa.Integer, primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(UUID_LENGTH), unique=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('value', sa.String(255)),
    )

    op.create_table(
        'ptp_parameter_owners',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('id', sa.Integer, primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(UUID_LENGTH), unique=True),
        sa.Column('type', sa.String(255), nullable=False),
        sa.Column('capabilities', sa.Text),
    )

    op.create_table(
        'ptp_instances',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('id', sa.Integer,
                  sa.ForeignKey('ptp_parameter_owners.id', ondelete="CASCADE"),
                  primary_key=True, nullable=False),
        sa.Column('name', sa.String(255), unique=True, nullable=False),
        sa.Column('service', sa.String(255)),
        sa.Column('extra_info', sa.Text),
    )

    op.create_table(
        'ptp_interfaces',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('id', sa.Integer,
                  sa.ForeignKey('ptp_parameter_owners.id', ondelete="CASCADE"),
                  primary_key=True, nullable=False),
        sa.Column('name', sa.String(255), unique=True),
        sa.Column('ptp_instance_id', sa.Integer,
                  sa.ForeignKey('ptp_instances.id', ondelete="CASCADE"),
                  nullable=False),
        sa.Column('extra_info', sa.Text),
    )

    op.create_table(
        'ptp_parameter_ownerships',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('id', sa.Integer, primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(UUID_LENGTH), unique=True),
        sa.Column('parameter_uuid', sa.String(UUID_LENGTH),
                  sa.ForeignKey('ptp_parameters.uuid', ondelete='CASCADE'),
                  nullable=False),
        sa.Column('owner_uuid', sa.String(UUID_LENGTH),
                  sa.ForeignKey('ptp_parameter_owners.uuid', ondelete='CASCADE'),
                  nullable=False),
        sa.UniqueConstraint('parameter_uuid', 'owner_uuid', name='u_paramowner'),
    )

    op.create_table(
        'ptp_instance_maps',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('id', sa.Integer, primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(UUID_LENGTH), unique=True),
        sa.Column('host_id', sa.Integer,
                  sa.ForeignKey('i_host.id', ondelete='CASCADE'),
                  nullable=False),
        sa.Column('ptp_instance_id', sa.Integer,
                  sa.ForeignKey('ptp_instances.id', ondelete='CASCADE'),
                  nullable=False),
        sa.UniqueConstraint('host_id', 'ptp_instance_id', name='u_hostinstance'),
    )

    op.create_table(
        'ptp_interface_maps',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('id', sa.Integer, primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(UUID_LENGTH), unique=True),
        sa.Column('interface_id', sa.Integer,
                  sa.ForeignKey('interfaces.id', ondelete='CASCADE'),
                  nullable=False),
        sa.Column('ptp_interface_id', sa.Integer,
                  sa.ForeignKey('ptp_interfaces.id', ondelete='CASCADE'),
                  nullable=False),
        sa.UniqueConstraint('interface_id', 'ptp_interface_id',
                            name='u_ifaceptpiface'),
    )



    #121_retimer_version.py
    op.add_column('fpga_devices', sa.Column('retimer_a_version', sa.String(32)))
    op.add_column('fpga_devices', sa.Column('retimer_b_version', sa.String(32)))



    #122_remove_profiles.py

    if connection.dialect.name == 'postgresql':
        # Delete partition records for profile hosts
        connection.execute(sa.text(
            "DELETE FROM partition USING i_host "
            "WHERE i_host.recordtype='profile' "
            "AND partition.forihostid=i_host.id"
        ))

        # Delete profile hosts
        connection.execute(sa.text("DELETE FROM i_host WHERE recordtype='profile'"))

        # Update personality enum - remove 'profile' value
        connection.execute(sa.text('ALTER TABLE i_host ALTER COLUMN personality TYPE varchar(60)'))
        connection.execute(sa.text('DROP TYPE IF EXISTS "invPersonalityEnum"'))
        connection.execute(sa.text(
            "CREATE TYPE \"invPersonalityEnum\" AS ENUM ("
            "'controller', 'worker', 'network', 'storage', 'reserve1', 'reserve2')"
        ))
        connection.execute(sa.text(
            'ALTER TABLE i_host ALTER COLUMN personality '
            'TYPE "invPersonalityEnum" USING '
            'personality::text::"invPersonalityEnum"'
        ))

        # Update recordtype enum - remove 'profile' value
        connection.execute(sa.text('ALTER TABLE i_host ALTER COLUMN recordtype TYPE varchar(60)'))
        connection.execute(sa.text('DROP TYPE IF EXISTS "recordtypeEnum"'))
        connection.execute(sa.text(
            "CREATE TYPE \"recordtypeEnum\" AS ENUM ("
            "'standard', 'sprofile', 'reserve1', 'reserve2')"
        ))
        connection.execute(sa.text(
            'ALTER TABLE i_host ALTER COLUMN recordtype '
            'TYPE "recordtypeEnum" USING '
            'recordtype::text::"recordtypeEnum"'
        ))



    #123_device_image_bmc.py
    op.add_column('device_images_functional', sa.Column('bmc', sa.Boolean, default=False))



    #124_max_cpu_frequency.py
    op.add_column('i_host', sa.Column('max_cpu_mhz_configured', sa.String(64)))
    op.add_column('i_host', sa.Column('max_cpu_mhz_allowed', sa.String(64)))



    #125_certificate_add_new_columns.py
    # add column to certificate table
    op.add_column('certificate', sa.Column('subject', sa.String(255), nullable=True))
    op.add_column('certificate', sa.Column('hash_subject', sa.String(64), nullable=True))



    #126_apparmor.py
    op.add_column('i_host', sa.Column('apparmor', sa.String(64), default="disabled"))



    #127_upgrade_add_upgrading_enum.py

    if connection.dialect.name == 'postgresql':
        # Update invprovision enum - add 'upgrading' value
        connection.execute(sa.text('ALTER TABLE i_host ALTER COLUMN invprovision TYPE varchar(60)'))
        connection.execute(sa.text('DROP TYPE IF EXISTS "invprovisionStateEnum"'))
        connection.execute(sa.text(
            "CREATE TYPE \"invprovisionStateEnum\" AS ENUM ("
            "'unprovisioned', 'inventoried', 'configured', 'provisioning', "
            "'provisioned', 'upgrading', 'reserve1', 'reserve2')"
        ))
        connection.execute(sa.text(
            'ALTER TABLE i_host ALTER COLUMN invprovision TYPE "invprovisionStateEnum" '
            'USING invprovision::text::"invprovisionStateEnum"'
        ))



    #128_hwsettle.py
    op.add_column('i_host', sa.Column('hw_settle', sa.String(4), default="0"))



    #129_kernel_running.py
    op.add_column('i_host', sa.Column('kernel_running', sa.String(64)))
    op.add_column('i_host', sa.Column('kernel_config_status', sa.String(255)))



    #130_min_cpu_frequency_and_cstates.py
    op.add_column('i_host', sa.Column('min_cpu_mhz_allowed', sa.String(64)))
    op.add_column('i_host', sa.Column('cstates_available', sa.String(255)))



    #131_kube_upgrade_add_recovery_attempts.py
    op.add_column('kube_upgrade', sa.Column('recovery_attempts', sa.Integer,
                                            nullable=False, server_default=sa.text("0")))



    #132_runtime_config.py
    op.create_table(
        'runtime_config',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('id', sa.Integer, primary_key=True, nullable=False),
        sa.Column('config_uuid', sa.String(UUID_LENGTH), nullable=False),
        sa.Column('config_dict', sa.String(767)),
        sa.Column('state', sa.String(255)),
        sa.Column('forihostid', sa.Integer,
                  sa.ForeignKey('i_host.id', ondelete='CASCADE'), nullable=False),
        sa.Column('reserved_1', sa.String(255)),
        sa.UniqueConstraint('config_uuid', 'forihostid', name='u_config_uuid_forihostid'),
    )



    #133_apparmor_config_status.py
    op.add_column('i_host', sa.Column('apparmor_config_status', sa.String(255), default="config_pending"))



    #134_kube_app_bundle.py
    op.create_table(
        'kube_app_bundle',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('id', sa.Integer, primary_key=True, nullable=False),
        sa.Column('name', sa.String(255), nullable=True),
        sa.Column('version', sa.String(255), nullable=True),
        sa.Column('file_path', sa.String(255), nullable=True),
        sa.Column('auto_update', sa.Boolean, nullable=False),
        sa.Column('k8s_auto_update', sa.Boolean, nullable=False),
        sa.Column('k8s_timing', KubeAppBundle.KubeAppBundleTimingEnum, nullable=False),
        sa.Column('k8s_minimum_version', sa.String(16), nullable=False, server_default='1.0.0'),
        sa.Column('k8s_maximum_version', sa.String(16), nullable=True),
        sa.Column('reserved', sa.Text, nullable=True),
        sa.UniqueConstraint('name', 'version', name='u_bundle_name_version'),
        sa.UniqueConstraint('file_path', name='u_bundle_file_path'),
    )

    # Create KubeApp FK to KubeAppBundle
    op.add_column('kube_app', sa.Column('app_bundle_id', sa.Integer,
                                        sa.ForeignKey('kube_app_bundle.id',
                                                      ondelete='SET NULL')))



    #135_nvme_host.py
    op.add_column('i_host', sa.Column('nvme_host_id', sa.String(36)))
    op.add_column('i_host', sa.Column('nvme_host_nqn', sa.String(224)))



    #136_network_addresspool.py
    op.add_column('networks', sa.Column('primary_pool_family', sa.String(4)))

    op.create_table(
        'network_addresspools',
        sa.Column('created_at', sa.DateTime),
        sa.Column('updated_at', sa.DateTime),
        sa.Column('deleted_at', sa.DateTime),
        sa.Column('id', sa.Integer, primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('address_pool_id', sa.Integer, sa.ForeignKey('address_pools.id', ondelete='CASCADE')),
        sa.Column('network_id', sa.Integer, sa.ForeignKey('networks.id', ondelete='CASCADE')),
        sa.UniqueConstraint('network_id', 'address_pool_id', name='u_network_id@address_pool_id'),
    )



    #137_add_host_sw_version.py
    op.add_column('i_host', sa.Column('sw_version', sa.String(128)))



    #138_host_remove_mgmt_ip.py
    """
       This database upgrade removes unused attributes
       from i_host table.
    """

    op.drop_column('i_host', 'mgmt_ip')



    #139_add_host_fs_state.py
    op.add_column('host_fs', sa.Column('state', sa.String(255)))



    #140_add_hostfs_and_controllerfs_capabilities.py
    op.add_column('host_fs', sa.Column('capabilities', sa.Text))
    op.add_column('controller_fs', sa.Column('capabilities', sa.Text))



    #141_addresses_interface_on_delete.py
    """
       This database upgrade changes the 'on delete' parameter in
       the addresses table
    """

    if connection.dialect.name == 'postgresql':
        connection.execute(sa.text('ALTER TABLE addresses DROP CONSTRAINT '
                                   'addresses_interface_id_fkey;'))

        connection.execute(sa.text('ALTER TABLE addresses ADD CONSTRAINT '
                                   'addresses_interface_id_fkey FOREIGN KEY '
                                   '(interface_id) REFERENCES '
                                   'interfaces(id) ON DELETE SET NULL;'))



    #142_drop_legacy_upgrade_tables.py
    op.drop_table('host_upgrade')
    op.drop_table('software_upgrade')
    op.drop_table('loads')



    #143_interface_max_tx_rate_and_max_rx_rate.py
    """Perform sysinv database upgrade for network interface
    """

    op.add_column('interfaces', sa.Column('max_tx_rate', sa.Integer))
    op.add_column('interfaces', sa.Column('max_rx_rate', sa.Integer))


def downgrade() -> None:
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
