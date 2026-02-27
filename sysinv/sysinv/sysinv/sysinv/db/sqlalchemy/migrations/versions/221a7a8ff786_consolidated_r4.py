#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""consolidated r4

Revision ID: 221a7a8ff786
Revises: 96dcf94cbf08
Create Date: 2025-10-07 08:40:27.959502

"""
from typing import Sequence, Union
from eventlet.green import subprocess
import json
import tsconfig.tsconfig as tsconfig

from alembic import op
import sqlalchemy as sa
from oslo_log import log
from sysinv.common import constants
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '221a7a8ff786'
down_revision: Union[str, None] = '96dcf94cbf08'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

LOG = log.getLogger(__name__)


def _populate_system_mode(connection, system_table):
    if tsconfig.system_mode is not None:
        mode = tsconfig.system_mode
    else:
        mode = constants.SYSTEM_MODE_DUPLEX

    sys = list(connection.execute(system_table.select().where(
        system_table.c.uuid is not None)))
    if len(sys) > 0:
        if sys[0].system_mode is None:
            connection.execute(system_table.update().where(
                system_table.c.uuid == sys[0].uuid).values(
                {'system_mode': mode}))


def _populate_system_timezone(connection, system_table):
    timezone = constants.TIME_ZONE_UTC
    sys = list(connection.execute(system_table.select().where(
        system_table.c.uuid is not None)))
    if len(sys) > 0:
        if sys[0].timezone is None:
            connection.execute(system_table.update().where(
                system_table.c.uuid == sys[0].uuid).values(
                {'timezone': timezone}))


def _update_ceph_mon_device_path(connection, ceph_mon_table):
    # Obtain the ceph mon entry
    ceph_mon_entry = list(connection.execute(ceph_mon_table.select()))

    # If there is no entry in the ceph_mon table, return
    if not ceph_mon_entry:
        return

    # Update the ceph mon with the corresponding device path
    device_node = getattr(ceph_mon_entry[0], 'device_path', None)

    if device_node:
        command = ['find', '-L', '/dev/disk/by-path', '-samefile', device_node]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True)
        out, err = process.communicate()
        device_path = out.rstrip()

        connection.execute(ceph_mon_table.update().where(
            ceph_mon_table.c.uuid == ceph_mon_entry[0]['uuid']).values(
            {'device_path': device_path}))


def upgrade():
    """Perform sysinv database upgrade migrations (release4).
    """
    connection = op.get_bind()
    meta = sa.MetaData()

    # 046_drop_iport.py
    op.drop_table('i_port')

    # 047_install_state.py
    op.add_column('i_host', sa.Column('install_state', sa.String(255)))
    op.add_column('i_host', sa.Column('install_state_info', sa.String(255)))

    # 048 Replace services enum with string (include ceph, platform)
    op.drop_table('service_parameter')
    op.create_table('service_parameter',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('service', sa.String(16)),
        sa.Column('section', sa.String(255)),
        sa.Column('name', sa.String(255)),
        sa.Column('value', sa.String(255)),
        sa.UniqueConstraint('service', 'section', 'name', name='u_servicesectionname'),
    )

    # 049_add_controllerfs_scratch.py
    op.add_column('controller_fs', sa.Column('scratch_gib', sa.Integer()))
    # 052_add_controllerfs_state.py
    op.add_column('controller_fs', sa.Column('state', sa.String(255)))

    # 050_services.py
    op.create_table('services',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True),
        sa.Column('name', sa.String(255), nullable=False),
        sa.Column('enabled', sa.Boolean(), default=False),
    )
    op.drop_table('i_servicegroup')

    # 053_add_virtual_interface.py
    op.create_table('virtual_interfaces',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), sa.ForeignKey('interfaces.id', ondelete='CASCADE'), primary_key=True, nullable=False),
        sa.Column('imac', sa.String(255)),
        sa.Column('imtu', sa.Integer()),
        sa.Column('providernetworks', sa.String(255)),
        sa.Column('providernetworksdict', sa.Text()),
    )

    # 054_system_mode.py
    op.add_column('i_system', sa.Column('system_mode', sa.String(255)))
    systems = sa.Table('i_system', meta, autoload_with=connection)
    _populate_system_mode(connection, systems)

    # 055_tpmconfig.py Seed HTTPS disabled capability in i_system table
    sys = list(connection.execute(systems.select().where(systems.c.uuid is not None)))
    if len(sys) > 0:
        json_dict = json.loads(sys[0].capabilities)
        json_dict['https_enabled'] = 'n'
        connection.execute(systems.update().where(
            systems.c.uuid == sys[0].uuid).values(
            {'capabilities': json.dumps(json_dict)}))

    # Add tpmconfig DB table
    op.create_table('tpmconfig',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('tpm_path', sa.String(255)),
    )

    # Add tpmdevice DB table
    op.create_table('tpmdevice',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('state', sa.String(255)),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
    )

    # 056_ipv_add_failed_status.py
    if connection.dialect.name == 'postgresql':
        pv_state_enum = postgresql.ENUM('unprovisioned', 'adding', 'provisioned', 'removing', 'failed', 'reserve2', name='pvStateEnum')
        pv_state_enum.create(op.get_bind())

    # 057_idisk_id_path_wwn.py
    op.add_column('i_idisk', sa.Column('device_id', sa.String(255)))
    op.add_column('i_idisk', sa.Column('device_path', sa.String(255)))
    op.add_column('i_idisk', sa.Column('device_wwn', sa.String(255)))

    # Remove the device_node unique constraint and add a unique constraint for device_path
    op.drop_constraint('u_devhost', 'i_idisk', type_='unique')
    op.create_unique_constraint('u_devhost', 'i_idisk', ['device_path', 'forihostid'])

    # 058_system_timezone.py
    op.add_column('i_system', sa.Column('timezone', sa.String(255)))
    _populate_system_timezone(connection, systems)

    # 060_disk_device_path.py
    op.add_column('i_pv', sa.Column('idisk_device_path', sa.String(255)))
    # Update the ceph_mon table
    op.alter_column('ceph_mon', 'device_node', new_column_name='device_path')
    ceph_mon = sa.Table('ceph_mon', meta, autoload_with=connection)
    _update_ceph_mon_device_path(connection, ceph_mon)
    # Update the journal table
    op.alter_column('journal', 'device_node', new_column_name='device_path')
    # Update the storage_lvm table
    op.drop_column('storage_lvm', 'cinder_device')

    # 062_iscsi_initiator_name.py
    op.add_column('i_host', sa.Column('iscsi_initiator_name', sa.String(64)))


def downgrade():
    raise NotImplementedError('SysInv database downgrade is unsupported.')
