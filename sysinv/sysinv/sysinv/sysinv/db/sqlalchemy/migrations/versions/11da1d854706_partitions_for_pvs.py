#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""partitions for pvs

Revision ID: 11da1d854706
Revises: 4d130b21c3d0
Create Date: 2025-10-08 23:58:51.077856

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from oslo_log import log


# revision identifiers, used by Alembic.
revision: str = '11da1d854706'
down_revision: Union[str, None] = '4d130b21c3d0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

LOG = log.getLogger(__name__)


def upgrade():
    # Add the 'available_mib' column to the i_idisk table
    op.add_column('i_idisk', sa.Column('available_mib', sa.Integer()))

    # Rename columns in the i_pv table to show that an uuid, device node
    # and device path can be either those of a disk or a partition
    op.alter_column('i_pv', 'idisk_uuid', new_column_name='disk_or_part_uuid')
    op.alter_column('i_pv', 'idisk_device_node', new_column_name='disk_or_part_device_node')
    op.alter_column('i_pv', 'idisk_device_path', new_column_name='disk_or_part_device_path')

    # Create the partition table
    op.create_table(
        'partition',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('start_mib', sa.Integer()),
        sa.Column('end_mib', sa.Integer()),
        sa.Column('size_mib', sa.Integer()),
        sa.Column('device_path', sa.String(255)),
        sa.Column('type_guid', sa.String(36)),
        sa.Column('type_name', sa.String(64)),
        sa.Column('idisk_id', sa.Integer(), sa.ForeignKey('i_idisk.id', ondelete='CASCADE')),
        sa.Column('idisk_uuid', sa.String(36)),
        sa.Column('capabilities', sa.Text()),
        sa.Column('status', sa.Integer()),
        sa.Column('foripvid', sa.Integer(), sa.ForeignKey('i_pv.id')),
        sa.Column('forihostid', sa.Integer(), sa.ForeignKey('i_host.id')),
        mysql_engine='InnoDB',
        mysql_charset='utf8',
    )


def downgrade():
    raise NotImplementedError('SysInv database downgrade is unsupported.')