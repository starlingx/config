#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""multi storage backend

Revision ID: 507283dd1e06
Revises: 8d58ae0fc30d
Create Date: 2025-10-07 08:17:22.932602

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '507283dd1e06'
down_revision: Union[str, None] = '8d58ae0fc30d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add columns to i_storconfig table
    op.add_column('i_storconfig', sa.Column('state', sa.String(255)))
    op.add_column('i_storconfig', sa.Column('task', sa.String(255)))
    op.add_column('i_storconfig', sa.Column('ceph_mon_gib', sa.Integer()))
    op.add_column('i_storconfig', sa.Column('ceph_mon_dev_ctrl0', sa.String(255)))
    op.add_column('i_storconfig', sa.Column('ceph_mon_dev_ctrl1', sa.String(255)))

    # Update existing records with default values
    connection = op.get_bind()
    meta = sa.MetaData()
    i_storconfig = sa.Table('i_storconfig', meta, autoload_with=connection)
    connection.execute(i_storconfig.update().values(
        state='configured',
        ceph_mon_gib=20
    ))


def downgrade():
    raise NotImplementedError('SysInv database downgrade is unsupported.')
