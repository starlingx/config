#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""cluster


Revision ID: f71cc2a45120
Revises: 9780b2a1532d
Create Date: 2025-10-07 08:16:09.345112

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f71cc2a45120'
down_revision: Union[str, None] = '9780b2a1532d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    # Create clusters table
    op.create_table('clusters',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(255), unique=True, index=True),
        sa.Column('cluster_uuid', sa.String(255), unique=True, index=True),
        sa.Column('type', sa.String(255)),
        sa.Column('name', sa.String(255), unique=True, index=True),
        sa.Column('capabilities', sa.Text()),
        sa.Column('system_id', sa.Integer(), sa.ForeignKey('i_system.id', ondelete='CASCADE'), nullable=True),
        sa.UniqueConstraint('name', 'system_id', name='u_name@system'),
    )

    # Create peers table
    op.create_table('peers',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(255), unique=True, index=True),
        sa.Column('name', sa.String(255), index=True),
        sa.Column('status', sa.String(255)),
        sa.Column('info', sa.Text()),
        sa.Column('capabilities', sa.Text()),
        sa.Column('cluster_id', sa.Integer(), sa.ForeignKey('clusters.id', ondelete='CASCADE'), nullable=True),
        sa.UniqueConstraint('name', 'cluster_id', name='u_name@cluster'),
    )

    # Add peer_id column to i_host table
    op.add_column('i_host', sa.Column('peer_id', sa.Integer(), sa.ForeignKey('peers.id'), nullable=True))


def downgrade():
    # Drop peer_id column from i_host table
    op.drop_column('i_host', 'peer_id')

    # Drop peers table
    op.drop_table('peers')

    # Drop clusters table
    op.drop_table('clusters')