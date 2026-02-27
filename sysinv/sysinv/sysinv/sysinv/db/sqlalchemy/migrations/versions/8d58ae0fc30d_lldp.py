#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""lldp

Revision ID: 8d58ae0fc30d
Revises: ea2a09db8645
Create Date: 2025-10-07 08:17:03.972536

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8d58ae0fc30d'
down_revision: Union[str, None] = 'ea2a09db8645'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    # Create lldp_agents table
    op.create_table('lldp_agents',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('port_id', sa.Integer(), sa.ForeignKey('ports.id', ondelete='CASCADE')),
        sa.Column('status', sa.String(255)),
    )

    # Create lldp_neighbours table
    op.create_table('lldp_neighbours',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('host_id', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
        sa.Column('port_id', sa.Integer(), sa.ForeignKey('ports.id', ondelete='CASCADE')),
        sa.Column('msap', sa.String(511), nullable=False),
        sa.UniqueConstraint('msap', 'port_id', name='u_msap_port_id'),
    )

    # Create lldp_tlvs table
    op.create_table('lldp_tlvs',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('agent_id', sa.Integer(), sa.ForeignKey('lldp_agents.id', ondelete='CASCADE'), nullable=True),
        sa.Column('neighbour_id', sa.Integer(), sa.ForeignKey('lldp_neighbours.id', ondelete='CASCADE'), nullable=True),
        sa.Column('type', sa.String(255)),
        sa.Column('value', sa.String(255)),
    )


def downgrade():
    raise NotImplementedError('SysInv database downgrade is unsupported.')
