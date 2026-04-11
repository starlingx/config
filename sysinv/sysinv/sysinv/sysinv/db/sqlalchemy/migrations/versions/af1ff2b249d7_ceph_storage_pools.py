#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""ceph storage pools

Revision ID: af1ff2b249d7
Revises: 432c9eee887a
Create Date: 2025-10-07 07:48:04.692064

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'af1ff2b249d7'
down_revision: Union[str, None] = '432c9eee887a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade():
    # Add new columns to i_storconfig table
    op.add_column('i_storconfig', sa.Column('cinder_pool_gib', sa.Integer()))
    op.add_column('i_storconfig', sa.Column('ephemeral_pool_gib', sa.Integer()))

    # Rename existing column
    op.alter_column('i_storconfig', 'glance_gib', new_column_name='glance_pool_gib')


def downgrade():
    # Rename column back
    op.alter_column('i_storconfig', 'glance_pool_gib', new_column_name='glance_gib')

    # Drop added columns
    op.drop_column('i_storconfig', 'ephemeral_pool_gib')
    op.drop_column('i_storconfig', 'cinder_pool_gib')
