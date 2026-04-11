#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""horizon lockout params

Revision ID: e0f95475ea3a
Revises: c1348f2aff2f
Create Date: 2025-10-07 08:38:56.640888

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'e0f95475ea3a'
down_revision: Union[str, None] = 'c1348f2aff2f'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade():
    # Create i_horizon_lockout table
    op.create_table('i_horizon_lockout',
        sa.Column('lockout_time', sa.Integer()),
        sa.Column('lockout_retries', sa.Integer()),
    )

    # Enhance the services enum to include horizon
    bind = op.get_bind()
    if bind.dialect.name == 'postgresql':
        # Add 'horizon' value to existing serviceEnum
        op.execute("ALTER TYPE \"serviceEnum\" ADD VALUE 'horizon'")


def downgrade():
    raise NotImplementedError('SysInv database downgrade is unsupported.')
