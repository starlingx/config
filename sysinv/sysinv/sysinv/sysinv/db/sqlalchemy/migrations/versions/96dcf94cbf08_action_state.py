#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""action state

Revision ID: 96dcf94cbf08
Revises: 37ee62e52c17
Create Date: 2025-10-07 08:40:10.974916

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '96dcf94cbf08'
down_revision: Union[str, None] = '37ee62e52c17'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    """This database upgrade updates the i_host table with the
       action_state and mtce_info attributes.
       The action_state is to track sysinv host action_state, such
       as resinstall.
       The mtce_info attribute is a mtce-only attribute for mtce usage.
    """
    # Add columns to i_host table
    op.add_column('i_host', sa.Column('action_state', sa.String(255)))
    op.add_column('i_host', sa.Column('mtce_info', sa.String(255)))


def downgrade():
    raise NotImplementedError('SysInv database downgrade is unsupported.')