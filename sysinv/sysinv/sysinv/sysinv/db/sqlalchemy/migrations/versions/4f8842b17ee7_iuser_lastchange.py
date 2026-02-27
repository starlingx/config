#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""iuser lastchange

Revision ID: 4f8842b17ee7
Revises: 642ec4287884
Create Date: 2025-12-12 00:10:00.773685

"""
from typing import Sequence
from typing import Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4f8842b17ee7'
down_revision: Union[str, None] = '642ec4287884'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add passwd_last_change column to i_user table
    op.add_column('i_user', sa.Column('passwd_last_change', sa.Integer()))


def downgrade() -> None:
    # Drop passwd_last_change column
    op.drop_column('i_user', 'passwd_last_change')
