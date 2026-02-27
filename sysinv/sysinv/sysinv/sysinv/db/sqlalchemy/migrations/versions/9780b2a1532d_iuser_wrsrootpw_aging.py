#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""iuser wrsrootpw aging

Revision ID: 9780b2a1532d
Revises: 0b8155d29ac8
Create Date: 2025-10-07 08:12:01.388305

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '9780b2a1532d'
down_revision: Union[str, None] = '0b8155d29ac8'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    # Add columns to i_user table
    op.add_column('i_user', sa.Column('passwd_hash', sa.String(255)))
    op.add_column('i_user', sa.Column('passwd_expiry_days', sa.Integer()))


def downgrade():
    # Drop added columns
    op.drop_column('i_user', 'passwd_hash')
    op.drop_column('i_user', 'passwd_expiry_days')