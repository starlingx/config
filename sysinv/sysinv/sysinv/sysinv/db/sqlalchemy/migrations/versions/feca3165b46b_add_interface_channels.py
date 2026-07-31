#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""add interface channels

Revision ID: feca3165b46b
Revises: df9ef3592001
Create Date: 2026-06-21 22:01:00.000000

"""
from typing import Sequence
from typing import Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'feca3165b46b'
down_revision: Union[str, None] = 'df9ef3592001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('interfaces', sa.Column('channels', sa.Integer()))
    op.add_column('interfaces', sa.Column('sriov_vf_channels', sa.Integer()))


def downgrade() -> None:
    op.drop_column('interfaces', 'sriov_vf_channels')
    op.drop_column('interfaces', 'channels')
