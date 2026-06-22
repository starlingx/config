#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""add port channels

Revision ID: df9ef3592001
Revises: 37417d93ead9
Create Date: 2026-06-21 22:00:00.000000

"""
from typing import Sequence
from typing import Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'df9ef3592001'
down_revision: Union[str, None] = '37417d93ead9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('ports', sa.Column('numchannels', sa.Integer()))
    op.add_column('ports', sa.Column('maxchannels', sa.Integer()))
    op.add_column('ports', sa.Column('sriov_vf_numchannels', sa.Integer()))
    op.add_column('ports', sa.Column('sriov_vf_maxchannels', sa.Integer()))


def downgrade() -> None:
    op.drop_column('ports', 'sriov_vf_maxchannels')
    op.drop_column('ports', 'sriov_vf_numchannels')
    op.drop_column('ports', 'maxchannels')
    op.drop_column('ports', 'numchannels')
