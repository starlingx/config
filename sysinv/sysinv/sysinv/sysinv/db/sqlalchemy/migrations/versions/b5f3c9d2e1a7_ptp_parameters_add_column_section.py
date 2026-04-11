#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""ptp parameters add column section

Revision ID: b5f3c9d2e1a7
Revises: 4f8842b17ee7
Create Date: 2025-01-01 00:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


revision: str = 'b5f3c9d2e1a7'
down_revision: Union[str, None] = '4f8842b17ee7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # add column to ptp_parameters table
    op.add_column('ptp_parameters', sa.Column('section', sa.String(255), server_default='global'))


def downgrade() -> None:
    # remove column from ptp_parameters table
    op.drop_column('ptp_parameters', 'section')
