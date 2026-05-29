#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""ptp parameter value to text

Revision ID: 46d9561a6931
Revises: b5f3c9d2e1a7
Create Date: 2026-05-27

"""
from typing import Sequence
from typing import Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '46d9561a6931'
down_revision: Union[str, None] = 'b5f3c9d2e1a7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column('ptp_parameters', 'value',
                    existing_type=sa.String(255),
                    type_=sa.Text(),
                    existing_nullable=True)


def downgrade() -> None:
    op.alter_column('ptp_parameters', 'value',
                    existing_type=sa.Text(),
                    type_=sa.String(255),
                    existing_nullable=True)
