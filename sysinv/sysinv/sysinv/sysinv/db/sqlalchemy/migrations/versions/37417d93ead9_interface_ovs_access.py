#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""interface ovs_access

Revision ID: 37417d93ead9
Revises: 46d9561a6931
Create Date: 2026-06-15 00:00:00.000000

"""
from typing import Sequence
from typing import Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '37417d93ead9'
down_revision: Union[str, None] = '46d9561a6931'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('interfaces',
                  sa.Column('ovs_access', sa.Boolean(), default=False))
