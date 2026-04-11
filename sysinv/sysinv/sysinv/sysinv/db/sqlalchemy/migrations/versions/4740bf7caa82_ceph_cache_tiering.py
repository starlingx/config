#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""ceph cache tiering

Revision ID: 4740bf7caa82
Revises: e0f95475ea3a
Create Date: 2025-10-07 08:39:27.020513

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '4740bf7caa82'
down_revision: Union[str, None] = 'e0f95475ea3a'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    # Enhance the services enum to include ceph
    bind = op.get_bind()
    if bind.dialect.name == 'postgresql':
        # Add 'ceph' value to existing serviceEnum
        op.execute("ALTER TYPE \"serviceEnum\" ADD VALUE 'ceph'")


def downgrade():
    raise NotImplementedError('SysInv database downgrade is unsupported.')