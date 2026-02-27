#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""system distributed cloud role

Revision ID: ca454f69323d
Revises: dcad7048ee17
Create Date: 2025-10-09 00:00:26.551840

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ca454f69323d'
down_revision: Union[str, None] = 'dcad7048ee17'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add distributed_cloud_role column to i_system table
    op.add_column('i_system', sa.Column('distributed_cloud_role', sa.String(255)))


def downgrade() -> None:
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
