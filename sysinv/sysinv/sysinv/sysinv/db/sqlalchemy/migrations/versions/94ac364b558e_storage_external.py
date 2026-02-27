#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""storage external

Revision ID: 94ac364b558e
Revises: ca454f69323d
Create Date: 2025-10-09 00:00:41.956287

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '94ac364b558e'
down_revision: Union[str, None] = 'ca454f69323d'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """
       This database upgrade creates a new storage_external table
    """

    # Create storage_external table
    op.create_table('storage_external',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(),
                  sa.ForeignKey('storage_backend.id', ondelete='CASCADE'),
                  primary_key=True, unique=True, nullable=False),
    )


def downgrade() -> None:
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')