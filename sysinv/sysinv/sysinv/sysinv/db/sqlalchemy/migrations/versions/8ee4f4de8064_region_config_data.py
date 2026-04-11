#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""region config data

Revision ID: 8ee4f4de8064
Revises: 7b3f70738379
Create Date: 2025-10-08 23:59:39.479797

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '8ee4f4de8064'
down_revision: Union[str, None] = '7b3f70738379'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def upgrade() -> None:
    # Add region_name and service_project_name to i_system table
    op.add_column('i_system', sa.Column('region_name', sa.Text(), default='RegionOne'))
    op.add_column('i_system', sa.Column('service_project_name', sa.Text(), default='services'))

    # Add region_name and capabilities to services table
    op.add_column('services', sa.Column('region_name', sa.Text(), default='RegionOne'))
    op.add_column('services', sa.Column('capabilities', sa.Text()))


def downgrade() -> None:
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
