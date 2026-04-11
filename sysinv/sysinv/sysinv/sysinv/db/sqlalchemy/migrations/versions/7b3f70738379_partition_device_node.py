#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""partition device node

Revision ID: 7b3f70738379
Revises: 008440a44441
Create Date: 2025-10-08 23:59:20.606054

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7b3f70738379'
down_revision: Union[str, None] = '008440a44441'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Add the 'device_node' column to the partition table
    op.add_column('partition', sa.Column('device_node', sa.String(64)))

    # Add unique constraint for a partition's device path
    op.create_unique_constraint('u_partition_path_host_id', 'partition',
                               ['device_path', 'forihostid'])


def downgrade() -> None:
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
