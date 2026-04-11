#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""system security profile

Revision ID: 008440a44441
Revises: 11da1d854706
Create Date: 2025-10-08 23:59:04.909707

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '008440a44441'
down_revision: Union[str, None] = '11da1d854706'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    # Add security_profile column to i_system table
    op.add_column('i_system', sa.Column('security_profile', sa.String(255)))

    # Populate security_profile with default value
    connection = op.get_bind()
    meta = sa.MetaData()
    i_system = sa.Table('i_system', meta, autoload_with=connection)

    sys = list(connection.execute(
        i_system.select().where(i_system.c.uuid.isnot(None))))
    if len(sys) > 0:
        if sys[0].security_profile is None:
            connection.execute(
                i_system.update().where(
                    i_system.c.uuid == sys[0].uuid
                ).values({'security_profile': 'standard'}))


def downgrade():
    raise NotImplementedError('SysInv database downgrade is unsupported.')