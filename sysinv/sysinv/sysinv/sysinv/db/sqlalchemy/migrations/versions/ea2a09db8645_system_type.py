#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""system type

Revision ID: ea2a09db8645
Revises: f71cc2a45120
Create Date: 2025-10-07 08:16:53.730391

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import tsconfig.tsconfig as tsconfig
from sysinv.common import constants

# revision identifiers, used by Alembic.
revision: str = 'ea2a09db8645'
down_revision: Union[str, None] = 'f71cc2a45120'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def _populate_system_type(connection, system_table):
    if constants.WORKER in tsconfig.subfunctions:
        s_type = constants.TIS_AIO_BUILD
    else:
        s_type = constants.TIS_STD_BUILD

    sys = list(connection.execute(system_table.select().where(system_table.c.uuid is not None)))
    if len(sys) > 0:
        if sys[0].system_type is None:
            connection.execute(system_table.update().where(system_table.c.uuid == sys[0].uuid).values({'system_type': s_type}))


def upgrade():
    # Add system_type column to i_system table
    op.add_column('i_system', sa.Column('system_type', sa.String(255)))

    # Populate system_type with appropriate value
    connection = op.get_bind()
    meta = sa.MetaData()
    i_system = sa.Table('i_system', meta, autoload_with=connection)
    _populate_system_type(connection, i_system)


def downgrade():
    raise NotImplementedError('SysInv database downgrade is unsupported.')
