#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""rpm to idisk

Revision ID: 805020c3bcae
Revises: 4ad7ee5e761c
Create Date: 2025-10-07 08:38:14.142735

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sysinv.common import constants


# revision identifiers, used by Alembic.
revision: str = '805020c3bcae'
down_revision: Union[str, None] = '4ad7ee5e761c'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def _populate_rpm_type(connection, idisk_table):
    disks = list(connection.execute(idisk_table.select().where(
                 idisk_table.c.uuid is not None)))
    if len(disks) > 0:
        connection.execute(idisk_table.update().where(idisk_table.c.rpm is None).values(
            {'rpm': constants.DEVICE_TYPE_UNDETERMINED}))


def upgrade():
    # Add rpm column to i_idisk table
    op.add_column('i_idisk', sa.Column('rpm', sa.String(255)))

    # Populate rpm column with default values
    connection = op.get_bind()
    meta = sa.MetaData()
    i_idisk = sa.Table('i_idisk', meta, autoload_with=connection)
    _populate_rpm_type(connection, i_idisk)


def downgrade():
    raise NotImplementedError('SysInv database downgrade is unsupported.')
