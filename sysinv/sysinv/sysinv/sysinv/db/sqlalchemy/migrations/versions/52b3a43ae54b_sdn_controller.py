#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""sdn controller

Revision ID: 52b3a43ae54b
Revises: 4740bf7caa82
Create Date: 2025-10-07 08:39:48.146292

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import json


# revision identifiers, used by Alembic.
revision: str = '52b3a43ae54b'
down_revision: Union[str, None] = '4740bf7caa82'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    # Seed SDN disabled capability in the i_system DB table
    connection = op.get_bind()
    meta = sa.MetaData()
    systems = sa.Table('i_system', meta, autoload_with=connection)

    # only one system entry should be populated
    sys = list(connection.execute(systems.select().where(systems.c.uuid is not None)))
    if len(sys) > 0:
        json_dict = json.loads(sys[0].capabilities)
        json_dict['sdn_enabled'] = 'n'
        connection.execute(systems.update().where(
            systems.c.uuid == sys[0].uuid).values(
            {'capabilities': json.dumps(json_dict)}))

    # Enhance the services enum to include network
    if connection.dialect.name == 'postgresql':
        # Add 'network' value to existing serviceEnum
        op.execute("ALTER TYPE \"serviceEnum\" ADD VALUE 'network'")

    # Create sdn_controller table
    op.create_table('sdn_controller',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('ip_address', sa.String(255)),
        sa.Column('port', sa.Integer()),
        sa.Column('transport', sa.String(255)),
        sa.Column('state', sa.String(255)),
    )


def downgrade():
    raise NotImplementedError('SysInv database downgrade is unsupported.')
