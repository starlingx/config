#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""remotelogging

Revision ID: c1348f2aff2f
Revises: 805020c3bcae
Create Date: 2025-10-07 08:38:37.049251

"""
from typing import Sequence, Union
import uuid
from datetime import datetime

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'c1348f2aff2f'
down_revision: Union[str, None] = '805020c3bcae'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _populate_remotelogging_table(connection, remotelogging, i_system):
    """This function inserts all the initial data about journals, into the
       remotelogging table.
    """
    sys = list(connection.execute(i_system.select().where(i_system.c.uuid is not None)))
    if len(sys) > 0:
        remotelogging_uuid = str(uuid.uuid4())
        values = {'created_at': datetime.now(),
                  'updated_at': None,
                  'deleted_at': None,
                  'uuid': remotelogging_uuid,
                  'enabled': False,
                  'transport': 'udp',
                  'ip_address': None,
                  'port': 514,
                  'key_file': None,
                  'system_id': sys[0].id,
                  }
        connection.execute(remotelogging.insert().values(values))


def upgrade():
    # Create log transport enum
    log_transport_enum = postgresql.ENUM('udp', 'tcp', 'tls', name='logTransportEnum')

    # Create remotelogging table
    op.create_table('remotelogging',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('enabled', sa.Boolean(), default=False),
        sa.Column('transport', log_transport_enum),
        sa.Column('ip_address', sa.String(50), unique=True, index=True),
        sa.Column('port', sa.Integer(), default=514),
        sa.Column('key_file', sa.String(255)),
        sa.Column('system_id', sa.Integer(), sa.ForeignKey('i_system.id', ondelete='CASCADE'), nullable=True),
    )

    # Populate the new remotelogging table with the initial data
    connection = op.get_bind()
    meta = sa.MetaData()
    remotelogging = sa.Table('remotelogging', meta, autoload_with=connection)
    i_system = sa.Table('i_system', meta, autoload_with=connection)
    _populate_remotelogging_table(connection, remotelogging, i_system)


def downgrade():
    # Drop remotelogging table
    op.drop_table('remotelogging')

    # Drop enum
    postgresql.ENUM(name='logTransportEnum').drop(op.get_bind())