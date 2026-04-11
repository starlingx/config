#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""ceph journal ssd

Revision ID: 4ad7ee5e761c
Revises: 507283dd1e06
Create Date: 2025-10-07 08:30:27.229491

"""
from typing import Sequence, Union
import uuid
from datetime import datetime

from alembic import op
import sqlalchemy as sa
from oslo_log import log


# revision identifiers, used by Alembic.
revision: str = '4ad7ee5e761c'
down_revision: Union[str, None] = '507283dd1e06'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


LOG = log.getLogger(__name__)


def _populate_journal(connection, journal, i_istor, i_idisk):
    """This function inserts all the initial data about journals, into the
       journal table.
    """
    # Obtain all the entries from i_istor and i_idisk tables.
    storage_items = list(connection.execute(i_istor.select()))
    # Go through all the OSDs.
    for osd in storage_items:
        # Obtain the disk on which the OSD is kept.
        sel = sa.select([i_idisk]).where(i_idisk.c.foristorid == osd['id'])
        i_idisk_entry = connection.execute(sel).fetchone()

        # Insert values into the table.
        if i_idisk_entry:
            # The collocated journal is always on /dev/sdX2.
            journal_node = i_idisk_entry['device_node'] + "2"
            journal_size_mib = 1024
            journal_uuid = str(uuid.uuid4())

            values = {'created_at': datetime.now(),
                      'updated_at': None,
                      'deleted_at': None,
                      'uuid': journal_uuid,
                      'device_node': journal_node,
                      'size_mib': journal_size_mib,
                      'onistor_uuid': osd['uuid'],
                      'foristorid': osd['id'],
                      }
            connection.execute(journal.insert().values(values))


def upgrade():
    # Create journal table
    op.create_table('journal',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('device_node', sa.String(255)),
        sa.Column('size_mib', sa.Integer()),
        sa.Column('onistor_uuid', sa.String(36)),
        sa.Column('foristorid', sa.Integer(), sa.ForeignKey('i_istor.id', ondelete='CASCADE'), unique=True),
    )

    # Populate the new journal table with the initial data: all journals are collocated
    connection = op.get_bind()
    meta = sa.MetaData()
    journal = sa.Table('journal', meta, autoload_with=connection)
    i_istor = sa.Table('i_istor', meta, autoload_with=connection)
    i_idisk = sa.Table('i_idisk', meta, autoload_with=connection)

    _populate_journal(connection, journal, i_istor, i_idisk)


def downgrade():
    raise NotImplementedError('SysInv database downgrade is unsupported.')