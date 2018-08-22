########################################################################
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

import uuid

from datetime import datetime
from sqlalchemy import Integer, String, Boolean, DateTime
from sqlalchemy import Column, MetaData, Table, ForeignKey

ENGINE = 'InnoDB'
CHARSET = 'utf8'

def _populate_ptp_table(migrate_engine, meta, ptp, i_system):
    """This function inserts all the initial data about journals,
       into the ptp table.
    """

    sys = list(i_system.select().where(i_system.c.uuid is not None).execute())
    if len(sys) > 0:
        ptp_insert = ptp.insert()
        ptp_uuid = str(uuid.uuid4())
        values = {'created_at': datetime.now(),
                  'updated_at': None,
                  'deleted_at': None,
                  'uuid': ptp_uuid,
                  'enabled': False,
                  'mode': 'hardware',
                  'transport': 'l2',
                  'mechanism': 'e2e',
                  'system_id': sys[0].id,
                  }
        ptp_insert.execute(values)


def upgrade(migrate_engine):

    meta = MetaData()
    meta.bind = migrate_engine

    i_system = Table('i_system', meta, autoload=True)
    ptp = Table(
        'ptp',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('enabled', Boolean, default=False),
        Column('mode', String(16), default='hardware'),
        Column('transport', String(4), default='l2'),
        Column('mechanism', String(4), default='e2e'),

        Column('system_id', Integer,
               ForeignKey('i_system.id', ondelete="CASCADE"),
               nullable=True),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    ptp.create()
    # Populate the new ptp table with the initial data
    _populate_ptp_table(migrate_engine, meta, ptp, i_system)


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    ptp = Table('ptp', meta, autoload=True)
    ptp.drop()
