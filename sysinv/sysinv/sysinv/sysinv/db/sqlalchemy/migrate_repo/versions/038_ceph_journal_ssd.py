# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import uuid
from datetime import datetime

from sqlalchemy import Integer, DateTime
from sqlalchemy import Column, MetaData, String, Table, ForeignKey, select

from oslo_log import log


ENGINE = 'InnoDB'
CHARSET = 'utf8'

ENGINE = 'InnoDB'
CHARSET = 'utf8'

LOG = log.getLogger(__name__)


def _populate_journal(migrate_engine, meta, journal, i_istor, i_idisk):
    """This function inserts all the initial data about journals, into the
       journal table.
    """

    conn = migrate_engine.connect()

    journal = Table('journal', meta, autoload=True)
    i_istor = Table('i_istor', meta, autoload=True)
    i_idisk = Table('i_idisk', meta, autoload=True)

    # Obtain all the entries from i_istor and i_idisk tables.
    storage_items = list(i_istor.select().execute())
    # Go through all the OSDs.
    for osd in storage_items:
        journal_insert = journal.insert()

        # Obtain the disk on which the OSD is kept.
        sel = select([i_idisk]).where(i_idisk.c.foristorid == osd['id'])
        i_idisk_entry = conn.execute(sel).fetchone()

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
            journal_insert.execute(values)


def upgrade(migrate_engine):

    meta = MetaData()
    meta.bind = migrate_engine

    i_idisk = Table('i_idisk', meta, autoload=True)
    i_istor = Table('i_istor', meta, autoload=True)
    journal = Table(
                      'journal',
                      meta,
                      Column('created_at', DateTime),
                      Column('updated_at', DateTime),
                      Column('deleted_at', DateTime),
                      Column('id', Integer, primary_key=True, nullable=False),
                      Column('uuid', String(36), unique=True),
                      Column('device_node', String(255)),
                      Column('size_mib', Integer),
                      Column('onistor_uuid', String(36)),
                      Column('foristorid', Integer,
                             ForeignKey(i_istor.c.id, ondelete='CASCADE'),
                             unique=True),

                      mysql_engine=ENGINE,
                      mysql_charset=CHARSET,
                     )

    try:
        journal.create()
    except Exception:
        LOG.error("Table |%s| not created", repr(journal))
        raise

    # Populate the new journal table with the initial data: all journals are
    # collocated.
    _populate_journal(migrate_engine, meta, journal, i_istor, i_idisk)


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
