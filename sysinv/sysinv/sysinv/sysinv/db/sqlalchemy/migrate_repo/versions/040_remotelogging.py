# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import json
import uuid

from datetime import datetime
from sqlalchemy import Integer, String, Boolean, DateTime, Enum
from sqlalchemy import Column, MetaData, Table, ForeignKey

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def _populate_remotelogging_table(migrate_engine, meta, remotelogging, i_system):
    """This function inserts all the initial data about journals, into the
       remotelogging table.
    """

    sys = list(i_system.select().where(i_system.c.uuid is not None).execute())
    if len(sys) > 0:
        remotelogging_insert = remotelogging.insert()
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
        remotelogging_insert.execute(values)


def upgrade(migrate_engine):

    logTransportEnum = Enum('udp',
                      'tcp',
                      'tls',
                      name='logTransportEnum')

    meta = MetaData()
    meta.bind = migrate_engine

    i_system = Table('i_system', meta, autoload=True)
    remotelogging = Table(
        'remotelogging',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('enabled', Boolean, default=False),
        Column('transport', logTransportEnum),
        Column('ip_address', String(50), unique=True, index=True),
        Column('port', Integer, default=514),
        Column('key_file', String(255)),

        Column('system_id', Integer,
               ForeignKey('i_system.id', ondelete="CASCADE"),
               nullable=True),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    remotelogging.create()
    # Populate the new remotelogging table with the initial data
    _populate_remotelogging_table(migrate_engine, meta, remotelogging,
        i_system)


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    remotelogging = Table('remotelogging', meta, autoload=True)
    remotelogging.drop()
