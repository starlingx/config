# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from migrate.changeset import UniqueConstraint
from sqlalchemy import Column, DateTime, ForeignKey, Integer, MetaData, String
from sqlalchemy import Table, Text

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    Table('i_system',
        meta,
        Column('id', Integer,
            primary_key=True, nullable=False),
        mysql_engine=ENGINE, mysql_charset=CHARSET)

    clusters = Table(
        'clusters',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(255), unique=True, index=True),
        Column('cluster_uuid', String(255), unique=True, index=True),

        Column('type', String(255)),
        Column('name', String(255), unique=True, index=True),
        Column('capabilities', Text),

        Column('system_id', Integer,
               ForeignKey('i_system.id', ondelete="CASCADE"),
               nullable=True),

        UniqueConstraint('name', 'system_id', name='u_name@system'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    clusters.create()

    peers = Table(
        'peers',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(255), unique=True, index=True),

        Column('name', String(255), index=True),
        Column('status', String(255)),
        Column('info', Text),
        Column('capabilities', Text),

        Column('cluster_id', Integer,
               ForeignKey('clusters.id', ondelete="CASCADE"),
               nullable=True),

        UniqueConstraint('name', 'cluster_id', name='u_name@cluster'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    peers.create()

    i_host = Table('i_host', meta,
                   Column('id', Integer,
                          primary_key=True, nullable=False),
                   mysql_engine=ENGINE, mysql_charset=CHARSET,
                   autoload=True)

    i_host.create_column(Column('peer_id', Integer,
                         ForeignKey('peers.id'),
                         nullable=True))


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    i_host = Table('i_host', meta,
                   Column('id', Integer,
                          primary_key=True, nullable=False),
                   mysql_engine=ENGINE, mysql_charset=CHARSET,
                   autoload=True)

    i_host.drop_column(Column('cluster_id'))

    peers = Table('peers', meta, autoload=True)
    peers.drop()

    clusters = Table('clusters', meta, autoload=True)
    clusters.drop()
