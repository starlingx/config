########################################################################
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from migrate.changeset import UniqueConstraint
from sqlalchemy import Integer, String, DateTime
from sqlalchemy import Column, MetaData, Table, ForeignKey

from sysinv.db.sqlalchemy.models import UUID_LENGTH

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    Table('i_host', meta, autoload=True)

    runtime_config = Table(
        'runtime_config',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('config_uuid', String(UUID_LENGTH), nullable=False),
        Column('config_dict', String(767)),
        Column('state', String(255)),
        Column('forihostid', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE'), nullable=False),
        Column('reserved_1', String(255)),
        UniqueConstraint('config_uuid', 'forihostid', name='u_config_uuid_forihostid'),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    runtime_config.create()


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    runtime_config = Table('runtime_config', meta, autoload=True)
    runtime_config.drop()
