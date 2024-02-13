#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import DateTime, Integer, String
from sqlalchemy import ForeignKey, UniqueConstraint

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    Table('address_pools', meta, autoload=True)

    networks = Table('networks', meta, autoload=True)
    networks.create_column(Column('primary_pool_family', String(4)))

    network_addrpool = Table(
        'network_addresspools',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('address_pool_id', Integer, ForeignKey('address_pools.id', ondelete='CASCADE')),
        Column('network_id', Integer, ForeignKey('networks.id', ondelete='CASCADE')),
        UniqueConstraint('network_id', 'address_pool_id', name='u_network_id@address_pool_id'),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    network_addrpool.create()


def downgrade(migrate_engine):
    raise NotImplementedError('SysInv databse downgrade is unsupported.')
