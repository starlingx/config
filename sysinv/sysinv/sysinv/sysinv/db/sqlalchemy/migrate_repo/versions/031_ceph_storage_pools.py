# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Integer
from sqlalchemy import Column, MetaData, Table

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    i_storconfig = Table('i_storconfig', meta, autoload=True)
    i_storconfig.create_column(Column('cinder_pool_gib', Integer))
    i_storconfig.create_column(Column('ephemeral_pool_gib', Integer))
    i_storconfig.c.glance_gib.alter(name='glance_pool_gib')


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    i_storconfig = Table('i_storconfig', meta, autoload=True)
    i_storconfig.drop_column('ephemeral_pool_gib')
    i_storconfig.drop_column('cinder_pool_gib')
    i_storconfig.c.glance_pool_gib.alter(name='glance_gib')
