#
# Copyright (c) 2018 Wind River Systems, Inc.
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

    i_storconfig = Table('storage_ceph', meta, autoload=True)
    i_storconfig.create_column(Column('kube_pool_gib', Integer))


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    i_storconfig = Table('storage_ceph', meta, autoload=True)
    i_storconfig.drop_column('kube_pool_gib')
