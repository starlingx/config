# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Integer, String
from sqlalchemy import Column, MetaData, Table

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    i_userconfig = Table('i_user', meta, autoload=True)
    i_userconfig.create_column(Column('passwd_hash', String(255)))
    i_userconfig.create_column(Column('passwd_expiry_days', Integer))


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    i_userconfig = Table('i_user', meta, autoload=True)
    i_userconfig.drop_column('passwd_hash')
    i_userconfig.drop_column('passwd_expiry_days')
