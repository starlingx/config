# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Integer
from sqlalchemy import Column, MetaData, Table


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    i_userconfig = Table('i_user', meta, autoload=True)
    i_userconfig.create_column(Column('passwd_last_change', Integer))


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    i_userconfig = Table('i_user', meta, autoload=True)
    i_userconfig.drop_column('passwd_last_change')
