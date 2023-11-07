#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import String


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    migrate_engine.connect()
    i_host = Table('i_host', meta, autoload=True)
    i_host.create_column(Column('apparmor', String(64), default="disabled"))
    i_host.create_column(Column('apparmor_config_status', String(255), default="config_pending"))


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    raise NotImplementedError('SysInv databse downgrade is unsupported.')
