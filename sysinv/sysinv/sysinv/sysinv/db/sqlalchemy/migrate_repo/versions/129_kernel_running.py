#
# Copyright (c) 2023 Wind River Systems, Inc.
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
    i_host.create_column(Column('kernel_running', String(64)))
    i_host.create_column(Column('kernel_config_status', String(255)))


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    raise NotImplementedError('SysInv database downgrade is unsupported.')
