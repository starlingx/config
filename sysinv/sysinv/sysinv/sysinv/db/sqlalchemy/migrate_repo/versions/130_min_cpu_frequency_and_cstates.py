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
    host_table = Table('i_host', meta, autoload=True)
    host_table.create_column(Column('min_cpu_mhz_allowed', String(64)))
    host_table.create_column(Column('cstates_available', String(255)))


def downgrade(migrate_engine):
    raise NotImplementedError('SysInv database downgrade is unsupported.')
