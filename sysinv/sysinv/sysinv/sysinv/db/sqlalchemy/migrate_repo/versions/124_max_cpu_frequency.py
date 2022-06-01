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
    host_table = Table('i_host', meta, autoload=True)
    host_table.create_column(Column('max_cpu_mhz_configured', String(64)))
    host_table.create_column(Column('max_cpu_mhz_allowed', String(64)))


def downgrade(migrate_engine):
    raise NotImplementedError('SysInv database downgrade is unsupported.')
