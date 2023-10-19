#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import String


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    host_table = Table('i_host', meta, autoload=True)
    host_table.create_column(Column('nvme_host_id', String(36)))
    host_table.create_column(Column('nvme_host_nqn', String(224)))


def downgrade(migrate_engine):
    raise NotImplementedError('SysInv database downgrade is unsupported.')
