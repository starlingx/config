#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from sqlalchemy import Column, MetaData, Table

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    """
       This database upgrade removes unused attributes
       from i_host table.
    """

    meta = MetaData()
    meta.bind = migrate_engine

    host_table = Table('i_host', meta, autoload=True)
    host_table.drop_column(Column('mgmt_ip'))

    return True


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Downgrade is unsupported.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
