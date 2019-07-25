# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import String, Integer

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    """
       This database upgrade creates a new host inv_state attribute for
       storing the inventory state for a host.
    """

    meta = MetaData()
    meta.bind = migrate_engine

    host = Table('i_host',
                 meta,
                 Column('id', Integer, primary_key=True, nullable=False),
                 mysql_engine=ENGINE, mysql_charset=CHARSET, autoload=True)

    # Add the inventory state attribute
    host.create_column(Column('inv_state', String(255)))


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Downgrade is unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
