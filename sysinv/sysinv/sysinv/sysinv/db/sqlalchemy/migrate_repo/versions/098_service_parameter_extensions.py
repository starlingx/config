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
    meta = MetaData()
    meta.bind = migrate_engine

    # Increase the size of the value column
    service_parameter = Table('service_parameter',
                              meta,
                              Column('id', Integer,
                                     primary_key=True, nullable=False),
                              mysql_engine=ENGINE, mysql_charset=CHARSET,
                              autoload=True)

    service_col = service_parameter.c.value
    service_col.alter(Column('value', String(4096)))


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Downgrade is unsupported.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
