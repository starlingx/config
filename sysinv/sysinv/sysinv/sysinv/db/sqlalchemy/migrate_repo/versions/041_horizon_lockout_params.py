# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Enum, Integer, String
from sqlalchemy import Column, MetaData, Table
from sqlalchemy.dialects import postgresql

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    i_horizon_lockout = Table(
        'i_horizon_lockout',
        meta,
        Column('lockout_time', Integer),
        Column('lockout_retries', Integer),
     )
    i_horizon_lockout.create()

    # Enhance the services enum to include horizon
    service_parameter = Table('service_parameter',
                              meta,
                              Column('id', Integer,
                                     primary_key=True, nullable=False),
                              mysql_engine=ENGINE, mysql_charset=CHARSET,
                              autoload=True)

    if migrate_engine.url.get_dialect() is postgresql.dialect:
        old_serviceEnum = Enum('identity',
                               name='serviceEnum')

        serviceEnum = Enum('identity',
                           'horizon',
                           name='serviceEnum')

        service_col = service_parameter.c.service
        service_col.alter(Column('service', String(60)))
        old_serviceEnum.drop(bind=migrate_engine, checkfirst=False)
        serviceEnum.create(bind=migrate_engine, checkfirst=False)
        migrate_engine.execute('ALTER TABLE service_parameter ALTER COLUMN service TYPE "serviceEnum" '
                   'USING service::text::"serviceEnum"')


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
