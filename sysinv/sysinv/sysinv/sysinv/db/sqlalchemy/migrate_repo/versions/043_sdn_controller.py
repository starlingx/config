# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from migrate.changeset import UniqueConstraint
from sqlalchemy import Enum, Integer, String, DateTime
from sqlalchemy import Column, MetaData, Table, ForeignKey
from sqlalchemy.dialects import postgresql
import json

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Seed SDN disabled capability in the i_system DB table
    systems = Table('i_system', meta, autoload=True)
    # only one system entry should be populated
    sys = list(systems.select().where(
        systems.c.uuid is not None).execute())
    if len(sys) > 0:
        json_dict = json.loads(sys[0].capabilities)
        json_dict['sdn_enabled'] = 'n'
        systems.update().where(
            systems.c.uuid == sys[0].uuid).values(
            {'capabilities': json.dumps(json_dict)}).execute()

    # Enhance the services enum to include network
    service_parameter = Table('service_parameter',
                              meta,
                              Column('id', Integer,
                                     primary_key=True, nullable=False),
                              mysql_engine=ENGINE, mysql_charset=CHARSET,
                              autoload=True)

    if migrate_engine.url.get_dialect() is postgresql.dialect:
        old_serviceEnum = Enum('identity',
                               'horizon',
                               'ceph',
                               name='serviceEnum')

        serviceEnum = Enum('identity',
                           'horizon',
                           'ceph',
                           'network',
                           name='serviceEnum')

        service_col = service_parameter.c.service
        service_col.alter(Column('service', String(60)))
        old_serviceEnum.drop(bind=migrate_engine, checkfirst=False)
        serviceEnum.create(bind=migrate_engine, checkfirst=False)
        migrate_engine.execute('ALTER TABLE service_parameter ALTER COLUMN service TYPE "serviceEnum" '
                   'USING service::text::"serviceEnum"')

    sdn_controller = Table(
        'sdn_controller',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('ip_address', String(255)),
        Column('port', Integer),
        Column('transport', String(255)),
        Column('state', String(255)),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    sdn_controller.create()


def downgrade(migrate_engine):
    # Don't support SysInv downgrades at this time
    raise NotImplementedError('SysInv database downgrade is unsupported.')
