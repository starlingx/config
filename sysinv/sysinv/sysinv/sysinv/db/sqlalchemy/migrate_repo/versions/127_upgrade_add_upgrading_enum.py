# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import MetaData, Table, Column, Integer, Enum, String
from sqlalchemy.dialects import postgresql


ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    Table('i_system',
        meta,
        Column('id', Integer,
            primary_key=True, nullable=False),
        mysql_engine=ENGINE, mysql_charset=CHARSET)

    i_host = Table('i_host',
                   meta,
                   Column('id', Integer,
                          primary_key=True, nullable=False),
                   mysql_engine=ENGINE, mysql_charset=CHARSET,
                   autoload=True)

    if migrate_engine.url.get_dialect() is postgresql.dialect:
        old_provisionEnum = Enum('unprovisioned',
                             'inventoried',
                             'configured',
                             'provisioning',
                             'provisioned',
                             'reserve1',
                             'reserve2',
                             name='invprovisionStateEnum')

        provisionEnum = Enum('unprovisioned',
                             'inventoried',
                             'configured',
                             'provisioning',
                             'provisioned',
                             'upgrading',
                             'reserve1',
                             'reserve2',
                             name='invprovisionStateEnum')

        inv_provision_col = i_host.c.invprovision
        inv_provision_col.alter(Column('invprovision', String(60)))
        old_provisionEnum.drop(bind=migrate_engine, checkfirst=False)
        provisionEnum.create(bind=migrate_engine, checkfirst=False)
        migrate_engine.execute('ALTER TABLE i_host ALTER COLUMN invprovision TYPE "invprovisionStateEnum" '
                   'USING invprovision::text::"invprovisionStateEnum"')


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
