# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2021 Wind River Systems, Inc.
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

    i_host = Table('i_host',
                   meta,
                   Column('id', Integer,
                          primary_key=True, nullable=False),
                   mysql_engine=ENGINE, mysql_charset=CHARSET,
                   autoload=True)

    if migrate_engine.url.get_dialect() is postgresql.dialect:
        old_recordTypeEnum = Enum('standard',
                                  'profile',
                                  'sprofile',
                                  'reserve1',
                                  'reserve2',
                                  name='recordtypeEnum')

        recordTypeEnum = Enum('standard',
                              'sprofile',
                              'reserve1',
                              'reserve2',
                              name='recordtypeEnum')

        old_personalityEnum = Enum('controller',
                                   'worker',
                                   'network',
                                   'storage',
                                   'profile',
                                   'reserve1',
                                   'reserve2',
                                   name='invPersonalityEnum')

        personalityEnum = Enum('controller',
                               'worker',
                               'network',
                               'storage',
                               'reserve1',
                               'reserve2',
                               name='invPersonalityEnum')

        migrate_engine.execute("delete from partition using i_host"
                               " where i_host.recordtype='profile'"
                               " and partition.forihostid=i_host.id")

        migrate_engine.execute("delete from i_host where recordtype='profile'")

        personality_col = i_host.c.personality
        personality_col.alter(Column('personality', String(60)))
        old_personalityEnum.drop(bind=migrate_engine, checkfirst=False)
        personalityEnum.create(bind=migrate_engine, checkfirst=False)
        migrate_engine.execute('ALTER TABLE i_host ALTER COLUMN personality '
                               'TYPE "invPersonalityEnum" USING '
                               'personality::text::"invPersonalityEnum"')

        recordtype_col = i_host.c.recordtype
        recordtype_col.alter(Column('recordtype', String(60)))
        old_recordTypeEnum.drop(bind=migrate_engine, checkfirst=False)
        recordTypeEnum.create(bind=migrate_engine, checkfirst=False)
        migrate_engine.execute('ALTER TABLE i_host ALTER COLUMN recordtype '
                               'TYPE "recordtypeEnum" USING '
                               'recordtype::text::"recordtypeEnum"')


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
