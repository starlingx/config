#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from sqlalchemy import Enum
from sqlalchemy import MetaData
from sqlalchemy import Table
from sqlalchemy.dialects import postgresql

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    """
       This database upgrade removes host-based
       snmp related table (community and trapdest)
    """

    meta = MetaData()
    meta.bind = migrate_engine

    i_community = Table('i_community', meta, autoload=True)
    i_community.drop()
    i_trap_destination = Table('i_trap_destination', meta, autoload=True)
    i_trap_destination.drop()

    if migrate_engine.url.get_dialect() is postgresql.dialect:
        old_typeEnum = Enum('snmpv2c_trap',
                            'reserve1',
                            'reserve2',
                            name='snmpVersionEnum')

        old_transportEnum = Enum('udp',
                                 'reserve1',
                                 'reserve2',
                                 name='snmpTransportType')

        old_accessEnum = Enum('ro',
                              'rw',
                              'reserve1',
                              'reserve2',
                              name='accessEnum')

        # The enumerations are not defined in metadata, and therefore
        # are usually deleted when the table is dropped.
        # checkfirst=True means these will not drop if already dropped
        old_typeEnum.drop(bind=migrate_engine, checkfirst=True)
        old_transportEnum.drop(bind=migrate_engine, checkfirst=True)
        old_accessEnum.drop(bind=migrate_engine, checkfirst=True)


def downgrade(migrate_engine):
    # Downgrade is unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
