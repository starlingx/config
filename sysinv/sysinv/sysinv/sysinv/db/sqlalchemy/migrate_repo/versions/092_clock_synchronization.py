# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import String
from sysinv.common import constants

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    """
       This database upgrade creates a new host clock_synchronization attribute
       for storing the clock_synchronization type (ntp/ptp) for a host.
    """

    meta = MetaData()
    meta.bind = migrate_engine

    host = Table('i_host', meta, autoload=True)
    host.create_column(Column('clock_synchronization', String(32)),
                       default=constants.NTP)

    ntp = Table('i_ntp', meta, autoload=True)
    ntp.drop_column(Column('enabled'))

    ptp = Table('ptp', meta, autoload=True)
    ptp.drop_column(Column('enabled'))

    return True


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Downgrade is unsupported.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
