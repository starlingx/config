#
# Copyright (c) 2021 Intel Corporation, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import Table


def upgrade(migrate_engine):
    """
        This database upgrade updates the i_system table by creating
        new columns to store GPS coordinates.
        Arguments:
        - Requires sqlalchemy migration engine
    """

    meta = MetaData()
    meta.bind = migrate_engine
    migrate_engine.connect()

    i_system = Table('i_system', meta, autoload=True)
    i_system.create_column(Column('latitude', String(30)))
    i_system.create_column(Column('longitude', String(30)))


def downgrade(migrate_engine):
    # Downgrade is unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
