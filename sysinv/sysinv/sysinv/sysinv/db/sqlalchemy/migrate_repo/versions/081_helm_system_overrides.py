#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Text
from sqlalchemy import Column, MetaData, Table

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    """
       This database upgrade creates a new column for storing passwords
       on the helm chart override table.
    """

    meta = MetaData()
    meta.bind = migrate_engine

    helm_overrides = Table('helm_overrides', meta, autoload=True)
    helm_overrides.create_column(Column('system_overrides', Text,
                                        nullable=True))


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    helm_overrides = Table('helm_overrides', meta, autoload=True)
    helm_overrides.drop_column('system_overrides')
