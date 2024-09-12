# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Text, Table

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    host_fs = Table('host_fs', meta, autoload=True)
    host_fs.create_column(Column('capabilities', Text))

    controller_fs = Table('controller_fs', meta, autoload=True)
    controller_fs.create_column(Column('capabilities', Text))


def downgrade(migrate_engine):
    # Downgrade is unsupported.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
