# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table, Boolean


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    intp_table = Table('i_ntp', meta, autoload=True)
    intp_table.create_column(Column('enabled', Boolean, default=True))


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    intp_table = Table('i_ntp', meta, autoload=True)
    intp_table.drop_column('enabled')
