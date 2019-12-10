# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, String, Table

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    interface = Table('interfaces', meta, autoload=True)
    interface.create_column(Column('ptp_role', String(255)), default='none')


def downgrade(migrate_engine):
    # Downgrade is unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
