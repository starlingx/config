# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table, String

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    fpga_devices = Table('fpga_devices', meta, autoload=True)
    fpga_devices.create_column(Column('retimer_a_version', String(32)))
    fpga_devices.create_column(Column('retimer_b_version', String(32)))


def downgrade(migrate_engine):
    # Downgrade is unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
