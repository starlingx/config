# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import MetaData, Table

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    host_upgrade = Table('host_upgrade', meta, autoload=True)
    host_upgrade.drop()

    software_upgrade = Table('software_upgrade', meta, autoload=True)
    software_upgrade.drop()

    loads = Table('loads', meta, autoload=True)
    loads.drop()
    return True


def downgrade(migrate_engine):
    raise NotImplementedError('SysInv database downgrade is unsupported.')
