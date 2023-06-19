# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import Integer

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    migrate_engine.connect()
    kube_upgrade = Table('kube_upgrade', meta, autoload=True)
    kube_upgrade.create_column(Column('recovery_attempts', Integer, nullable=False, default=0))


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
