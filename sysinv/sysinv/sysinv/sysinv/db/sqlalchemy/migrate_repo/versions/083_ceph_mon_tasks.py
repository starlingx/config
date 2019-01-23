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

    ceph_mon = Table('ceph_mon', meta, autoload=True)
    ceph_mon.create_column(Column('state', String(255)))
    ceph_mon.create_column(Column('task', String(255)))


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
