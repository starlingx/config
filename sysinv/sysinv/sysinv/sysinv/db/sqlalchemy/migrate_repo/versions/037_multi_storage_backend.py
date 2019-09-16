# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import String
from sqlalchemy import Integer


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    i_storconfig = Table('i_storconfig', meta, autoload=True)
    i_storconfig.create_column(Column('state', String(255)))
    i_storconfig.create_column(Column('task', String(255)))
    i_storconfig.create_column(Column('ceph_mon_gib', Integer))
    i_storconfig.create_column(Column('ceph_mon_dev_ctrl0', String(255)))
    i_storconfig.create_column(Column('ceph_mon_dev_ctrl1', String(255)))
    # In release 15.12, virtual box controllers would only have 10GiB for
    # the ceph mon filesystem.
    # When upgrading from 15.12, we will show 20GiB for virtual box
    # - this shouldn't cause any issues and can be corrected by resizing
    # this filesystem to anything other than 20Gib after the upgrade.
    i_storconfig.update().values(
        {'state': 'configured',
         'ceph_mon_gib': 20}).execute()


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
