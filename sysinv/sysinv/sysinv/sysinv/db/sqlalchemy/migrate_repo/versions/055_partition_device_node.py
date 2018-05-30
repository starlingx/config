# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Integer, DateTime, String, Text
from sqlalchemy import Column, MetaData, Table, ForeignKey
from migrate.changeset import UniqueConstraint

from sysinv.openstack.common import log

ENGINE = 'InnoDB'
CHARSET = 'utf8'

LOG = log.getLogger(__name__)


def upgrade(migrate_engine):

    meta = MetaData()
    meta.bind = migrate_engine

    partition = Table('partition', meta, autoload=True)

    # Add the 'device_node' column to the partition table.
    partition.create_column(Column('device_node', String(64)))

    # Add unique constraint for a partition's device path.
    UniqueConstraint('device_path', 'forihostid', table=partition,
                     name='u_partition_path_host_id').create()


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
