# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Integer, DateTime
from sqlalchemy import Column, MetaData, String, Table, ForeignKey, Text

from sysinv.openstack.common import log

ENGINE = 'InnoDB'
CHARSET = 'utf8'

LOG = log.getLogger(__name__)


def upgrade(migrate_engine):

    meta = MetaData()
    meta.bind = migrate_engine

    i_pv = Table('i_pv', meta, autoload=True)
    i_idisk = Table('i_idisk', meta, autoload=True)
    i_host = Table('i_host', meta, autoload=True)

    # Add the 'available_mib' column to the i_idisk table.
    i_idisk.create_column(Column('available_mib', Integer))

    # Rename the columns from the i_pv table to show that an uuid, device node
    # and device path can be either those of a disk or a partition.
    i_pv.c.idisk_uuid.alter(name='disk_or_part_uuid')
    i_pv.c.idisk_device_node.alter(name='disk_or_part_device_node')
    i_pv.c.idisk_device_path.alter(name='disk_or_part_device_path')

    # Create the partition table.
    partition = Table(
        'partition',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('start_mib', Integer),
        Column('end_mib', Integer),
        Column('size_mib', Integer),
        Column('device_path', String(255)),
        Column('type_guid', String(36)),
        Column('type_name', String(64)),
        Column('idisk_id', Integer,
               ForeignKey(i_idisk.c.id, ondelete='CASCADE')),
        Column('idisk_uuid', String(36)),
        Column('capabilities', Text),
        Column('status', Integer),
        Column('foripvid', Integer,
               ForeignKey(i_pv.c.id)),
        Column('forihostid', Integer,
               ForeignKey(i_host.c.id)),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    try:
        partition.create()
    except Exception:
        LOG.error("Table |%s| not created", repr(partition))
        raise


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
