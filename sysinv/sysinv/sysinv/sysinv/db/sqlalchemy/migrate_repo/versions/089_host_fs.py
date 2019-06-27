# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import DateTime, String, Integer
from sqlalchemy import Column, MetaData, Table, ForeignKey

from sysinv.openstack.common import log

ENGINE = 'InnoDB'
CHARSET = 'utf8'

LOG = log.getLogger(__name__)


def upgrade(migrate_engine):
    """
       This database upgrade creates a new host_fs table for storing
       filesystem info for a host.
    """

    meta = MetaData()
    meta.bind = migrate_engine

    Table('i_host',
          meta,
          Column('id', Integer, primary_key=True, nullable=False),
          mysql_engine=ENGINE, mysql_charset=CHARSET, autoload=True)

    # Define and create the host_fs table.
    fs_app = Table(
        'host_fs',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('name', String(255)),
        Column('size', Integer),
        Column('logical_volume', String(64)),
        Column('forihostid', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    fs_app.create()


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Downgrade is unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
