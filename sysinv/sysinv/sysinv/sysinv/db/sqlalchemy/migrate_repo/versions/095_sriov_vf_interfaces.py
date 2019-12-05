# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, String, Table, Integer, DateTime
from sqlalchemy import ForeignKey


ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    Table('interfaces', meta, autoload=True)

    sriov_vf_interfaces = Table(
        'vf_interfaces',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, ForeignKey('interfaces.id', ondelete="CASCADE"),
               primary_key=True, nullable=False),

        Column('imac', String(255)),
        Column('imtu', Integer),
        Column('sriov_numvfs', Integer),
        Column('sriov_vf_driver', String(255)),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    sriov_vf_interfaces.create()


def downgrade(migrate_engine):
    # Downgrade is unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
