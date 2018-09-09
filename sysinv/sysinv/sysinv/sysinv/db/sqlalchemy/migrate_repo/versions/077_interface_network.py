# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import DateTime, Integer, String
from sqlalchemy import ForeignKey, UniqueConstraint

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    Table('interfaces', meta, autoload=True)
    networks = Table('networks', meta, autoload=True)
    networks.create_column(Column('name', String(255)))

    interface_network = Table(
        'interface_networks',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('interface_id', Integer, ForeignKey('interfaces.id', ondelete='CASCADE')),
        Column('network_id', Integer, ForeignKey('networks.id', ondelete='CASCADE')),
        UniqueConstraint('interface_id', 'network_id', name='u_interface_id@network_id'),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    interface_network.create()


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
