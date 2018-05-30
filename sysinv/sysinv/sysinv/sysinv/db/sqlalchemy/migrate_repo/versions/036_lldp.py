# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from migrate.changeset import UniqueConstraint
from sqlalchemy import Integer, String, DateTime
from sqlalchemy import Column, MetaData, Table, ForeignKey

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    ports = Table('ports', meta, autoload=True, autoload_with=migrate_engine)
    ihost = Table('i_host', meta, autoload=True, autoload_with=migrate_engine)

    lldp_agents = Table(
        'lldp_agents',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('host_id', Integer, ForeignKey('i_host.id',
                                              ondelete='CASCADE')),
        Column('port_id', Integer, ForeignKey('ports.id',
                                              ondelete='CASCADE')),
        Column('status', String(255)),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    lldp_agents.create()

    lldp_neighbours = Table(
        'lldp_neighbours',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('host_id', Integer, ForeignKey('i_host.id',
                                              ondelete='CASCADE')),
        Column('port_id', Integer, ForeignKey('ports.id',
                                              ondelete='CASCADE')),

        Column('msap', String(511), nullable=False),

        UniqueConstraint('msap', 'port_id',
                         name='u_msap_port_id'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    lldp_neighbours.create()

    lldp_tlvs = Table(
        'lldp_tlvs',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('agent_id', Integer,
               ForeignKey('lldp_agents.id', ondelete="CASCADE"),
               nullable=True),
        Column('neighbour_id', Integer,
               ForeignKey('lldp_neighbours.id', ondelete="CASCADE"),
               nullable=True),
        Column('type', String(255)),
        Column('value', String(255)),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    lldp_tlvs.create()


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
