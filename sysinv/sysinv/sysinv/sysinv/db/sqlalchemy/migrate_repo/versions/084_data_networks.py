# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import DateTime, Integer, String
from sqlalchemy import ForeignKey, UniqueConstraint
from sysinv.common import constants

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    Table('interfaces', meta, autoload=True)

    datanetworks = Table(
        'datanetworks',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('name', String(255), unique=True),
        Column('network_type', String(255)),
        Column('description', String(255)),
        Column('mtu', Integer, nullable=False),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    datanetworks_flat = Table(
        'datanetworks_flat',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer,
               ForeignKey('datanetworks.id', ondelete="CASCADE"),
               primary_key=True, nullable=False),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    datanetworks_vlan = Table(
        'datanetworks_vlan',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer,
               ForeignKey('datanetworks.id', ondelete="CASCADE"),
               primary_key=True, nullable=False),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    datanetworks_vxlan = Table(
        'datanetworks_vxlan',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer,
               ForeignKey('datanetworks.id', ondelete="CASCADE"),
               primary_key=True, nullable=False),

        Column('multicast_group', String(64), nullable=True),
        Column('port_num', Integer, nullable=False),
        Column('ttl', Integer, nullable=False),
        Column('mode', String(32), nullable=False,
               default=constants.DATANETWORK_MODE_DYNAMIC),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    interface_datanetworks = Table(
        'interface_datanetworks',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('interface_id', Integer,
               ForeignKey('interfaces.id', ondelete='CASCADE')),
        Column('datanetwork_id', Integer,
               ForeignKey('datanetworks.id', ondelete='CASCADE')),

        UniqueConstraint('interface_id', 'datanetwork_id',
                         name='u_interface_id@datanetwork_id'),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    tables = (
        datanetworks,
        datanetworks_flat,
        datanetworks_vlan,
        datanetworks_vxlan,
        interface_datanetworks,
    )

    for index, table in enumerate(tables):
        try:
            table.create()
        except Exception:
            # If an error occurs, drop all tables created so far to return
            # to the previously existing state.
            meta.drop_all(tables=tables[:index])
            raise

    ethernet_interfaces = Table('ethernet_interfaces', meta, autoload=True)
    ethernet_interfaces.drop_column('providernetworks')
    ethernet_interfaces.drop_column('providernetworksdict')

    ae_interfaces = Table('ae_interfaces', meta, autoload=True)
    ae_interfaces.drop_column('providernetworks')
    ae_interfaces.drop_column('providernetworksdict')

    vlan_interfaces = Table('vlan_interfaces', meta, autoload=True)
    vlan_interfaces.drop_column('providernetworks')
    vlan_interfaces.drop_column('providernetworksdict')

    virtual_interfaces = Table('virtual_interfaces', meta, autoload=True)
    virtual_interfaces.drop_column('providernetworks')
    virtual_interfaces.drop_column('providernetworksdict')


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
