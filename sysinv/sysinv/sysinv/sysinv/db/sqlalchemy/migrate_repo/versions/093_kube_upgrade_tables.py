# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import DateTime, String, Integer
from sqlalchemy import Column, MetaData, Table, ForeignKey

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    """
       This database upgrade creates a new kube_upgrade and kube_host_upgrade
       tables for storing kubernetes upgrade info.
    """

    meta = MetaData()
    meta.bind = migrate_engine

    kube_upgrade = Table(
        'kube_upgrade',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('from_version', String(255)),
        Column('to_version', String(255)),
        Column('state', String(128)),
        Column('reserved_1', String(255)),
        Column('reserved_2', String(255)),
        Column('reserved_3', String(255)),
        Column('reserved_4', String(255)),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    kube_upgrade.create()

    Table('i_host',
          meta,
          Column('id', Integer, primary_key=True, nullable=False),
          mysql_engine=ENGINE, mysql_charset=CHARSET, autoload=True)

    kube_host_upgrade = Table(
        'kube_host_upgrade',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('target_version', String(255)),
        Column('status', String(128)),
        Column('reserved_1', String(255)),
        Column('reserved_2', String(255)),
        Column('reserved_3', String(255)),
        Column('reserved_4', String(255)),

        Column('host_id', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    kube_host_upgrade.create()


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Downgrade is unsupported.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
