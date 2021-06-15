#
# Copyright (c) 2020 Intel Corporation, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import ForeignKey
from sqlalchemy import Integer
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import Table
from sqlalchemy import Text

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    """
       This database upgrade creates a new kube_rootca_update
       table and a new kube_rootca_host_update table
    """

    meta = MetaData()
    meta.bind = migrate_engine

    Table('i_host', meta, autoload=True)

    # Define and create the kube_rootca_update table.
    kube_rootca_update = Table(
        'kube_rootca_update',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True,
               unique=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('from_rootca_cert', String(255)),
        Column('to_rootca_cert', String(255)),
        Column('state', String(255)),
        Column('capabilities', Text),
        Column('reserved_1', String(255)),
        Column('reserved_2', String(255)),
        Column('reserved_3', String(255)),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    kube_rootca_update.create()

    kube_rootca_host_update = Table(
        'kube_rootca_host_update',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True,
               unique=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('target_rootca_cert', String(255)),
        Column('effective_rootca_cert', String(255)),
        Column('state', String(255)),
        Column('host_id', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),
        Column('capabilities', Text),
        Column('reserved_1', String(255)),
        Column('reserved_2', String(255)),
        Column('reserved_3', String(255)),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    kube_rootca_host_update.create()


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
