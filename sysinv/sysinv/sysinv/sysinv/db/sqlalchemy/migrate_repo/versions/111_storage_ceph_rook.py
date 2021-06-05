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

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    """
       This database upgrade creates a new storage_ceph_rook table
    """

    meta = MetaData()
    meta.bind = migrate_engine

    Table('storage_backend', meta, autoload=True)

    # Define and create the storage_ceph_rook table.
    storage_ceph_rook = Table(
        'storage_ceph_rook',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer,
               ForeignKey('storage_backend.id', ondelete="CASCADE"),
               primary_key=True, unique=True, nullable=False),
        Column('ceph_conf', String(255), unique=True, index=True),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    storage_ceph_rook.create()


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
