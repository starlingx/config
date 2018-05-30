# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2017-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import uuid
from datetime import datetime

from migrate import ForeignKeyConstraint
from sqlalchemy import Integer, DateTime, Boolean, String, Text
from sqlalchemy import Column, MetaData, Table, ForeignKey, select

from sysinv.openstack.common import log

ENGINE = 'InnoDB'
CHARSET = 'utf8'

LOG = log.getLogger(__name__)


def upgrade(migrate_engine):
    """
       This database upgrade creates a new storage_tiers table
    """

    meta = MetaData()
    meta.bind = migrate_engine

    storage_backend = Table('storage_backend', meta, autoload=True)
    storage_backend.create_column(Column('name', String(255)))

    clusters = Table('clusters', meta, autoload=True)

    storage_tiers = Table(
        'storage_tiers',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True, index=True),

        Column('name', String(255), unique=True, index=True),
        Column('type', String(64)),
        Column('status', String(64)),
        Column('capabilities', Text),

        Column('forbackendid', Integer,
               ForeignKey(storage_backend.c.id)),

        Column('forclusterid', Integer,
               ForeignKey(clusters.c.id)),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    storage_tiers.create()

    storage_ceph = Table('storage_ceph', meta, autoload=True)
    storage_ceph.create_column(Column('tier_id', Integer,
                                      ForeignKey('storage_tiers.id'),
                                      nullable=True))

    istor = Table('i_istor', meta, autoload=True)
    istor.create_column(Column('fortierid', Integer,
                               ForeignKey('storage_tiers.id'),
                               nullable=True))


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
