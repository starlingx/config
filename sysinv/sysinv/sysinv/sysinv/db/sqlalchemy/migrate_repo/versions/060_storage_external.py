# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import uuid
from datetime import datetime

from migrate import ForeignKeyConstraint
from sqlalchemy import Integer, DateTime, Boolean, String
from sqlalchemy import Column, MetaData, Table, ForeignKey, select

from sysinv.openstack.common import log

ENGINE = 'InnoDB'
CHARSET = 'utf8'

LOG = log.getLogger(__name__)


def upgrade(migrate_engine):
    """
       This database upgrade creates a new storage_external table
    """

    meta = MetaData()
    meta.bind = migrate_engine

    storage_backend = Table('storage_backend', meta, autoload=True)

    # Define and create the storage_external table.
    storage_external = Table(
        'storage_external',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer,
               ForeignKey('storage_backend.id', ondelete="CASCADE"),
               primary_key=True, unique=True, nullable=False),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    storage_external.create()


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
