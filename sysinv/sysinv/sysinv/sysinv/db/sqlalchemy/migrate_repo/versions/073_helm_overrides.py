# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import DateTime, String, Text
from sqlalchemy import Column, MetaData, Table

from sysinv.openstack.common import log

ENGINE = 'InnoDB'
CHARSET = 'utf8'

LOG = log.getLogger(__name__)


def upgrade(migrate_engine):
    """
       This database upgrade creates a new table for storing helm chart
       user-specified override values.
    """

    meta = MetaData()
    meta.bind = migrate_engine

    # Define and create the helm_overrides table.
    helm_overrides = Table(
        'helm_overrides',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('name', String(255), unique=True, index=True),
        Column('user_overrides', Text, nullable=True),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    helm_overrides.create()


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
