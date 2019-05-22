# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import DateTime, String, Integer, Boolean
from sqlalchemy import Column, MetaData, Table

from sysinv.openstack.common import log

ENGINE = 'InnoDB'
CHARSET = 'utf8'

LOG = log.getLogger(__name__)


def upgrade(migrate_engine):
    """
       This database upgrade creates a new table for storing kubenetes
       application info.
    """

    meta = MetaData()
    meta.bind = migrate_engine

    # Define and create the helm_overrides table.
    kube_app = Table(
        'kube_app',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('id', Integer, primary_key=True),
        Column('name', String(255), unique=True, nullable=False),
        Column('app_version', String(255), nullable=False),
        Column('manifest_name', String(255), nullable=False),
        Column('manifest_file', String(255), nullable=True),
        Column('status', String(255), nullable=False),
        Column('progress', String(255), nullable=True),
        Column('active', Boolean, nullable=False, default=False),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    kube_app.create()


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
