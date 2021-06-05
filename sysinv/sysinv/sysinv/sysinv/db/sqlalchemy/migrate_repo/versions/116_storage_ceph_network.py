#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import Table

from sysinv.common import constants

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # add network to storage_ceph table
    storage_ceph = Table(
        'storage_ceph',
        meta,
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
        autoload=True)

    col = Column('network', String(255), nullable=True, default=constants.NETWORK_TYPE_MGMT)
    col.create(storage_ceph)
    col.alter(nullable=False)


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
