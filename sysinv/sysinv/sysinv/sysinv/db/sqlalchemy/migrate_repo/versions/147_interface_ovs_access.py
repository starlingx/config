# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import Boolean

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    """Perform sysinv database upgrade for network interface
       adding ovs_access column.
    """

    meta = MetaData()
    meta.bind = migrate_engine

    interface = Table('interfaces', meta, autoload=True)
    interface.create_column(Column('ovs_access', Boolean, default=False))


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
