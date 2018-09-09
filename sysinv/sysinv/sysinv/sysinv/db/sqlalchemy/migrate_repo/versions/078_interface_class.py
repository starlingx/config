# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import String
from sysinv.openstack.common import log

ENGINE = 'InnoDB'
CHARSET = 'utf8'
LOG = log.getLogger(__name__)


def upgrade(migrate_engine):
    """Perform sysinv database upgrade for network interface
    """

    meta = MetaData()
    meta.bind = migrate_engine

    interface = Table('interfaces', meta, autoload=True)
    interface.create_column(Column('ifclass', String(255)))


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
