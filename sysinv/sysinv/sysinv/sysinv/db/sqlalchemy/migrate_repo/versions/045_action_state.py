# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import Table

from sysinv.openstack.common import log

ENGINE = 'InnoDB'
CHARSET = 'utf8'

LOG = log.getLogger(__name__)


def upgrade(migrate_engine):
    """This database upgrade updates the i_host table with the
       action_state and mtce_info attributes.
       The action_state is to track sysinv host action_state, such
       as resinstall.
       The mtce_info attribute is a mtce-only attribute for mtce usage.
    """

    meta = MetaData()
    meta.bind = migrate_engine
    migrate_engine.connect()

    i_host = Table('i_host', meta, autoload=True)
    i_host.create_column(Column('action_state', String(255)))
    i_host.create_column(Column('mtce_info', String(255)))


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
