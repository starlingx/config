# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import String
import tsconfig.tsconfig as tsconfig
from sysinv.common import constants


def _populate_system_type(system_table):

    if constants.COMPUTE in tsconfig.subfunctions:
        s_type = constants.TIS_AIO_BUILD
    else:
        s_type = constants.TIS_STD_BUILD

    sys = list(system_table.select().where(system_table.c.uuid is not None).execute())
    if len(sys) > 0:
        if sys[0].system_type is None:
            system_table.update().where(system_table.c.uuid == sys[0].uuid).values({'system_type': s_type}).execute()


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    i_system = Table('i_system', meta, autoload=True)
    i_system.create_column(Column('system_type', String(255)))
    _populate_system_type(i_system)


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
