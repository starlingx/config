# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import String
from sysinv.common import constants


def _populate_security_feature(system_table):
    sys = list(system_table.select().where(system_table.c.uuid is not None).execute())
    if len(sys) > 0:
        if sys[0].security_feature is None:
            # TODO - once we support R4/R5 kernel options, this should populate
            # data from R4/R5 version, rather than use default
            system_table.update().where(system_table.c.uuid == sys[0].uuid).\
                values({'security_feature': constants.SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_DEFAULT_OPTS}).execute()


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    i_system = Table('i_system', meta, autoload=True)
    i_system.create_column(Column('security_feature', String(255)))
    _populate_security_feature(i_system)


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
