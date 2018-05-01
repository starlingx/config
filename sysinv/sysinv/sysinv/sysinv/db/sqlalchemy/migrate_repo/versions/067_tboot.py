# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import String


def _populate_tboot(host_table):
    host_list = list(host_table.select().where(host_table.c.uuid is not None).execute())
    if len(host_list) > 0:
        # tboot option must be selected at install time, otherwise it risks
        # disabling existing systems with secure boot.  Use empty string for
        # migrated hosts
        tboot_value = ''
        for host in host_list:
            host_table.update().where(host_table.c.uuid == host.uuid).\
                values({'tboot': tboot_value}).execute()


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    host_table = Table('i_host', meta, autoload=True)
    host_table.create_column(Column('tboot', String(64)))
    _populate_tboot(host_table)


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
