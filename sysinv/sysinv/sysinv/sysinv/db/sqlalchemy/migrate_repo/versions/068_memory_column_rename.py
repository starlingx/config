# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import MetaData, Table

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    memory = Table('i_imemory', meta, autoload=True)
    memory.c.avs_hugepages_size_mib.alter(name="vswitch_hugepages_size_mib")
    memory.c.avs_hugepages_reqd.alter(name="vswitch_hugepages_reqd")
    memory.c.avs_hugepages_nr.alter(name="vswitch_hugepages_nr")
    memory.c.avs_hugepages_avail.alter(name="vswitch_hugepages_avail")
    return True


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
