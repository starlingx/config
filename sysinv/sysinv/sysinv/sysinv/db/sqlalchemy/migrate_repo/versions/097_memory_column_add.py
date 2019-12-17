# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import MetaData, Table, Column
from sqlalchemy import Boolean, Integer

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    memory = Table('i_imemory', meta, autoload=True)
    memoryColPerFlag = Column('vm_pending_as_percentage', Boolean, default=False)
    memoryColPerFlag.create(memory, populate_default=True)

    memoryCol2MPercentage = Column('vm_hugepages_2M_percentage', Integer, default=None)
    memoryCol2MPercentage.create(memory, populate_default=True)

    memoryCol1GPercentage = Column('vm_hugepages_1G_percentage', Integer, default=None)
    memoryCol1GPercentage.create(memory, populate_default=True)

    assert memoryColPerFlag is memory.c.vm_pending_as_percentage
    assert memoryCol2MPercentage is memory.c.vm_hugepages_2M_percentage
    assert memoryCol1GPercentage is memory.c.vm_hugepages_1G_percentage

    return True


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
