# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import uuid
from datetime import datetime

from migrate import ForeignKeyConstraint
from sqlalchemy import Integer, DateTime
from sqlalchemy import Column, MetaData, String, Table, ForeignKey, select

from sysinv.openstack.common import log
from sysinv.common import constants


ENGINE = 'InnoDB'
CHARSET = 'utf8'

LOG = log.getLogger(__name__)


def _populate_rpm_type(idisk_table):

    disks = list(idisk_table.select().where(
                 idisk_table.c.uuid is not None).execute())
    if len(disks) > 0:
            idisk_table.update().where(idisk_table.c.rpm == None).values(
                {'rpm': constants.DEVICE_TYPE_UNDETERMINED}).execute()


def upgrade(migrate_engine):

    meta = MetaData()
    meta.bind = migrate_engine

    i_idisk = Table('i_idisk', meta, autoload=True)
    i_idisk.create_column(Column('rpm', String(255)))

    _populate_rpm_type(i_idisk)


def downgrade(migrate_engine):
    # Downgrade is unsupported.
    raise NotImplementedError("SysInv database downgrade is unsupported.")
