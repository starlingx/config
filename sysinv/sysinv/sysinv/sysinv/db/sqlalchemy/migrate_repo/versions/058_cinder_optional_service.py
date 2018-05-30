# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from migrate import ForeignKeyConstraint
from sqlalchemy import Integer, DateTime, Boolean, String, Text
from sqlalchemy import Column, MetaData, Table, ForeignKey, select

from sysinv.openstack.common import log

import json

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):

    meta = MetaData()
    meta.bind = migrate_engine

    i_idisk = Table('i_idisk', meta, autoload=True)
    storage_lvm = Table('storage_lvm', meta, autoload=True)
    storage_backend = Table('storage_backend', meta, autoload=True)

    # Remove cinder_gib parameter.
    # Save it in the idisk capabilities first.

    storage_lvm_entry = list(storage_lvm.select().execute())

    if len(storage_lvm_entry) > 0:
        cinder_gib = storage_lvm_entry[0]['cinder_gib']
        idisks = list(i_idisk.select().execute())

        for idisk in idisks:
            capabilities = json.loads(idisk.capabilities)
            if ('device_function' in capabilities and
                    capabilities['device_function'] == 'cinder_device'):
                capabilities['cinder_gib'] = cinder_gib

                i_idisk.update().where(
                    i_idisk.c.uuid == idisk['uuid']).values(
                    {'capabilities': json.dumps(capabilities)}).execute()

    storage_lvm.drop_column('cinder_gib')

    # Define and create the storage_file table.
    storage_file = Table(
        'storage_file',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer,
               ForeignKey('storage_backend.id', ondelete="CASCADE"),
               primary_key=True, unique=True, nullable=False),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    storage_file.create()

    storage_backend.create_column(Column('services', Text))
    storage_backend.create_column(Column('capabilities', Text))


def downgrade(migrate_engine):
    # Downgrade is unsupported.
    raise NotImplementedError("SysInv database downgrade is unsupported.")
