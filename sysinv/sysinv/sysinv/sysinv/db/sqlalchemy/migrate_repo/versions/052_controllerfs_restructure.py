# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import uuid
from datetime import datetime
from sqlalchemy import Integer, Boolean, String
from sqlalchemy import Column, MetaData, Table

from oslo_log import log

ENGINE = 'InnoDB'
CHARSET = 'utf8'

LOG = log.getLogger(__name__)


def upgrade(migrate_engine):
    """This database upgrade will change the controllerfs table to now have
       one row per filesystem.
    """
    meta = MetaData()
    meta.bind = migrate_engine

    controller_fs = Table('controller_fs', meta, autoload=True)

    # Create new columns
    controller_fs.create_column(Column('name', String(64)))
    controller_fs.create_column(Column('size', Integer))
    controller_fs.create_column(Column('logical_volume', String(64)))
    controller_fs.create_column(Column('replicated', Boolean, default=False))

    # Get the first row
    fs = list(controller_fs.select().where(
        controller_fs.c.uuid is not None).execute())

    if len(fs) > 0:
        # If there is data in the table then migrate it
        database_gib = fs[0].database_gib
        cgcs_gib = fs[0].cgcs_gib
        img_conversions_gib = fs[0].img_conversions_gib
        backup_gib = fs[0].backup_gib
        scratch_gib = fs[0].scratch_gib
        forisystemid = fs[0].forisystemid

        LOG.info("Migrate the controllerfs table, database_gib=%s, "
                 "cgcs_gib=%s, img_conversions_gib=%s, backup_gib=%s, "
                 "scratch_gib=%s" %
                 (database_gib, cgcs_gib, img_conversions_gib, backup_gib,
                  scratch_gib))

        # Delete the original row
        controller_fs_delete = controller_fs.delete(
            controller_fs.c.uuid is not None)
        controller_fs_delete.execute()

        # Add the new rows
        if backup_gib > 0:
            controller_fs_insert = controller_fs.insert()  # pylint: disable=no-value-for-parameter
            controller_fs_uuid = str(uuid.uuid4())
            values = {'created_at': datetime.now(),
                      'updated_at': None,
                      'deleted_at': None,
                      'uuid': controller_fs_uuid,
                      'name': 'backup',
                      'size': backup_gib,
                      'replicated': False,
                      'logical_volume': 'backup-lv',
                      'forisystemid': forisystemid,
                      }
            controller_fs_insert.execute(values)

        if cgcs_gib > 0:
            controller_fs_insert = controller_fs.insert()  # pylint: disable=no-value-for-parameter
            controller_fs_uuid = str(uuid.uuid4())
            values = {'created_at': datetime.now(),
                      'updated_at': None,
                      'deleted_at': None,
                      'uuid': controller_fs_uuid,
                      'name': 'cgcs',
                      'size': cgcs_gib,
                      'replicated': True,
                      'logical_volume': 'cgcs-lv',
                      'forisystemid': forisystemid,
                      }
            controller_fs_insert.execute(values)

        if database_gib > 0:
            controller_fs_insert = controller_fs.insert()  # pylint: disable=no-value-for-parameter
            controller_fs_uuid = str(uuid.uuid4())
            values = {'created_at': datetime.now(),
                      'updated_at': None,
                      'deleted_at': None,
                      'uuid': controller_fs_uuid,
                      'name': 'database',
                      'size': database_gib,
                      'replicated': True,
                      'logical_volume': 'pgsql-lv',
                      'forisystemid': forisystemid,
                      }
            controller_fs_insert.execute(values)

        if scratch_gib > 0:
            controller_fs_insert = controller_fs.insert()  # pylint: disable=no-value-for-parameter
            controller_fs_uuid = str(uuid.uuid4())
            values = {'created_at': datetime.now(),
                      'updated_at': None,
                      'deleted_at': None,
                      'uuid': controller_fs_uuid,
                      'name': 'scratch',
                      'size': scratch_gib,
                      'replicated': False,
                      'logical_volume': 'scratch-lv',
                      'forisystemid': forisystemid,
                      }
            controller_fs_insert.execute(values)

        if img_conversions_gib > 0:
            controller_fs_insert = controller_fs.insert()  # pylint: disable=no-value-for-parameter
            controller_fs_uuid = str(uuid.uuid4())
            values = {'created_at': datetime.now(),
                      'updated_at': None,
                      'deleted_at': None,
                      'uuid': controller_fs_uuid,
                      'name': 'img-conversions',
                      'size': img_conversions_gib,
                      'replicated': False,
                      'logical_volume': 'img-conversions-lv',
                      'forisystemid': forisystemid,
                      }
            controller_fs_insert.execute(values)

    # Drop the old columns
    controller_fs.drop_column('database_gib')
    controller_fs.drop_column('cgcs_gib')
    controller_fs.drop_column('img_conversions_gib')
    controller_fs.drop_column('backup_gib')
    controller_fs.drop_column('scratch_gib')


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
