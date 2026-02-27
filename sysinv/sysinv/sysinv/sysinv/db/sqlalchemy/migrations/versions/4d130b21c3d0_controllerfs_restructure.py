#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""controllerfs restructure

Revision ID: 4d130b21c3d0
Revises: 08a4b7b81134
Create Date: 2025-10-08 23:58:30.832222

"""
from typing import Sequence, Union
import uuid
from datetime import datetime

from alembic import op
import sqlalchemy as sa
from oslo_log import log


# revision identifiers, used by Alembic.
revision: str = '4d130b21c3d0'
down_revision: Union[str, None] = '08a4b7b81134'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


LOG = log.getLogger(__name__)


def upgrade():
    """This database upgrade will change the controllerfs table to now have
       one row per filesystem.
    """
    connection = op.get_bind()
    meta = sa.MetaData()

    # Add new columns
    op.add_column('controller_fs', sa.Column('name', sa.String(64)))
    op.add_column('controller_fs', sa.Column('size', sa.Integer()))
    op.add_column('controller_fs', sa.Column('logical_volume', sa.String(64)))
    op.add_column('controller_fs', sa.Column('replicated', sa.Boolean(), default=False))

    controller_fs = sa.Table('controller_fs', meta, autoload_with=connection)

    # Get the first row
    fs = list(connection.execute(controller_fs.select().where(
        controller_fs.c.uuid is not None)))

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
        connection.execute(controller_fs.delete().where(controller_fs.c.uuid is not None))

        # Add the new rows
        if backup_gib > 0:
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
            connection.execute(controller_fs.insert().values(values))

        if cgcs_gib > 0:
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
            connection.execute(controller_fs.insert().values(values))

        if database_gib > 0:
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
            connection.execute(controller_fs.insert().values(values))

        if scratch_gib > 0:
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
            connection.execute(controller_fs.insert().values(values))

        if img_conversions_gib > 0:
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
            connection.execute(controller_fs.insert().values(values))

    # Drop the old columns
    op.drop_column('controller_fs', 'database_gib')
    op.drop_column('controller_fs', 'cgcs_gib')
    op.drop_column('controller_fs', 'img_conversions_gib')
    op.drop_column('controller_fs', 'backup_gib')
    op.drop_column('controller_fs', 'scratch_gib')


def downgrade():
    raise NotImplementedError('SysInv database downgrade is unsupported.')