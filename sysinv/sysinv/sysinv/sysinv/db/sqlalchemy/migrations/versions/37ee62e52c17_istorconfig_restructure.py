#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""istorconfig restructure

Revision ID: 37ee62e52c17
Revises: 52b3a43ae54b
Create Date: 2025-10-07 08:39:58.996454

"""
from typing import Sequence, Union
import uuid
from datetime import datetime

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '37ee62e52c17'
down_revision: Union[str, None] = '52b3a43ae54b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    """This database upgrade replaces the i_storconfig table with five
       tables: controller_fs, storage_backend, storage_ceph, storage_lvm,
       ceph_mon.
    """
    connection = op.get_bind()
    meta = sa.MetaData()

    # Create controller_fs table
    op.create_table('controller_fs',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('database_gib', sa.Integer()),
        sa.Column('cgcs_gib', sa.Integer()),
        sa.Column('img_conversions_gib', sa.Integer()),
        sa.Column('backup_gib', sa.Integer()),
        sa.Column('forisystemid', sa.Integer(), sa.ForeignKey('i_system.id', ondelete='CASCADE')),
    )

    # Create storage_backend table
    op.create_table('storage_backend',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('backend', sa.String(255)),
        sa.Column('state', sa.String(255)),
        sa.Column('task', sa.String(255)),
        sa.Column('forisystemid', sa.Integer(), sa.ForeignKey('i_system.id', ondelete='CASCADE')),
    )

    # Create storage_lvm table
    op.create_table('storage_lvm',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), sa.ForeignKey('storage_backend.id', ondelete='CASCADE'), primary_key=True, unique=True, nullable=False),
        sa.Column('cinder_device', sa.String(255)),
        sa.Column('cinder_gib', sa.Integer()),
    )

    # Create storage_ceph table
    op.create_table('storage_ceph',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), sa.ForeignKey('storage_backend.id', ondelete='CASCADE'), primary_key=True, unique=True, nullable=False),
        sa.Column('cinder_pool_gib', sa.Integer()),
        sa.Column('glance_pool_gib', sa.Integer()),
        sa.Column('ephemeral_pool_gib', sa.Integer()),
        sa.Column('object_pool_gib', sa.Integer()),
        sa.Column('object_gateway', sa.Boolean(), default=False),
    )

    # Create ceph_mon table
    op.create_table('ceph_mon',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(), primary_key=True, nullable=False),
        sa.Column('uuid', sa.String(36), unique=True),
        sa.Column('device_node', sa.String(255)),
        sa.Column('ceph_mon_gib', sa.Integer()),
        sa.Column('forihostid', sa.Integer(), sa.ForeignKey('i_host.id', ondelete='CASCADE')),
    )

    # Move the data from the i_storconfig table to the new tables
    i_host = sa.Table('i_host', meta, autoload_with=connection)
    i_storconfig = sa.Table('i_storconfig', meta, autoload_with=connection)
    storage_backend = sa.Table('storage_backend', meta, autoload_with=connection)
    storage_lvm = sa.Table('storage_lvm', meta, autoload_with=connection)
    storage_ceph = sa.Table('storage_ceph', meta, autoload_with=connection)
    controller_fs = sa.Table('controller_fs', meta, autoload_with=connection)
    ceph_mon = sa.Table('ceph_mon', meta, autoload_with=connection)

    # Obtain the i_storconfig entries
    storcfg_items = list(connection.execute(i_storconfig.select()))

    # If there are two entries in the i_storconfig table, then it means that
    # Ceph backend was added over LVM
    lvm_and_ceph = False
    if len(storcfg_items) > 1:
        lvm_and_ceph = True

    if storcfg_items:
        for storcfg in storcfg_items:
            # Populate the storage_backend table
            storage_backend_uuid = str(uuid.uuid4())
            values = {'created_at': datetime.now(),
                      'updated_at': None,
                      'deleted_at': None,
                      'uuid': storage_backend_uuid,
                      'backend': storcfg['cinder_backend'],
                      'state': storcfg['state'],
                      'task': storcfg['task'],
                      'forisystemid': storcfg['forisystemid'],
                      }
            connection.execute(storage_backend.insert().values(values))

            # Get the id of the new storage_backend entry
            new_stor_id_sel = sa.select([storage_backend]).where(
                storage_backend.c.uuid == storage_backend_uuid)
            new_stor_id = connection.execute(new_stor_id_sel).fetchone()['id']

            # Populate the storage_lvm table
            if storcfg['cinder_backend'] == 'lvm':
                values = {'created_at': datetime.now(),
                          'updated_at': None,
                          'deleted_at': None,
                          'id': new_stor_id,
                          'cinder_device': storcfg['cinder_device'],
                          'cinder_gib': storcfg['cinder_gib'],
                          }
                connection.execute(storage_lvm.insert().values(values))

            # Populate the storage_ceph table
            if storcfg['cinder_backend'] == 'ceph':
                if (storcfg['cinder_pool_gib'] or
                        storcfg['glance_pool_gib'] or
                        storcfg['ephemeral_pool_gib']):
                    values = {'created_at': datetime.now(),
                              'updated_at': None,
                              'deleted_at': None,
                              'id': new_stor_id,
                              'cinder_pool_gib': storcfg['cinder_pool_gib'],
                              'glance_pool_gib': storcfg['glance_pool_gib'],
                              'ephemeral_pool_gib': storcfg['ephemeral_pool_gib'],
                              'object_pool_gib': 0,
                              'object_gateway': False,
                              }
                    connection.execute(storage_ceph.insert().values(values))

            # Populate the controller_fs table
            fill_storage = True
            if lvm_and_ceph and storcfg['cinder_backend'] == 'ceph':
                fill_storage = False

            if fill_storage:
                controller_fs_uuid = str(uuid.uuid4())
                values = {'created_at': datetime.now(),
                          'updated_at': None,
                          'deleted_at': None,
                          'uuid': controller_fs_uuid,
                          'database_gib': storcfg['database_gib'],
                          'cgcs_gib': storcfg['image_gib'],
                          'img_conversions_gib': storcfg['img_conversions_gib'],
                          'backup_gib': storcfg['backup_gib'],
                          'forisystemid': storcfg['forisystemid'],
                          }
                connection.execute(controller_fs.insert().values(values))

            # Populate the ceph_mon table
            if storcfg['cinder_backend'] == 'ceph':
                if (storcfg['ceph_mon_dev_ctrl0'] and
                        storcfg['ceph_mon_dev_ctrl1'] and
                        storcfg['ceph_mon_gib']):
                    ctrl0_id_sel = sa.select([i_host]).where(i_host.c.hostname == 'controller-0')
                    ctrl0_id = connection.execute(ctrl0_id_sel).fetchone()['id']
                    ctrl1_id_sel = sa.select([i_host]).where(i_host.c.hostname == 'controller-1')
                    ctrl1_id = connection.execute(ctrl1_id_sel).fetchone()['id']

                    values0 = {'created_at': datetime.now(),
                               'updated_at': None,
                               'deleted_at': None,
                               'uuid': str(uuid.uuid4()),
                               'device_node': storcfg['ceph_mon_dev_ctrl0'],
                               'ceph_mon_gib': storcfg['ceph_mon_gib'],
                               'forihostid': ctrl0_id,
                               }

                    values1 = {'created_at': datetime.now(),
                               'updated_at': None,
                               'deleted_at': None,
                               'uuid': str(uuid.uuid4()),
                               'device_node': storcfg['ceph_mon_dev_ctrl1'],
                               'ceph_mon_gib': storcfg['ceph_mon_gib'],
                               'forihostid': ctrl1_id,
                               }

                    connection.execute(ceph_mon.insert().values(values0))
                    connection.execute(ceph_mon.insert().values(values1))

    # Delete the i_storconfig table
    op.drop_table('i_storconfig')


def downgrade():
    raise NotImplementedError('SysInv database downgrade is unsupported.')
