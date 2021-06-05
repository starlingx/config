# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import uuid
from datetime import datetime

from sqlalchemy import Integer, DateTime, Boolean, String
from sqlalchemy import Column, MetaData, Table, ForeignKey, select

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    """This database upgrade replaces the i_istorconfig table with five
       tables: controller_fs, storage_backend, storage_ceph, storage_lvm,
       ceph_mon.
    """

    meta = MetaData()
    meta.bind = migrate_engine
    conn = migrate_engine.connect()

    i_host = Table('i_host', meta, autoload=True)
    i_system = Table('i_system', meta, autoload=True)

    # Define and create the controller_fs table.
    controller_fs = Table(
        'controller_fs',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('database_gib', Integer),
        Column('cgcs_gib', Integer),
        Column('img_conversions_gib', Integer),
        Column('backup_gib', Integer),
        Column('forisystemid', Integer,
               ForeignKey(i_system.c.id, ondelete='CASCADE')),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    controller_fs.create()

    # Define and create the storage_backend table.
    storage_backend = Table(
        'storage_backend',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('backend', String(255)),
        Column('state', String(255)),
        Column('task', String(255)),
        Column('forisystemid', Integer,
               ForeignKey(i_system.c.id, ondelete='CASCADE')),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    storage_backend.create()

    # Define and create the storage_lvm table.
    storage_lvm = Table(
        'storage_lvm',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer,
               ForeignKey('storage_backend.id', ondelete="CASCADE"),
               primary_key=True, unique=True, nullable=False),
        Column('cinder_device', String(255)),
        Column('cinder_gib', Integer),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    storage_lvm.create()

    # Define and create the storage_ceph table.
    storage_ceph = Table(
        'storage_ceph',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer,
               ForeignKey('storage_backend.id', ondelete="CASCADE"),
               primary_key=True, unique=True, nullable=False),
        Column('cinder_pool_gib', Integer),
        Column('glance_pool_gib', Integer),
        Column('ephemeral_pool_gib', Integer),
        Column('object_pool_gib', Integer),
        Column('object_gateway', Boolean, default=False),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    storage_ceph.create()

    # Define and create the ceph_mon table.
    ceph_mon = Table(
        'ceph_mon',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('device_node', String(255)),
        Column('ceph_mon_gib', Integer),
        Column('forihostid', Integer,
               ForeignKey(i_host.c.id, ondelete='CASCADE')),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    ceph_mon.create()

    # Move the data from the i_storconfig table to the new tables.
    i_storconfig = Table('i_storconfig', meta, autoload=True)

    # Obtain the i_storconfig entries.
    storcfg_items = list(i_storconfig.select().execute())

    # If there are two entries in the i_storconfig table, then it means that
    # Ceph backend was added over LVM.
    lvm_and_ceph = False
    if len(storcfg_items) > 1:
        lvm_and_ceph = True

    if storcfg_items:
        for storcfg in storcfg_items:

            # Populate the storage_backend table.
            storage_backend_insert = storage_backend.insert()  # pylint: disable=no-value-for-parameter
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
            storage_backend_insert.execute(values)

            # Get the id of the new storage_backend entry.
            new_stor_id_sel = select([storage_backend]).where(
                storage_backend.c.uuid == storage_backend_uuid)
            new_stor_id = conn.execute(new_stor_id_sel).fetchone()['id']

            # Populate the storage_lvm table.
            if storcfg['cinder_backend'] == 'lvm':
                storage_lvm_insert = storage_lvm.insert()  # pylint: disable=no-value-for-parameter

                values = {'created_at': datetime.now(),
                          'updated_at': None,
                          'deleted_at': None,
                          'id': new_stor_id,
                          'cinder_device': storcfg['cinder_device'],
                          'cinder_gib': storcfg['cinder_gib'],
                          }
                storage_lvm_insert.execute(values)

            # Populate the storage_ceph table.
            # Do this only if the backend of the current item is ceph.
            if storcfg['cinder_backend'] == 'ceph':
                if (storcfg['cinder_pool_gib'] or
                        storcfg['glance_pool_gib'] or
                        storcfg['ephemeral_pool_gib']):

                    storage_ceph_insert = storage_ceph.insert()  # pylint: disable=no-value-for-parameter
                    values = {'created_at': datetime.now(),
                              'updated_at': None,
                              'deleted_at': None,
                              'id': new_stor_id,
                              'cinder_pool_gib': storcfg['cinder_pool_gib'],
                              'glance_pool_gib': storcfg['glance_pool_gib'],
                              'ephemeral_pool_gib': storcfg[
                                  'ephemeral_pool_gib'],
                              'object_pool_gib': 0,
                              'object_gateway': False,
                              }
                    storage_ceph_insert.execute(values)

            # Populate the controller_fs table.
            # If Ceph was added over LVM, we need to take the data for
            # controller_fs from the LVM i_storconfig entry.
            fill_storage = True
            if lvm_and_ceph and storcfg['cinder_backend'] == 'ceph':
                fill_storage = False

            if fill_storage:
                controller_fs_insert = controller_fs.insert()  # pylint: disable=no-value-for-parameter
                controller_fs_uuid = str(uuid.uuid4())

                values = {'created_at': datetime.now(),
                          'updated_at': None,
                          'deleted_at': None,
                          'uuid': controller_fs_uuid,
                          'database_gib': storcfg['database_gib'],
                          'cgcs_gib': storcfg['image_gib'],
                          'img_conversions_gib': storcfg[
                              'img_conversions_gib'],
                          'backup_gib': storcfg['backup_gib'],
                          'forisystemid': storcfg['forisystemid'],
                          }
                controller_fs_insert.execute(values)

            # Populate the ceph_mon table.
            if storcfg['cinder_backend'] == 'ceph':
                if (storcfg['ceph_mon_dev_ctrl0'] and
                        storcfg['ceph_mon_dev_ctrl1'] and
                        storcfg['ceph_mon_gib']):
                    ceph_mon_insert_ctrl0 = ceph_mon.insert()  # pylint: disable=no-value-for-parameter
                    ceph_mon_insert_ctrl1 = ceph_mon.insert()  # pylint: disable=no-value-for-parameter

                    ctrl0_id_sel = select([i_host]).where(
                        i_host.c.hostname == 'controller-0')
                    ctrl0_id = conn.execute(ctrl0_id_sel).fetchone()['id']
                    ctrl1_id_sel = select([i_host]).where(
                        i_host.c.hostname == 'controller-1')
                    ctrl1_id = conn.execute(ctrl1_id_sel).fetchone()['id']

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

                    ceph_mon_insert_ctrl0.execute(values0)
                    ceph_mon_insert_ctrl1.execute(values1)

    # Delete the i_storconfig table.
    i_storconfig.drop()


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
