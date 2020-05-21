#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import DateTime, String, Integer, Boolean, Text
from sqlalchemy import Column, MetaData, Table
from sqlalchemy import ForeignKey, UniqueConstraint

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    """
       This database upgrade creates a device_images, device_labels and
       device_image_state tables.
    """

    meta = MetaData()
    meta.bind = migrate_engine

    device_images = Table(
        'device_images',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('bitstream_type', String(255)),
        # The pci_vendor and pci_device fields cannot be referenced from the
        # pci_devices table. The device images intended for a specific
        # vendor/device on a subcloud may not be present on the
        # SystemController region
        Column('pci_vendor', String(4)),
        Column('pci_device', String(4)),
        Column('name', String(255)),
        Column('description', String(255)),
        Column('image_version', String(255)),
        Column('applied', Boolean, nullable=False, default=False),
        Column('capabilities', Text),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    device_images_rootkey = Table(
        'device_images_rootkey',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer,
               ForeignKey('device_images.id', ondelete="CASCADE"),
               primary_key=True, nullable=False),

        Column('key_signature', String(255), nullable=False),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    device_images_functional = Table(
        'device_images_functional',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer,
               ForeignKey('device_images.id', ondelete="CASCADE"),
               primary_key=True, nullable=False),

        Column('bitstream_id', String(255), nullable=False),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    device_images_keyrevocation = Table(
        'device_images_keyrevocation',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer,
               ForeignKey('device_images.id', ondelete="CASCADE"),
               primary_key=True, nullable=False),

        Column('revoke_key_id', Integer, nullable=False),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    host = Table('i_host', meta, autoload=True)
    Table('pci_devices', meta, autoload=True)
    Table('fpga_devices', meta, autoload=True)
    device_labels = Table(
        'device_labels',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('host_id', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),
        Column('pcidevice_id', Integer,
               ForeignKey('pci_devices.id', ondelete='CASCADE')),
        Column('fpgadevice_id', Integer,
               ForeignKey('fpga_devices.id', ondelete='CASCADE')),
        Column('label_key', String(384)),
        Column('label_value', String(128)),
        Column('capabilities', Text),

        UniqueConstraint('pcidevice_id', 'label_key',
                         name='u_pcidevice_id@label_key'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    device_image_labels = Table(
        'device_image_labels',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('image_id', Integer,
               ForeignKey('device_images.id', ondelete='CASCADE')),
        Column('label_id', Integer,
               ForeignKey('device_labels.id', ondelete='CASCADE')),
        Column('status', String(128)),
        Column('capabilities', Text),

        UniqueConstraint('image_id', 'label_id', name='u_image_id@label_id'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    device_image_state = Table(
        'device_image_state',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('host_id', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),
        Column('pcidevice_id', Integer,
               ForeignKey('pci_devices.id', ondelete='CASCADE')),
        Column('image_id', Integer,
               ForeignKey('device_images.id', ondelete='CASCADE')),
        Column('status', String(128)),
        Column('update_start_time', DateTime),
        Column('capabilities', Text),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    tables = (
        device_images,
        device_images_rootkey,
        device_images_functional,
        device_images_keyrevocation,
        device_labels,
        device_image_labels,
        device_image_state,
    )

    for index, table in enumerate(tables):
        try:
            table.create()
        except Exception:
            # If an error occurs, drop all tables created so far to return
            # to the previously existing state.
            meta.drop_all(tables=tables[:index])
            raise

    # Add the device_image_update attribute
    host.create_column(Column('device_image_update', String(64)))
    host.create_column(Column('reboot_needed', Boolean, default=False))


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Downgrade is unsupported.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
