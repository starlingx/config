#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
from sqlalchemy import Column, MetaData, Table
from migrate.changeset import UniqueConstraint

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    """
       This database upgrade removes unused attributes
       from pci_devices and device_labels tables.
    """

    meta = MetaData()
    meta.bind = migrate_engine

    pci_devices = Table('pci_devices', meta, autoload=True)
    pci_devices.drop_column(Column('status'))
    pci_devices.drop_column(Column('needs_firmware_update'))

    device_labels = Table('device_labels', meta, autoload=True)
    device_labels.drop_column(Column('fpgadevice_id'))
    UniqueConstraint('pcidevice_id', 'label_key', table=device_labels,
                     name='u_pcidevice_id@label_key').drop()

    return True


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Downgrade is unsupported.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
