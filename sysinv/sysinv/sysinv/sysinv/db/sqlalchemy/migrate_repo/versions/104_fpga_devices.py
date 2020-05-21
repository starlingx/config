#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import String, Integer, DateTime, Boolean
from sqlalchemy import ForeignKey, UniqueConstraint


ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    Table('i_host', meta, autoload=True)
    pci_devices = Table('pci_devices', meta, autoload=True)

    fpga_devices = Table(
        'fpga_devices',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('host_id', Integer, ForeignKey('i_host.id',
                                              ondelete='CASCADE')),
        Column('pci_id', Integer, ForeignKey('pci_devices.id',
                                              ondelete='CASCADE')),

        Column('pciaddr', String(32)),
        Column('bmc_build_version', String(32)),
        Column('bmc_fw_version', String(32)),
        Column('root_key', String(128)),
        Column('revoked_key_ids', String(512)),
        Column('boot_page', String(16)),
        Column('bitstream_id', String(32)),

        UniqueConstraint('pciaddr', 'host_id', name='u_pciaddrhost'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    fpga_devices.create()

    Table('ports', meta, autoload=True)

    fpga_ports = Table(
        'fpga_ports',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),
        Column('port_id', Integer, ForeignKey('ports.id', ondelete='CASCADE')),
        Column('fpga_id', Integer, ForeignKey('fpga_devices.id', ondelete='CASCADE')),
        UniqueConstraint('port_id', 'fpga_id', name='u_port_id@fpga_id'),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    fpga_ports.create()

    # Add new fields to pci_device table
    pci_devices.create_column(Column('status', String(128)))
    pci_devices.create_column(Column('needs_firmware_update', Boolean, default=False))


def downgrade(migrate_engine):
    # Downgrade is unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
