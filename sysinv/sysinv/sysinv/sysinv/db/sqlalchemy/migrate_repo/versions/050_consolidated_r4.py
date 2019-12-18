# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from eventlet.green import subprocess
import json
import tsconfig.tsconfig as tsconfig
from migrate.changeset import UniqueConstraint
from sqlalchemy import Boolean, DateTime, Enum, Integer, String, Text
from sqlalchemy import Column, ForeignKey, MetaData, Table
from sqlalchemy.dialects import postgresql

from oslo_log import log
from sysinv.common import constants

ENGINE = 'InnoDB'
CHARSET = 'utf8'
LOG = log.getLogger(__name__)


def _populate_system_mode(system_table):

    if tsconfig.system_mode is not None:
        mode = tsconfig.system_mode
    else:
        mode = constants.SYSTEM_MODE_DUPLEX

    sys = list(system_table.select().where(
        system_table.c.uuid is not None).execute())
    if len(sys) > 0:
        if sys[0].system_mode is None:
            system_table.update().where(
                system_table.c.uuid == sys[0].uuid).values(
                {'system_mode': mode}).execute()


def _populate_system_timezone(system_table):
    timezone = constants.TIME_ZONE_UTC
    sys = list(system_table.select().where(
        system_table.c.uuid is not None).execute())
    if len(sys) > 0:
        if sys[0].timezone is None:
            system_table.update().where(
                system_table.c.uuid == sys[0].uuid).values(
                {'timezone': timezone}).execute()


def _update_storage_lvm_device_path(storage_lvm):
    storage_lvm.drop_column('cinder_device')


def _update_ceph_mon_device_path(ceph_mon_table):
    # Obtain the ceph mon entry.
    ceph_mon_entry = list(ceph_mon_table.select().execute())

    # If there is no entry in the ceph_mon table, return.
    if not ceph_mon_entry:
        return

    # Update the ceph mon with the corresponding device path.
    device_node = getattr(ceph_mon_entry[0], 'device_path', None)

    if device_node:
        command = ['find', '-L', '/dev/disk/by-path', '-samefile', device_node]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        out, err = process.communicate()
        device_path = out.rstrip()

        ceph_mon_table.update().where(
            ceph_mon_table.c.uuid == ceph_mon_entry[0]['uuid']).values(
            {'device_path': device_path}).execute()


def upgrade(migrate_engine):
    """Perform sysinv database upgrade migrations (release4).
    """

    meta = MetaData()
    meta.bind = migrate_engine
    migrate_engine.connect()

    # 046_drop_iport.py
    i_port = Table('i_port', meta, autoload=True)
    i_port.drop()

    # 047_install_state.py
    i_host = Table('i_host', meta, autoload=True)
    i_host.create_column(Column('install_state', String(255)))
    i_host.create_column(Column('install_state_info', String(255)))

    # 048 Replace services enum with string (include ceph, platform)
    service_parameter = Table('service_parameter',
                              meta,
                              Column('id', Integer,
                                     primary_key=True, nullable=False),
                              mysql_engine=ENGINE, mysql_charset=CHARSET,
                              autoload=True)

    if migrate_engine.url.get_dialect() is postgresql.dialect:
        old_serviceEnum = Enum('identity',
                               'horizon',
                               'ceph',
                               'network',
                               name='serviceEnum')

        service_col = service_parameter.c.service
        service_col.alter(Column('service', String(16)))
        old_serviceEnum.drop(bind=migrate_engine, checkfirst=False)

    # 049_add_controllerfs_scratch.py
    controller_fs = Table('controller_fs', meta, autoload=True)
    controller_fs.create_column(Column('scratch_gib', Integer))
    # 052_add_controllerfs_state.py
    controller_fs.create_column(Column('state', String(255)))

    # 050_services.py
    services = Table(
        'services',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, ),

        Column('name', String(255), nullable=False),
        Column('enabled', Boolean, default=False),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    services.create()
    iservicegroup = Table('i_servicegroup', meta, autoload=True)
    iservicegroup.drop()

    # 051_mtce.py Enhance the services enum to include platform;
    # String per 048

    # 053_add_virtual_interface.py
    Table('interfaces', meta, autoload=True)

    virtual_interfaces = Table(
        'virtual_interfaces',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, ForeignKey('interfaces.id',
                                         ondelete="CASCADE"),
               primary_key=True, nullable=False),

        Column('imac', String(255)),
        Column('imtu', Integer),
        Column('providernetworks', String(255)),
        Column('providernetworksdict', Text),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    virtual_interfaces.create()

    # 054_system_mode.py
    systems = Table('i_system', meta, autoload=True)
    systems.create_column(Column('system_mode', String(255)))
    _populate_system_mode(systems)

    # 055_tpmconfig.py Seed HTTPS disabled capability in i_system table
    # only one system entry should be populated
    sys = list(systems.select().where(
        systems.c.uuid is not None).execute())
    if len(sys) > 0:
        json_dict = json.loads(sys[0].capabilities)
        json_dict['https_enabled'] = 'n'
        systems.update().where(
            systems.c.uuid == sys[0].uuid).values(
            {'capabilities': json.dumps(json_dict)}).execute()

    # Add tpmconfig DB table
    tpmconfig = Table(
        'tpmconfig',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('tpm_path', String(255)),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    tpmconfig.create()

    # Add tpmdevice DB table
    tpmdevice = Table(
        'tpmdevice',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('state', String(255)),
        Column('host_id', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE')),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    tpmdevice.create()

    # 056_ipv_add_failed_status.py
    # Enhance the pv_state enum to include 'failed'
    if migrate_engine.url.get_dialect() is postgresql.dialect:
        i_pv = Table('i_pv',
                     meta,
                     Column('id', Integer, primary_key=True, nullable=False),
                     mysql_engine=ENGINE, mysql_charset=CHARSET,
                     autoload=True)

        migrate_engine.execute('ALTER TABLE i_pv DROP CONSTRAINT "pvStateEnum"')
        # In 16.10, as DB changes by PATCH are not supported, we use 'reserve1' instead of
        # 'failed'. Therefore, even though upgrades with PVs in 'failed' state should not
        # be allowed, we still have to guard against them by converting 'reserve1' to
        # 'failed' everywhere.
        LOG.info("Migrate pv_state")
        migrate_engine.execute('UPDATE i_pv SET pv_state=\'failed\' WHERE pv_state=\'reserve1\'')

        pv_state_col = i_pv.c.pv_state
        pv_state_col.alter(Column('pv_state', String(32)))

    # 057_idisk_id_path_wwn.py
    i_idisk = Table('i_idisk', meta, autoload=True)

    # Add the columns for persistently identifying devices.
    i_idisk.create_column(Column('device_id', String(255)))
    i_idisk.create_column(Column('device_path', String(255)))
    i_idisk.create_column(Column('device_wwn', String(255)))

    # Remove the device_node unique constraint and add a unique constraint for
    # device_path.
    UniqueConstraint('device_node', 'forihostid', table=i_idisk,
                     name='u_devhost').drop()
    UniqueConstraint('device_path', 'forihostid', table=i_idisk,
                     name='u_devhost').create()

    # 058_system_timezone.py
    systems.create_column(Column('timezone', String(255)))
    _populate_system_timezone(systems)

    # 059 N/A

    # 060_disk_device_path.py
    i_pv = Table('i_pv', meta, autoload=True)
    ceph_mon = Table('ceph_mon', meta, autoload=True)
    journal_table = Table('journal', meta, autoload=True)
    storage_lvm = Table('storage_lvm', meta, autoload=True)
    # Update the i_pv table.
    i_pv.create_column(Column('idisk_device_path', String(255)))
    # Update the ceph_mon table.
    col_resource = getattr(ceph_mon.c, 'device_node')
    col_resource.alter(name='device_path')
    _update_ceph_mon_device_path(ceph_mon)
    # Update the journal table.
    col_resource = getattr(journal_table.c, 'device_node')
    col_resource.alter(name='device_path')
    # Update the storage_lvm table.
    _update_storage_lvm_device_path(storage_lvm)

    # 062_iscsi_initiator_name.py
    i_host = Table('i_host', meta, autoload=True)
    i_host.create_column(Column('iscsi_initiator_name', String(64)))


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
