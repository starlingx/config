########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

# TODO: restore imports
# Story: 2009248
# Task: 43497
# import uuid
# from datetime import datetime

from sqlalchemy import Integer, String, DateTime, Text
from sqlalchemy import Column, MetaData, Table, ForeignKey, UniqueConstraint

from sysinv.db.sqlalchemy.models import UUID_LENGTH

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def _populate_ptp_tables(meta, tables):
    """This function moves PTP configuration from other tables:
       - If advanced (specialized) ptp4l configuration is found in
         'service_parameter' table, it inserts a 'ptp4l' entry in
         'ptp_instances' table and inserts the corresponding entry(ies) in
         'ptp_parameters';
       - If phc2sys configuration is found in 'service_parameter' table, it
         inserts a 'phc2sys' entry in 'ptp_instances' table and inserts the
         corresponding entry(ies) in 'ptp_parameters';
       - If any interface has 'ptp_role' not equal to 'none', it inserts a
         'ptp4l' entry in 'ptp_instances' and inserts the corresponding entry
         in 'ptp_parameters'.
    """

    # TODO: implementation
    # Story: 2009248
    # Task: 43497
    pass


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    tables = {}

    ptp_parameters = Table(
        'ptp_parameters',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(UUID_LENGTH), unique=True),

        Column('name', String(255), nullable=False),
        Column('value', String(255)),

        UniqueConstraint('name', 'value', name='u_paramnamevalue'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    ptp_parameters.create()
    tables.update({'ptp_parameters': ptp_parameters})

    ptp_parameter_owners = Table(
        'ptp_parameter_owners',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(UUID_LENGTH), unique=True),

        Column('type', String(255), nullable=False),

        Column('capabilities', Text),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    ptp_parameter_owners.create()
    tables.update({'ptp_parameter_owners': ptp_parameter_owners})

    ptp_instances = Table(
        'ptp_instances',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer,
               ForeignKey('ptp_parameter_owners.id', ondelete="CASCADE"),
               primary_key=True, nullable=False),

        Column('name', String(255), unique=True, nullable=False),
        Column('service', String(255)),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    ptp_instances.create()
    tables.update({'ptp_instances': ptp_instances})

    ptp_interfaces = Table(
        'ptp_interfaces',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer,
               ForeignKey('ptp_parameter_owners.id', ondelete="CASCADE"),
               primary_key=True, nullable=False),

        Column('ptp_instance_id', Integer,
               ForeignKey('ptp_instances.id', ondelete="CASCADE"),
               nullable=False),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    ptp_interfaces.create()
    tables.update({'ptp_interfaces': ptp_interfaces})

    ptp_parameter_ownerships = Table(
        'ptp_parameter_ownerships',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(UUID_LENGTH), unique=True),

        Column('parameter_uuid', String(UUID_LENGTH),
               ForeignKey('ptp_parameters.uuid', ondelete='CASCADE'),
               nullable=False),
        Column('owner_uuid', String(UUID_LENGTH),
               ForeignKey('ptp_parameter_owners.uuid', ondelete='CASCADE'),
               nullable=False),

        UniqueConstraint('parameter_uuid', 'owner_uuid', name='u_paramowner'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    ptp_parameter_ownerships.create()
    tables.update({'ptp_parameter_ownerships': ptp_parameter_ownerships})

    i_host = Table('i_host', meta, autoload=True)
    tables.update({'i_host': i_host})

    ptp_instance_maps = Table(
        'ptp_instance_maps',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(UUID_LENGTH), unique=True),

        Column('host_id', Integer,
               ForeignKey('i_host.id', ondelete='CASCADE'),
               nullable=False),
        Column('ptp_instance_id', Integer,
               ForeignKey('ptp_instances.id', ondelete='CASCADE'),
               nullable=False),

        UniqueConstraint('host_id', 'ptp_instance_id', name='u_hostinstance'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    ptp_instance_maps.create()
    tables.update({'ptp_instance_maps': ptp_instance_maps})

    interfaces = Table('interfaces', meta, autoload=True)
    tables.update({'interfaces': interfaces})

    ptp_interface_maps = Table(
        'ptp_interface_maps',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(UUID_LENGTH), unique=True),

        Column('interface_id', Integer,
               ForeignKey('interfaces.id', ondelete='CASCADE'),
               nullable=False),
        Column('ptp_interface_id', Integer,
               ForeignKey('ptp_interfaces.id', ondelete='CASCADE'),
               nullable=False),

        UniqueConstraint('interface_id', 'ptp_interface_id',
                         name='u_ifaceptpiface'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    ptp_interface_maps.create()
    tables.update({'ptp_interface_maps': ptp_interface_maps})

    _populate_ptp_tables(meta, tables)


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    ptp_interface_maps = Table('ptp_interface_maps', meta, autoload=True)
    ptp_interface_maps.drop()

    ptp_instance_maps = Table('ptp_instance_maps', meta, autoload=True)
    ptp_instance_maps.drop()

    ptp_parameter_ownerships = Table('ptp_parameter_ownerships',
                                     meta,
                                     autoload=True)
    ptp_parameter_ownerships.drop()

    ptp_interfaces = Table('ptp_interfaces', meta, autoload=True)
    ptp_interfaces.drop()

    ptp_instances = Table('ptp_instances', meta, autoload=True)
    ptp_instances.drop()

    ptp_parameter_owners = Table('ptp_parameter_owners', meta, autoload=True)
    ptp_parameter_owners.drop()

    ptp_parameters = Table('ptp_parameters', meta, autoload=True)
    ptp_parameters.drop()
