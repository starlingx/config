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


def _populate_ptp_tables(meta, ptp_instances, ptp_interfaces,
                         ptp_parameters, ptp_parameter_ownerships):
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

    ptp_parameters = Table(
        'ptp_parameters',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(UUID_LENGTH), unique=True),

        Column('name', String(255), unique=True, nullable=False),
        Column('value', String(255)),

        UniqueConstraint('name', 'value', name='u_paramnamevalue'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    ptp_parameters.create()

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

    host = Table('i_host', meta, autoload=True)
    host.create_column(
        Column('ptp_instance_id', Integer, ForeignKey('ptp_instances.id')))

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

    interface = Table('interfaces', meta, autoload=True)
    interface.create_column(
        Column('ptp_interface_id', Integer, ForeignKey('ptp_interfaces.id')))

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
        Column('owner_uuid', String(UUID_LENGTH), nullable=False),

        UniqueConstraint('parameter_uuid', 'owner_uuid', name='u_paramowner'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    ptp_parameter_ownerships.create()

    _populate_ptp_tables(meta, ptp_instances, ptp_interfaces, ptp_parameters,
                         ptp_parameter_ownerships)


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

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
