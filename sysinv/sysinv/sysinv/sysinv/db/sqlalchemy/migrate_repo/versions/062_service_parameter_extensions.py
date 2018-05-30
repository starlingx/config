# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from migrate.changeset import UniqueConstraint
from sqlalchemy import Column, MetaData, Table
from sqlalchemy import Enum, String, Integer
from sqlalchemy.dialects import postgresql

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # add personality and resource to service_parameter table
    service_parameter = Table('service_parameter',
                              meta,
                              Column('id', Integer,
                                     primary_key=True, nullable=False),
                              mysql_engine=ENGINE, mysql_charset=CHARSET,
                              autoload=True)
    service_parameter.create_column(Column('personality', String(255)))
    service_parameter.create_column(Column('resource', String(255)))

    # Remove the existing unique constraint to add a unique constraint
    # with personality and resource.
    UniqueConstraint('service', 'section', 'name', table=service_parameter,
                     name='u_servicesectionname').drop()
    UniqueConstraint('service', 'section', 'name',
                     'personality', 'resource', table=service_parameter,
                     name='u_service_section_name_personality_resource').create()


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
