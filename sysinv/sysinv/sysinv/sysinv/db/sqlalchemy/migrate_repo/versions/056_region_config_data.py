# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import Text


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # add region_name and service_tenant_name to system table
    i_system = Table('i_system', meta, autoload=True)
    i_system.create_column(Column('region_name', Text, default="RegionOne"))
    i_system.create_column(Column('service_project_name', Text, default="services"))

    # add service_type, region_name and capabilities to services table
    i_service = Table('services', meta, autoload=True)
    # where the service resides
    i_service.create_column(Column('region_name', Text, default="RegionOne"))
    i_service.create_column(Column('capabilities', Text))


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
