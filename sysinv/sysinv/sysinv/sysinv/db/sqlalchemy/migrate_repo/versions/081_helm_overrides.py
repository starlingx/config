# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import DateTime, String, Text, Integer
from sqlalchemy import Column, MetaData, Table, UniqueConstraint, ForeignKey

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    """
       This database upgrade creates a new table for storing helm chart
       user-specified override values.
    """

    meta = MetaData()
    meta.bind = migrate_engine

    Table('kube_app', meta, autoload=True)

    # Define and create the helm_overrides table.
    helm_overrides = Table(
        'helm_overrides',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True),
        Column('name', String(255), nullable=False),
        Column('namespace', String(255), nullable=False),
        Column('user_overrides', Text, nullable=True),
        Column('app_id', Integer,
               ForeignKey('kube_app.id', ondelete='CASCADE')),
        UniqueConstraint('name', 'namespace', 'app_id', name='u_app_name_namespace'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    helm_overrides.create()


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
