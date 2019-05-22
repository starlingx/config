# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import DateTime, String, Integer
from sqlalchemy import Column, MetaData, Table, ForeignKey, UniqueConstraint

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    """
       This database upgrade creates a new table for storing kubenetes
       application releases info.
    """

    meta = MetaData()
    meta.bind = migrate_engine

    Table('kube_app', meta, autoload=True)

    # Define and create the kube application releases table.
    kube_app_releases = Table(
        'kube_app_releases',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('id', Integer, primary_key=True),

        Column('release', String(255), nullable=True),
        Column('namespace', String(255), nullable=True),
        Column('version', Integer),
        Column('app_id', Integer,
               ForeignKey('kube_app.id', ondelete='CASCADE')),

        UniqueConstraint('release', 'namespace', 'app_id', name='u_app_release_namespace'),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )

    kube_app_releases.create()


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
