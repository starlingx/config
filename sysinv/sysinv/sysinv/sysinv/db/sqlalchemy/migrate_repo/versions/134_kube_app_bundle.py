########################################################################
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from migrate.changeset import UniqueConstraint
from sqlalchemy import Integer, String, DateTime, Boolean, Text
from sqlalchemy import Column, MetaData, Table, ForeignKey
from sysinv.db.sqlalchemy.models import KubeAppBundle

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    kube_app_bundle = Table(
        'kube_app_bundle',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True, nullable=False),
        Column('name', String(255), nullable=False),
        Column('version', String(255), nullable=False),
        Column('file_path', String(255), nullable=False),
        Column('auto_update', Boolean, nullable=False),
        Column('k8s_auto_update', Boolean, nullable=False),
        Column('k8s_timing', KubeAppBundle.KubeAppBundleTimingEnum, nullable=False),
        Column('k8s_minimum_version', String(16), nullable=False),
        Column('k8s_maximum_version', String(16), nullable=True),
        Column('reserved', Text, nullable=True),
        UniqueConstraint('name', 'version', name='u_bundle_name_version'),
        UniqueConstraint('file_path', name='u_bundle_file_path'),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    kube_app_bundle.create()

    # Create KubeApp FK to KubeAppBundle
    kube_app = Table('kube_app', meta, autoload=True)
    kube_app.create_column(Column('app_bundle_id', Integer,
                                  ForeignKey('kube_app_bundle.id',
                                             ondelete='SET NULL')))


def downgrade(migrate_engine):
    raise NotImplementedError('SysInv database downgrade is unsupported.')
