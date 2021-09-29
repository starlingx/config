#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from migrate.changeset import UniqueConstraint
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import Table

from sysinv.common import kubernetes

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def _insert_default_kube_cmd_version(kube_cmd_versions):
    kube_cmd_versions_insert = kube_cmd_versions.insert()
    values = {
        'kubeadm_version': kubernetes.K8S_INITIAL_CMD_VERSION,
        'kubelet_version': kubernetes.K8S_INITIAL_CMD_VERSION
    }
    kube_cmd_versions_insert.execute(values)


def upgrade(migrate_engine):
    """
       This database upgrade creates a new kube_cmd_versions table
    """

    meta = MetaData()
    meta.bind = migrate_engine

    # Define and create the kube_cmd_versions table.
    kube_cmd_versions = Table(
        'kube_cmd_versions',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),
        Column('id', Integer, primary_key=True,
               unique=True, nullable=False),
        Column('kubeadm_version', String(255), nullable=False),
        Column('kubelet_version', String(255), nullable=False),
        UniqueConstraint('kubeadm_version', 'kubelet_version',
                         name='u_kubeadm_version_kubelet_version'),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    kube_cmd_versions.create()

    _insert_default_kube_cmd_version(kube_cmd_versions)


def downgrade(migrate_engine):
    # Downgrade is unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
