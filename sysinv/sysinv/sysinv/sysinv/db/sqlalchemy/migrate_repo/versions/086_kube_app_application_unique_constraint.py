# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from migrate.changeset import UniqueConstraint
from sqlalchemy import MetaData, Table

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    """
       This database upgrade drops the old unique constraint and creates
       new unique constraint for the kube_app table.
    """

    meta = MetaData()
    meta.bind = migrate_engine

    kube_app = Table('kube_app', meta, autoload=True)

    UniqueConstraint('name', table=kube_app).drop()
    UniqueConstraint('name', 'app_version', table=kube_app,
                     name='u_app_name_version').create()


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
