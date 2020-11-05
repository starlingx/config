# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column
from sqlalchemy import MetaData
from sqlalchemy import Table
from sqlalchemy import String
from sqlalchemy import Integer

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # add mode to kube_app table
    kube_app = Table(
        'kube_app',
        meta,
        Column('id', Integer,
               primary_key=True),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
        autoload=True)

    col = Column('mode', String(255), nullable=True)
    col.create(kube_app)


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
