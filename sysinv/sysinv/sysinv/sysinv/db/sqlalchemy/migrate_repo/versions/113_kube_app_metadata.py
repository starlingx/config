#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import MetaData
from sqlalchemy import Table
from sqlalchemy import Text

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # add app_metadata to kube_app table
    kube_app = Table(
        'kube_app',
        meta,
        Column('id', Integer,
               primary_key=True),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
        autoload=True)

    col = Column('app_metadata', Text, nullable=True)
    col.create(kube_app)


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
