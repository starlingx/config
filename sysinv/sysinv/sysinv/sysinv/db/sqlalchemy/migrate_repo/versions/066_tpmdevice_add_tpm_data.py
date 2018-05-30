# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import Integer, LargeBinary, Text
from sqlalchemy.dialects import postgresql

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # add tpm_data to tpmdevice table
    tpmdevice = Table('tpmdevice',
                      meta,
                      Column('id', Integer,
                             primary_key=True, nullable=False),
                      mysql_engine=ENGINE, mysql_charset=CHARSET,
                      autoload=True)

    tpmdevice.create_column(Column('binary', LargeBinary))
    tpmdevice.create_column(Column('tpm_data', Text))
    tpmdevice.create_column(Column('capabilities', Text))


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
