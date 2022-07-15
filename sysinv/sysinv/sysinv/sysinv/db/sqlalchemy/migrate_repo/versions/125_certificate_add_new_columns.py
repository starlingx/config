# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import Table


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # add column to certificate table
    certificate = Table('certificate', meta, autoload=True)

    col_subject = Column('subject', String(255), nullable=True)
    col_subject.create(certificate)

    col_hash_subject = Column('hash_subject', String(64), nullable=True)
    col_hash_subject.create(certificate)


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
