# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import DateTime, Integer, String, Text
from sysinv.openstack.common import log

ENGINE = 'InnoDB'
CHARSET = 'utf8'
LOG = log.getLogger(__name__)


def upgrade(migrate_engine):
    """Perform sysinv database upgrade for certificate
    """

    meta = MetaData()
    meta.bind = migrate_engine

    certificate = Table(
        'certificate',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True),

        Column('certtype', String(64)),
        Column('issuer', String(255)),
        Column('signature', String(255)),
        Column('start_date', DateTime),
        Column('expiry_date', DateTime),
        Column('capabilities', Text),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    certificate.create()


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
