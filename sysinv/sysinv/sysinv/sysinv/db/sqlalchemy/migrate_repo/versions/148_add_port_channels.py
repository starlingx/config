# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table
from sqlalchemy import Integer

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    """Perform sysinv database upgrade for network interface
    """

    meta = MetaData()
    meta.bind = migrate_engine

    port = Table('ports', meta, autoload=True)
    port.create_column(Column('numchannels', Integer))
    port.create_column(Column('maxchannels', Integer))
    port.create_column(Column('sriov_vf_numchannels', Integer))
    port.create_column(Column('sriov_vf_maxchannels', Integer))


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
