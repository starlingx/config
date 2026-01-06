########################################################################
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from sqlalchemy import Column
from sqlalchemy import MetaData
from sqlalchemy import String
from sqlalchemy import Table


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # add column to ptp_parameters table
    ptp_parameters = Table('ptp_parameters', meta, autoload=True)

    col_section = Column('section', String(255), default="global")
    col_section.create(ptp_parameters)


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # remove column from ptp_parameters table
    ptp_parameters = Table('ptp_parameters', meta, autoload=True)
    ptp_parameters.drop_column('section')
