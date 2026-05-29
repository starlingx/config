########################################################################
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from sqlalchemy import MetaData, Table, Text


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    ptp_params = Table('ptp_parameters', meta, autoload=True)
    ptp_params.c.value.alter(type=Text)


def downgrade(migrate_engine):
    raise NotImplementedError('SysInv database downgrade is unsupported.')
