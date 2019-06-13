# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#

from sqlalchemy import MetaData, Table

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    interface = Table('interfaces', meta, autoload=True)
    interface.drop_column('networktype')
    return True


def downgrade(migrate_engine):
    raise NotImplementedError('SysInv database downgrade is unsupported.')
