# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Boolean, Column, MetaData, Table

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    dev_img_functional = Table('device_images_functional', meta, autoload=True)
    dev_img_functional.create_column(Column('retimer_included', Boolean, default=False))


def downgrade(migrate_engine):
    # Downgrade is unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
