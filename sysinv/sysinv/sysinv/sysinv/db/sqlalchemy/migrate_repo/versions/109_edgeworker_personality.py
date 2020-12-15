#
# Copyright (c) 2020 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import MetaData

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Set to AUTOCOMMIT isolation level because
    # 'ALTER TYPE ... ADD' cannot run inside a transaction block
    # Only psycopg2 and pg8000 supports AUTOCOMMIT
    if ('postgresql+psycopg2' in str(migrate_engine.url) or
            'postgresql+pg8000' in str(migrate_engine.url)):
        ac_migrate_engine = migrate_engine.execution_options(isolation_level="AUTOCOMMIT")
        ac_migrate_engine.execute("ALTER TYPE \"invPersonalityEnum\" ADD VALUE 'edgeworker' AFTER 'reserve2'")


def downgrade(migrate_engine):
    # Downgrade is unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
