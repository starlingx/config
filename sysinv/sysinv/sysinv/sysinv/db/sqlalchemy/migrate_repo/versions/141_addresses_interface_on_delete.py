# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import MetaData
from sqlalchemy.dialects import postgresql

ENGINE = 'InnoDB'
CHARSET = 'utf8'


def upgrade(migrate_engine):
    """
       This database upgrade changes the 'on delete' parameter in
       the addresses table
    """

    meta = MetaData()
    meta.bind = migrate_engine

    if migrate_engine.url.get_dialect() is postgresql.dialect:
        migrate_engine.execute('ALTER TABLE addresses DROP CONSTRAINT '
                               'addresses_interface_id_fkey;')

        migrate_engine.execute('ALTER TABLE addresses ADD CONSTRAINT '
                               'addresses_interface_id_fkey FOREIGN KEY '
                               '(interface_id) REFERENCES '
                               'interfaces(id) ON DELETE SET NULL;')


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
