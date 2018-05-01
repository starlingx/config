# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import MetaData
from sqlalchemy import Table

from sysinv.openstack.common import log

import json

ENGINE = 'InnoDB'
CHARSET = 'utf8'

LOG = log.getLogger(__name__)


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Change https_enabled capability in the i_system DB table
    systems = Table('i_system', meta, autoload=True)
    # only one system entry should be populated
    sys = list(systems.select().where(
        systems.c.uuid is not None).execute())
    if len(sys) > 0:
        json_dict = json.loads(sys[0].capabilities)

        new_https_enabled_value = False

        if json_dict['https_enabled'] == 'y' :
                new_https_enabled_value = True
        elif json_dict['https_enabled'] == 'n' :
                new_https_enabled_value = False

        json_dict['https_enabled'] = new_https_enabled_value

        systems.update().where(
            systems.c.uuid == sys[0].uuid).values(
                {'capabilities': json.dumps(json_dict)}).execute()


def downgrade(migrate_engine):
    # Don't support SysInv downgrades at this time
    raise NotImplementedError('SysInv database downgrade is unsupported.')
