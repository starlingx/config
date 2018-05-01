# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import MetaData, Table
from sysinv.openstack.common import log

import json

ENGINE = 'InnoDB'
CHARSET = 'utf8'

LOG = log.getLogger(__name__)


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # Change region_config capability to a bool in the i_system DB table
    systems = Table('i_system', meta, autoload=True)
    # only one system entry should be populated
    sys = list(systems.select().where(
        systems.c.uuid is not None).execute())
    if len(sys) > 0:
        json_dict = json.loads(sys[0].capabilities)

        region_config = False

        if json_dict['region_config'] == 'y' :
            region_config = True
        elif json_dict['region_config'] == 'n' :
            region_config = False

        json_dict['region_config'] = region_config

        systems.update().where(
            systems.c.uuid == sys[0].uuid).values(
                {'capabilities': json.dumps(json_dict)}).execute()


def downgrade(migrate_engine):
    # Don't support SysInv downgrades at this time
    raise NotImplementedError('SysInv database downgrade is unsupported.')
