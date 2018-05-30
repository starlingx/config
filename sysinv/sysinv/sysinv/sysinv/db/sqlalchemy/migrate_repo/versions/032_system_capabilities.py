# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import json
from sqlalchemy import Column, MetaData, Table


def _populate_shared_services_capabilities(system_table):
    hp_shared_services = ['identity',
                          'image',
                          'volume']
    sys = list(system_table.select().where(
        system_table.c.uuid is not None).execute())
    if len(sys) > 0:
        json_dict = json.loads(sys[0].capabilities)
        if (json_dict.get('region_config') and
                json_dict.get('shared_services') is None):
            if json_dict.get('vswitch_type') == 'nuage_vrs':
                hp_shared_services.append('network')
            json_dict['shared_services'] = str(hp_shared_services)
            system_table.update().where(
                system_table.c.uuid == sys[0].uuid).values(
                {'capabilities': json.dumps(json_dict)}).execute()


def upgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine

    # populate shared_services in system capabilities for HP region upgrade
    systems = Table('i_system', meta, autoload=True)
    _populate_shared_services_capabilities(systems)


def downgrade(migrate_engine):
    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
