#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""system capabilities

Revision ID: 0b8155d29ac8
Revises: af1ff2b249d7
Create Date: 2025-10-07 07:59:43.521510

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '0b8155d29ac8'
down_revision: Union[str, None] = 'af1ff2b249d7'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

def _populate_shared_services_capabilities(connection,system_table):
    hp_shared_services = ['identity',
                          'image',
                          'volume']
    sys = list(connection.execute(system_table.select().where(
        system_table.c.uuid is not None)))
    if len(sys) > 0:
        json_dict = json.loads(sys[0].capabilities)
        if (json_dict.get('region_config') and
                json_dict.get('shared_services') is None):
            if json_dict.get('vswitch_type') == 'nuage_vrs':
                hp_shared_services.append('network')
            json_dict['shared_services'] = str(hp_shared_services)
            connection.execute(system_table.update().where(
                system_table.c.uuid == sys[0].uuid).values(
                {'capabilities': json.dumps(json_dict)}))


def upgrade():
    # Get connection and metadata
    connection = op.get_bind()
    meta = sa.MetaData()

    # Load the i_system table
    systems = sa.Table('i_system', meta, autoload_with=connection)

    # Populate shared_services in system capabilities for HP region upgrade
    _populate_shared_services_capabilities(connection,systems)


def downgrade():
    raise NotImplementedError('SysInv database downgrade is unsupported.')