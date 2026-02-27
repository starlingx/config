#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""https security

Revision ID: 08a4b7b81134
Revises: 221a7a8ff786
Create Date: 2025-10-07 08:40:40.131052

"""
from typing import Sequence, Union
import json

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '08a4b7b81134'
down_revision: Union[str, None] = '221a7a8ff786'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade():
    # Change https_enabled capability in the i_system DB table
    connection = op.get_bind()
    meta = sa.MetaData()
    systems = sa.Table('i_system', meta, autoload_with=connection)

    # only one system entry should be populated
    sys = list(connection.execute(systems.select().where(systems.c.uuid is not None)))
    if len(sys) > 0:
        json_dict = json.loads(sys[0].capabilities)

        new_https_enabled_value = False

        if json_dict['https_enabled'] == 'y':
            new_https_enabled_value = True
        elif json_dict['https_enabled'] == 'n':
            new_https_enabled_value = False

        json_dict['https_enabled'] = new_https_enabled_value

        connection.execute(systems.update().where(
            systems.c.uuid == sys[0].uuid).values(
            {'capabilities': json.dumps(json_dict)}))


def downgrade():
    raise NotImplementedError('SysInv database downgrade is unsupported.')