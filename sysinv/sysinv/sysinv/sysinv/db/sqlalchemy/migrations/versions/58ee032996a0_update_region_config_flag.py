#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""update region config flag

Revision ID: 58ee032996a0
Revises: 8ee4f4de8064
Create Date: 2025-10-08 23:59:58.596799

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import json


# revision identifiers, used by Alembic.
revision: str = '58ee032996a0'
down_revision: Union[str, None] = '8ee4f4de8064'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Change region_config capability to a bool in the i_system DB table
    connection = op.get_bind()

    # Get system records
    result = connection.execute(
        sa.text("SELECT uuid, capabilities FROM i_system WHERE uuid IS NOT NULL")
    )

    for row in result:
        if row.capabilities:
            json_dict = json.loads(row.capabilities)

            region_config = False

            if json_dict.get('region_config') == 'y':
                region_config = True
            elif json_dict.get('region_config') == 'n':
                region_config = False

            json_dict['region_config'] = region_config

            connection.execute(
                sa.text("UPDATE i_system SET capabilities = :capabilities WHERE uuid = :uuid"),
                {"capabilities": json.dumps(json_dict), "uuid": row.uuid}
            )


def downgrade() -> None:
    # Don't support SysInv downgrades at this time
    raise NotImplementedError('SysInv database downgrade is unsupported.')
