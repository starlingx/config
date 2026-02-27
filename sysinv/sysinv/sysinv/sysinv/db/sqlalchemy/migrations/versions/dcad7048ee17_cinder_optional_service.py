#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""cinder optional service

Revision ID: dcad7048ee17
Revises: 58ee032996a0
Create Date: 2025-10-09 00:00:12.228059

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import json


# revision identifiers, used by Alembic.
revision: str = 'dcad7048ee17'
down_revision: Union[str, None] = '58ee032996a0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    connection = op.get_bind()

    # Remove cinder_gib parameter.
    # Save it in the idisk capabilities first.

    storage_lvm_result = connection.execute(
        sa.text("SELECT * FROM storage_lvm")
    )
    storage_lvm_entries = storage_lvm_result.fetchall()

    if len(storage_lvm_entries) > 0:
        cinder_gib = storage_lvm_entries[0].cinder_gib

        idisk_result = connection.execute(
            sa.text("SELECT uuid, capabilities FROM i_idisk")
        )

        for idisk in idisk_result:
            capabilities = json.loads(idisk.capabilities)
            if ('device_function' in capabilities and
                    capabilities['device_function'] == 'cinder_device'):
                capabilities['cinder_gib'] = cinder_gib

                connection.execute(
                    sa.text("UPDATE i_idisk SET capabilities = :capabilities WHERE uuid = :uuid"),
                    {"capabilities": json.dumps(capabilities), "uuid": idisk.uuid}
                )

    # Drop cinder_gib column from storage_lvm
    op.drop_column('storage_lvm', 'cinder_gib')

    # Create storage_file table
    op.create_table('storage_file',
        sa.Column('created_at', sa.DateTime()),
        sa.Column('updated_at', sa.DateTime()),
        sa.Column('deleted_at', sa.DateTime()),
        sa.Column('id', sa.Integer(),
                  sa.ForeignKey('storage_backend.id', ondelete='CASCADE'),
                  primary_key=True, unique=True, nullable=False),
    )

    # Add columns to storage_backend table
    op.add_column('storage_backend', sa.Column('services', sa.Text()))
    op.add_column('storage_backend', sa.Column('capabilities', sa.Text()))


def downgrade() -> None:
    # Downgrade is unsupported.
    raise NotImplementedError("SysInv database downgrade is unsupported.")