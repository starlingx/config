# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2018, 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sqlalchemy import Column, MetaData, Table, Integer, inspect
from sqlalchemy import __version__ as sa_version

from oslo_log import log

ENGINE = 'InnoDB'
CHARSET = 'utf8'

LOG = log.getLogger(__name__)


def upgrade(migrate_engine):
    """
       This database upgrade deletes the ceilometer metering_time_to_live
       service parameter.
    """

    meta = MetaData()
    meta.bind = migrate_engine

    LOG.info("Deleting ceilometer metering_time_to_live service parameter")
    if sa_version >= '1.4.0':
        table_exists = inspect(migrate_engine).has_table("service_parameter")
    else:
        table_exists = migrate_engine.dialect.has_table(migrate_engine, "service_parameter")
    if table_exists:

        sp_t = Table('service_parameter',
                     meta,
                     Column('id', Integer, primary_key=True, nullable=False),
                     mysql_engine=ENGINE,
                     mysql_charset=CHARSET,
                     autoload=True)

        ceilometer_metering_time_to_live_delete = sp_t.delete().where(  # pylint: disable=no-value-for-parameter
             sp_t.c.service == 'ceilometer')
        ceilometer_metering_time_to_live_delete.execute()
    return True


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    raise NotImplementedError('SysInv database downgrade is unsupported.')
