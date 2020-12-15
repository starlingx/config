# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import uuid
from datetime import datetime
from sqlalchemy import Integer
from sqlalchemy import Column, MetaData, Table

from oslo_log import log
from sysinv.common import constants

ENGINE = 'InnoDB'
CHARSET = 'utf8'

LOG = log.getLogger(__name__)


def upgrade(migrate_engine):
    """
       This database upgrade migrates the ipm retention_secs field
       to ceilometer, panko and aodh time to live service parameters
       and then deletes the existing obsoleted ipm table.
    """

    meta = MetaData()
    meta.bind = migrate_engine

    # Verify the 'i_pm' table exists before trying to load it.
    # Doing so makes error handling more graceful by avoiding
    #   a traceback error if it does not exist.
    if not migrate_engine.dialect.has_table(migrate_engine, "i_pm"):
        return True

    # load the ipm table
    ipm = Table('i_pm', meta, autoload=True)

    # read retention_secs value
    pms = list(ipm.select().where(ipm.c.retention_secs is not None).execute())
    ipm.drop()

    if not len(pms):
        return True

    ret_secs = pms[0].retention_secs
    if (ret_secs == constants.PM_TTL_DEFAULT):
        return True

    LOG.info("migrating i_pm retention_secs value:%s" % ret_secs)
    if migrate_engine.dialect.has_table(migrate_engine, "service_parameter"):

        sp_t = Table('service_parameter',
                     meta,
                     Column('id', Integer, primary_key=True, nullable=False),
                     mysql_engine=ENGINE,
                     mysql_charset=CHARSET,
                     autoload=True)
        panko_event_time_to_live_insert = sp_t.insert()  # pylint: disable=no-value-for-parameter
        values = {'created_at': datetime.now(),
                  'uuid': str(uuid.uuid4()),
                  'service': 'panko',
                  'section': 'database',
                  'name': 'event_time_to_live',
                  'value': ret_secs,
                  }
        panko_event_time_to_live_insert.execute(values)

        ceilometer_metering_time_to_live_insert = sp_t.insert()  # pylint: disable=no-value-for-parameter
        values = {'created_at': datetime.now(),
                  'uuid': str(uuid.uuid4()),
                  'service': 'ceilometer',
                  'section': 'database',
                  'name': 'metering_time_to_live',
                  'value': ret_secs,
                  }
        ceilometer_metering_time_to_live_insert.execute(values)

        aodh_alarm_history_time_to_live_insert = sp_t.insert()  # pylint: disable=no-value-for-parameter
        values = {'created_at': datetime.now(),
                  'uuid': str(uuid.uuid4()),
                  'service': 'aodh',
                  'section': 'database',
                  'name': 'alarm_history_time_to_live',
                  'value': ret_secs,
                  }
        aodh_alarm_history_time_to_live_insert.execute(values)

    return True


def downgrade(migrate_engine):
    meta = MetaData()
    meta.bind = migrate_engine
    raise NotImplementedError('SysInv database downgrade is unsupported.')
