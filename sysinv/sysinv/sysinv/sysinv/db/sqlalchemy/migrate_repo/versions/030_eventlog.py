# vim: tabstop=4 shiftwidth=4 softtabstop=4
#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import time
import yaml
import collections
import os
import datetime
import uuid as uuid_gen

from sqlalchemy import Boolean, Integer, DateTime, BigInteger, Float
from sqlalchemy import Column, MetaData, String, Table, ForeignKey
from sqlalchemy.schema import ForeignKeyConstraint

from sysinv.openstack.common import log


ENGINE = 'InnoDB'
CHARSET = 'utf8'

LOG = log.getLogger(__name__)


def logInfo(msg):
    msg = "UPGRADE EVENTLOG: {}".format(msg)
    LOG.info(msg)


def _tableFromName(migrate_engine, tableName):
    meta = MetaData()
    meta.bind = migrate_engine
    t = Table(tableName, meta, autoload=True)
    return t


def _tableExists(migrate_engine, tableName):
    return _tableFromName(migrate_engine, tableName).exists()


def _tableDrop(migrate_engine, tableName):
    if _tableExists(migrate_engine, tableName):
        logInfo("Dropping table {}.".format(tableName))
        return _tableFromName(migrate_engine, tableName).drop()


def countTable(migrate_engine, tableName):
    r = migrate_engine.execute('select count(*) from {}'.format(tableName))
    for row in r:
        break        # grab first row of result in order to get count
    return row[0]


def populateEventLogFromAlarmHistoryAndCustomerLogs(migrate_engine):
    #
    # Raw postgres SQL to populate the i_event_log from
    # existing data in the i_alarm_history and i_customer_log tables
    #

    if not _tableExists(migrate_engine, 'i_alarm_history') or \
       not _tableExists(migrate_engine, 'i_customer_log'):
        logInfo("Not performing event log data migration since source tables do not exist")
        return

    populateEventLogSQL = """
                    insert into i_event_log
                       ( created_at,
                         updated_at,
                         deleted_at,
                         uuid,
                         event_log_id,
                         state,
                         entity_type_id,
                         entity_instance_id,
                         timestamp,
                         severity,
                         reason_text,
                         event_log_type,
                         probable_cause,
                         proposed_repair_action,
                         service_affecting,
                         suppression )
                    select
                         created_at,
                         updated_at,
                         deleted_at,
                         uuid,
                         alarm_id as event_log_id,
                         alarm_state as state,
                         entity_type_id,
                         entity_instance_id,
                         timestamp,
                         severity,
                         reason_text,
                         alarm_type as event_log_type,
                         probable_cause,
                         proposed_repair_action,
                         service_affecting,
                         suppression
                    from i_alarm_history
                    union
                    select
                         created_at,
                         updated_at,
                         deleted_at,
                         uuid,
                         log_id as event_log_id,
                         'log' as state,
                         entity_type_id,
                         entity_instance_id,
                         timestamp,
                         severity,
                         reason_text,
                         log_type as event_log_type,
                         probable_cause,
                         null as proposed_repair_action,
                         service_affecting,
                         null as suppression
                    from i_customer_log
                    order by created_at
    """

    start = time.time()

    iAlarmHistoryCount = countTable(migrate_engine, 'i_alarm_history')
    iCustomerLogCount = countTable(migrate_engine, 'i_customer_log')

    logInfo("Data migration started.")

    if iAlarmHistoryCount > 0 or iCustomerLogCount > 0:
        logInfo("Migrating {} i_alarm_history records.  \
                Migrating {} i_customer_log records.".format(iAlarmHistoryCount, iCustomerLogCount))

    result = migrate_engine.execute(populateEventLogSQL)
    elapsedTime = time.time() - start

    logInfo("Data migration end.  Elapsed time is {} seconds.".format(elapsedTime))

    return result


def get_events_yaml_filename():
    events_yaml_name = os.environ.get("EVENTS_YAML")
    if events_yaml_name is not None and os.path.isfile(events_yaml_name):
        return events_yaml_name
    return "/etc/fm/events.yaml"


def is_execute_alter_table():
    alter_table = True

    if os.environ.get("SYSINV_TEST_ENV") == 'True':
        alter_table = False

    return alter_table


def add_alarm_table_foreign_key(migrate_engine):

        add_event_suppression_foreign_key = """
                                 alter table      i_alarm
                                 add constraint   fk_ialarm_esuppression_alarm_id
                                 foreign key      (alarm_id)
                                 references       event_suppression (alarm_id)
                                 match full
        """
        migrate_engine.execute(add_event_suppression_foreign_key)


def upgrade(migrate_engine):

    start = time.time()

    meta = MetaData()
    meta.bind = migrate_engine

    event_suppression = Table(
        'event_suppression',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(36), unique=True, index=True),
        Column('alarm_id', String(15), unique=True, index=True),
        Column('description', String(255)),
        Column('suppression_status', String(15)),
        Column('set_for_deletion', Boolean),
        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    event_suppression.create()

    if is_execute_alter_table():
        add_alarm_table_foreign_key(migrate_engine)

    i_event_log = Table(
        'i_event_log',
        meta,
        Column('created_at', DateTime),
        Column('updated_at', DateTime),
        Column('deleted_at', DateTime),

        Column('id', Integer, primary_key=True, nullable=False),
        Column('uuid', String(255), unique=True, index=True),
        Column('event_log_id', String(255), index=True),
        Column('state', String(255)),
        Column('entity_type_id', String(255), index=True),
        Column('entity_instance_id', String(255), index=True),
        Column('timestamp', DateTime(timezone=False)),
        Column('severity', String(255), index=True),
        Column('reason_text', String(255)),
        Column('event_log_type', String(255), index=True),
        Column('probable_cause', String(255)),
        Column('proposed_repair_action', String(255)),
        Column('service_affecting', Boolean),
        Column('suppression', Boolean),
        Column('alarm_id', String(255), nullable=True),
        ForeignKeyConstraint(
            ['alarm_id'],
            ['event_suppression.alarm_id'],
            use_alter=True,
            name='fk_elog_alarm_id_esuppression_alarm_id'
        ),

        mysql_engine=ENGINE,
        mysql_charset=CHARSET,
    )
    i_event_log.create()

    populateEventLogFromAlarmHistoryAndCustomerLogs(migrate_engine)

    _tableDrop(migrate_engine, 'i_alarm_history')
    _tableDrop(migrate_engine, 'i_customer_log')

    elapsedTime = time.time() - start
    logInfo("Elapsed time for eventlog table create and migrate is {} seconds.".format(elapsedTime))


def downgrade(migrate_engine):

    # As per other openstack components, downgrade is
    # unsupported in this release.
    raise NotImplementedError('SysInv database downgrade is unsupported.')
