#!/usr/bin/env python
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


import datetime
from oslo_utils import timeutils

import pecan
from pecan import rest


import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import alarm_utils
from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1.query import Query
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils as api_utils
from sysinv.common import exception
from sysinv import objects
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log

LOG = log.getLogger(__name__)

import json


def prettyDict(dict):
    output = json.dumps(dict, sort_keys=True, indent=4)
    return output


class EventLogPatchType(types.JsonPatchType):
    pass


class EventLog(base.APIBase):
    """API representation of an event log.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    a event_log.
    """

    uuid = types.uuid
    "The UUID of the event_log"

    event_log_id = wsme.wsattr(wtypes.text, mandatory=True)
    "structured id for the event log;   AREA_ID  ID;   300-001"

    state = wsme.wsattr(wtypes.text, mandatory=True)
    "The state of the event"

    entity_type_id = wtypes.text
    "The type of the object event log"

    entity_instance_id = wsme.wsattr(wtypes.text, mandatory=True)
    "The original instance information of the object creating event log"

    timestamp = datetime.datetime
    "The time in UTC at which the event log is generated"

    severity = wsme.wsattr(wtypes.text, mandatory=True)
    "The severity of the log"

    reason_text = wtypes.text
    "The reason why the log is generated"

    event_log_type = wsme.wsattr(wtypes.text, mandatory=True)
    "The type of the event log"

    probable_cause = wsme.wsattr(wtypes.text, mandatory=True)
    "The probable cause of the event log"

    proposed_repair_action = wtypes.text
    "The action to clear the alarm"

    service_affecting = wtypes.text
    "Whether the log affects the service"

    suppression = wtypes.text
    "'allowed' or 'not-allowed'"

    suppression_status = wtypes.text
    "'suppressed' or 'unsuppressed'"

    links = [link.Link]
    "A list containing a self link and associated community string links"

    def __init__(self, **kwargs):

        self.fields = objects.event_log.fields.keys()
        for k in self.fields:
            setattr(self, k, kwargs.get(k))

    @classmethod
    def convert_with_links(cls, rpc_event_log, expand=True):

        if isinstance(rpc_event_log, tuple):
            ievent_log = rpc_event_log[0]
            suppress_status = rpc_event_log[1]
        else:
            ievent_log = rpc_event_log
            suppress_status = rpc_event_log.suppression_status

        if not expand:
            ievent_log['service_affecting'] = str(ievent_log['service_affecting'])
            ievent_log['suppression'] = str(ievent_log['suppression'])

        ilog = EventLog(**ievent_log.as_dict())
        if not expand:
            ilog.unset_fields_except(['uuid', 'event_log_id', 'entity_instance_id',
                                      'severity', 'timestamp', 'reason_text', 'state'])

        ilog.entity_instance_id = \
            alarm_utils.make_display_id(ilog.entity_instance_id, replace=False)

        ilog.suppression_status = str(suppress_status)

        return ilog


def _getEventType(alarms=False, logs=False):
    if alarms is False and logs is False:
        return "ALL"
    if alarms is True and logs is True:
        return "ALL"
    if logs is True:
        return "LOG"
    if alarms is True:
        return "ALARM"
    return "ALL"


class EventLogCollection(collection.Collection):
    """API representation of a collection of event_log."""

    event_log = [EventLog]
    "A list containing event_log objects"

    def __init__(self, **kwargs):
        self._type = 'event_log'

    @classmethod
    def convert_with_links(cls, ilog, limit=None, url=None,
                           expand=False, **kwargs):

        ilogs = []
        for a in ilog:
            ilogs.append(a)

        collection = EventLogCollection()
        collection.event_log = [EventLog.convert_with_links(ch, expand)
                                for ch in ilogs]

        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


def _handle_bad_input_date(f):
    """
       A decorator that executes function f and returns
       a more human readable error message on a SQL date exception
    """
    def date_handler_wrapper(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except Exception as e:
            import re
            e_str = "{}".format(e)
            for r in [".*date/time field value out of range: \"(.*)\".*LINE",
                      ".*invalid input syntax for type timestamp: \"(.*)\".*",
                      ".*timestamp out of range: \"(.*)\".*"]:
                p = re.compile(r, re.DOTALL)
                m = p.match(e_str)
                if m and len(m.groups()) > 0:
                    bad_date = m.group(1)
                    raise wsme.exc.ClientSideError(_("Invalid date '{}' specified".format(bad_date)))
            raise
    return date_handler_wrapper


class EventLogController(rest.RestController):
    """REST controller for eventlog."""

    _custom_actions = {
        'detail': ['GET'],
    }

    @_handle_bad_input_date
    def _get_eventlog_collection(self, marker, limit, sort_key, sort_dir,
                                 expand=False, resource_url=None,
                                 q=None, alarms=False, logs=False,
                                 include_suppress=False):

        if limit and limit < 0:
            raise wsme.exc.ClientSideError(_("Limit must be positive"))
        sort_dir = api_utils.validate_sort_dir(sort_dir)
        kwargs = {}
        if q is not None:
            for i in q:
                if i.op == 'eq':
                    if i.field == 'start' or i.field == 'end':
                        val = timeutils.normalize_time(
                            timeutils.parse_isotime(i.value)
                            .replace(tzinfo=None))
                        i.value = val.isoformat()
                    kwargs[i.field] = i.value

        evtType = _getEventType(alarms, logs)
        kwargs["evtType"] = evtType
        kwargs["include_suppress"] = include_suppress

        if marker:
            marker_obj = objects.event_log.get_by_uuid(pecan.request.context,
                                                       marker)

            ilog = pecan.request.dbapi.event_log_get_list(limit, marker_obj,
                                                          sort_key=sort_key,
                                                          sort_dir=sort_dir,
                                                          evtType=evtType,
                                                          include_suppress=include_suppress)
        else:
            kwargs['limit'] = limit
            ilog = pecan.request.dbapi.event_log_get_all(**kwargs)

        return EventLogCollection.convert_with_links(ilog, limit,
                                                     url=resource_url,
                                                     expand=expand,
                                                     sort_key=sort_key,
                                                     sort_dir=sort_dir)

    @wsme_pecan.wsexpose(EventLogCollection, [Query],
                         types.uuid, int, wtypes.text, wtypes.text, bool, bool, bool)
    def get_all(self, q=[], marker=None, limit=None, sort_key='timestamp',
                sort_dir='desc', alarms=False, logs=False, include_suppress=False):
        """Retrieve a list of event_log.

        :param marker: pagination marker for large data sets.
        :param limit: maximum number of resources to return in a single result.
        :param sort_key: column to sort results by. Default: id.
        :param sort_dir: direction to sort. "asc" or "desc". Default: asc.
        :param alarms: filter on alarms. Default: False
        :param logs: filter on logs. Default: False
        :param include_suppress: filter on suppressed alarms. Default: False
        """
        return self._get_eventlog_collection(marker, limit, sort_key,
                                             sort_dir, q=q, alarms=alarms, logs=logs,
                                             include_suppress=include_suppress)

    @wsme_pecan.wsexpose(EventLogCollection, types.uuid, int,
                         wtypes.text, wtypes.text, bool, bool)
    def detail(self, marker=None, limit=None, sort_key='id', sort_dir='asc', alarms=False, logs=False):
        """Retrieve a list of event_log with detail.

        :param marker: pagination marker for large data sets.
        :param limit: maximum number of resources to return in a single result.
        :param sort_key: column to sort results by. Default: id.
        :param sort_dir: direction to sort. "asc" or "desc". Default: asc.
        :param alarms: filter on alarms. Default: False
        :param logs: filter on logs. Default: False
        """
        # /detail should only work against collections
        parent = pecan.request.path.split('/')[:-1][-1]
        if parent != "event_log":
            raise exception.HTTPNotFound

        expand = True
        resource_url = '/'.join(['event_log', 'detail'])
        return self._get_eventlog_collection(marker, limit, sort_key, sort_dir,
                                             expand, resource_url, None, alarms, logs)

    @wsme_pecan.wsexpose(EventLog, wtypes.text)
    def get_one(self, id):
        """Retrieve information about the given event_log.

        :param id: UUID of an event_log.
        """
        rpc_ilog = objects.event_log.get_by_uuid(
            pecan.request.context, id)

        return EventLog.convert_with_links(rpc_ilog)
