#!/usr/bin/env python
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


import pecan
from pecan import rest

import wsme
from wsme import types as wtypes
import wsmeext.pecan as wsme_pecan

from sysinv.api.controllers.v1 import base
from sysinv.api.controllers.v1 import collection
from sysinv.api.controllers.v1 import link
from sysinv.api.controllers.v1.query import Query
from sysinv.api.controllers.v1 import types
from sysinv.api.controllers.v1 import utils as api_utils
from sysinv.common import constants
from sysinv.common import utils as cutils
from sysinv import objects
from sysinv.openstack.common.gettextutils import _
from sysinv.openstack.common import log

LOG = log.getLogger(__name__)


class EventSuppressionPatchType(types.JsonPatchType):
    @staticmethod
    def mandatory_attrs():
        return ['/uuid']


class EventSuppression(base.APIBase):
    """API representation of an event suppression.

    This class enforces type checking and value constraints, and converts
    between the internal object model and the API representation of
    an event_suppression.
    """

    id = int
    "Unique ID for this entry"

    uuid = types.uuid
    "Unique UUID for this entry"

    alarm_id = wsme.wsattr(wtypes.text, mandatory=True)
    "Unique id for the Alarm Type"

    description = wsme.wsattr(wtypes.text, mandatory=True)
    "Text description of the Alarm Type"

    suppression_status = wsme.wsattr(wtypes.text, mandatory=True)
    "'suppressed' or 'unsuppressed'"

    links = [link.Link]
    "A list containing a self link and associated links"

    def __init__(self, **kwargs):
        self.fields = objects.event_suppression.fields.keys()
        for k in self.fields:
            if not hasattr(self, k):
                continue
            setattr(self, k, kwargs.get(k, wtypes.Unset))

    @classmethod
    def convert_with_links(cls, rpc_event_suppression, expand=True):
        parm = EventSuppression(**rpc_event_suppression.as_dict())

        if not expand:
            parm.unset_fields_except(['uuid', 'alarm_id', 'description',
                                      'suppression_status'])

        parm.links = [link.Link.make_link('self', pecan.request.host_url,
                                          'event_suppression', parm.uuid),
                      link.Link.make_link('bookmark',
                                          pecan.request.host_url,
                                          'event_suppression', parm.uuid,
                                          bookmark=True)
                      ]
        return parm


class EventSuppressionCollection(collection.Collection):
    """API representation of a collection of  event_suppression."""

    event_suppression = [EventSuppression]
    "A list containing EventSuppression objects"

    def __init__(self, **kwargs):
        self._type = 'event_suppression'

    @classmethod
    def convert_with_links(cls, rpc_event_suppression, limit, url=None,
                           expand=False,
                           **kwargs):
        collection = EventSuppressionCollection()
        collection.event_suppression = [EventSuppression.convert_with_links(p, expand)
                                        for p in rpc_event_suppression]
        collection.next = collection.get_next(limit, url=url, **kwargs)
        return collection


LOCK_NAME = 'EventSuppressionController'


class EventSuppressionController(rest.RestController):
    """REST controller for event_suppression."""

    def __init__(self, parent=None, **kwargs):
        self._parent = parent

    def _get_event_suppression_collection(self, marker=None, limit=None,
                                          sort_key=None, sort_dir=None,
                                          expand=False, resource_url=None,
                                          q=None):
        limit = api_utils.validate_limit(limit)
        sort_dir = api_utils.validate_sort_dir(sort_dir)
        kwargs = {}
        if q is not None:
            for i in q:
                if i.op == 'eq':
                    kwargs[i.field] = i.value
        marker_obj = None
        if marker:
            marker_obj = objects.event_suppression.get_by_uuid(
                pecan.request.context, marker)

        if q is None:
            parms = pecan.request.dbapi.event_suppression_get_list(
                limit=limit, marker=marker_obj,
                sort_key=sort_key, sort_dir=sort_dir)
        else:
            kwargs['limit'] = limit
            kwargs['sort_key'] = sort_key
            kwargs['sort_dir'] = sort_dir

        parms = pecan.request.dbapi.event_suppression_get_all(**kwargs)

        return EventSuppressionCollection.convert_with_links(
            parms, limit, url=resource_url, expand=expand,
            sort_key=sort_key, sort_dir=sort_dir)

    def _get_updates(self, patch):
        """Retrieve the updated attributes from the patch request."""
        updates = {}
        for p in patch:
            attribute = p['path'] if p['path'][0] != '/' else p['path'][1:]
            updates[attribute] = p['value']
        return updates

    @staticmethod
    def _check_event_suppression_updates(updates):
        """Check attributes to be updated"""

        for parameter in updates:
            if parameter == 'suppression_status':
                if not((updates.get(parameter) == constants.FM_SUPPRESSED) or
                        (updates.get(parameter) == constants.FM_UNSUPPRESSED)):
                    msg = _("Invalid event_suppression parameter suppression_status values. \
                                 Valid values are: suppressed, unsuppressed")
                    raise wsme.exc.ClientSideError(msg)
            elif parameter == 'alarm_id':
                msg = _("event_suppression parameter alarm_id is not allowed to be updated.")
                raise wsme.exc.ClientSideError(msg)
            elif parameter == 'description':
                msg = _("event_suppression parameter description is not allowed to be updated.")
                raise wsme.exc.ClientSideError(msg)
            else:
                msg = _("event_suppression invalid parameter.")
                raise wsme.exc.ClientSideError(msg)

    @wsme_pecan.wsexpose(EventSuppressionCollection, [Query],
                         types.uuid, wtypes.text,
                         wtypes.text, wtypes.text, wtypes.text)
    def get_all(self, q=[], marker=None, limit=None,
                sort_key='id', sort_dir='asc'):
        """Retrieve a list of event_suppression."""
        sort_key = ['alarm_id']
        return self._get_event_suppression_collection(marker, limit,
                                                      sort_key,
                                                      sort_dir, q=q)

    @wsme_pecan.wsexpose(EventSuppression, types.uuid)
    def get_one(self, uuid):
        """Retrieve information about the given event_suppression."""
        rpc_event_suppression = objects.event_suppression.get_by_uuid(
            pecan.request.context, uuid)
        return EventSuppression.convert_with_links(rpc_event_suppression)

    @cutils.synchronized(LOCK_NAME)
    @wsme.validate(types.uuid, [EventSuppressionPatchType])
    @wsme_pecan.wsexpose(EventSuppression, types.uuid,
                         body=[EventSuppressionPatchType])
    def patch(self, uuid, patch):
        """Updates attributes of event_suppression."""
        event_suppression = objects.event_suppression.get_by_uuid(pecan.request.context, uuid)
        event_suppression = event_suppression.as_dict()

        updates = self._get_updates(patch)
        self._check_event_suppression_updates(updates)

        event_suppression.update(updates)

        updated_event_suppression = pecan.request.dbapi.event_suppression_update(uuid, updates)

        return EventSuppression.convert_with_links(updated_event_suppression)
