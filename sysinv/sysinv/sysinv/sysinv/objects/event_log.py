# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils

from sysinv.openstack.common import log as logging

LOG = logging.getLogger('event_log')


class EventLog(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.str_or_none,
        'event_log_id': utils.str_or_none,
        'state': utils.str_or_none,
        'entity_type_id': utils.str_or_none,
        'entity_instance_id': utils.str_or_none,
        'timestamp': utils.datetime_or_str_or_none,
        'severity': utils.str_or_none,
        'reason_text': utils.str_or_none,
        'event_log_type': utils.str_or_none,
        'probable_cause': utils.str_or_none,
        'proposed_repair_action': utils.str_or_none,
        'service_affecting': utils.str_or_none,
        'suppression': utils.str_or_none,
        'suppression_status': utils.str_or_none,
    }

    @staticmethod
    def _from_db_object(server, db_server):
        """Converts a database entity to a formal object."""

        if isinstance(db_server, tuple):
            db_server_fields = db_server[0]
            db_suppress_status = db_server[1]
            db_server_fields['suppression_status'] = db_suppress_status
        else:
            db_server_fields = db_server

        for field in server.fields:
            server[field] = db_server_fields[field]

        server.obj_reset_changes()
        return server

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.event_log_get(uuid)
