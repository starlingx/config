# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils

# from sysinv.openstack.common import log as logging


class EventSuppression(base.SysinvObject):
    # VERSION 1.0: Initial version
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.uuid_or_none,
        'alarm_id': utils.str_or_none,
        'description': utils.str_or_none,
        'suppression_status': utils.str_or_none,
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.event_suppression_get(uuid)
