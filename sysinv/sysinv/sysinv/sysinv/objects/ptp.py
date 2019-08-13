########################################################################
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class PTP(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,

            'enabled': utils.bool_or_none,
            'mode': utils.str_or_none,
            'transport': utils.str_or_none,
            'mechanism': utils.str_or_none,

            'isystem_uuid': utils.str_or_none,
            'system_id': utils.int_or_none
             }

    _foreign_fields = {
        'isystem_uuid': 'system:uuid'
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ptp_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.ptp_update(self.uuid,  # pylint: disable=no-member
                              updates)
