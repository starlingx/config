########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class PtpInstance(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,

            'name': utils.str_or_none,
            'service': utils.str_or_none,

            'host_id': utils.int_or_none,

            'host_uuid': utils.str_or_none,
            'hostname': utils.str_or_none,

            'capabilities': utils.dict_or_none
             }

    _foreign_fields = {
        'host_uuid': 'host:uuid',
        'hostname': 'host:hostname'
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ptp_instance_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.ptp_instance_update(self.uuid,  # pylint: disable=no-member
                                       updates)
