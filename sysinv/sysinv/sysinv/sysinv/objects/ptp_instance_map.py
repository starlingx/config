########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from sysinv.db import api as db_api
from sysinv.objects import base


class PtpInstanceMap(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'host_id': int,
            'ptp_instance_id': int,
             }

    _foreign_fields = {
        'host_id': 'host:id',
        'ptp_instance_id': 'instance:id',
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ptp_instance_map_get(uuid)
