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


class PtpInstanceMap(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,

            'host_id': int,
            'hostname': utils.str_or_none,

            'ptp_instance_id': int,
            'name': utils.str_or_none,
            'service': utils.str_or_none
             }

    _foreign_fields = {
        'host_id': 'host:id',
        'hostname': 'host:hostname',
        'ptp_instance_id': 'ptp_instance:id',
        'name': 'ptp_instance:name',
        'service': 'ptp_instance:service'
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ptp_instance_map_get(uuid)
