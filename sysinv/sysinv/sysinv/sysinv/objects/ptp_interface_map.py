########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from sysinv.db import api as db_api
from sysinv.objects import base


class PtpInterfaceMap(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'interface_id': int,
            'ptp_interface_id': int,
             }

    _foreign_fields = {
        'interface_id': 'interface:id',
        'ptp_interface_id': 'ptp_interface:id',
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ptp_interface_map_get(uuid)
