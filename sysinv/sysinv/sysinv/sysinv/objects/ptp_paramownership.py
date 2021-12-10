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


class PtpParameterOwnership(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'parameter_uuid': utils.str_or_none,
            'owner_uuid': utils.str_or_none,
             }

    _foreign_fields = {
        'parameter_uuid': 'parameter:uuid',
        'owner_uuid': 'owner:uuid'
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ptp_paramownership_get(uuid)
