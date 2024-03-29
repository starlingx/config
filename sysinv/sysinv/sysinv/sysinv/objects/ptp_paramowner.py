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


def get_parameters(field, db_object):
    ptp_parameters = db_object['ptp_parameters']
    parameters = []
    if ptp_parameters is not None:
        for p in ptp_parameters:
            parameter = '%s=%s' % (p.name, p.value)
            parameters.append(parameter)
    return parameters


class PtpParameterOwner(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,
            'type': utils.str_or_none,
            'capabilities': utils.dict_or_none,
             }

    _foreign_fields = {}

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ptp_paramowner_get(uuid)
