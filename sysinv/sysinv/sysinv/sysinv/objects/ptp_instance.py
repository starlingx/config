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
from sysinv.objects import ptp_paramowner


def get_hostnames(field, db_object):
    hosts = db_object['hosts']
    hostnames = []
    if hosts is not None:
        for h in hosts:
            hostnames.append(h.hostname)
    return hostnames


class PtpInstance(ptp_paramowner.PtpParameterOwner):

    dbapi = db_api.get_instance()

    fields = dict({
            'id': int,
            'name': utils.str_or_none,
            'service': utils.str_or_none,
            'hostnames': utils.list_of_strings_or_none,
            'parameters': utils.list_of_strings_or_none
             }, **ptp_paramowner.PtpParameterOwner.fields)

    _foreign_fields = {
        'hostnames': get_hostnames,
        'parameters': ptp_paramowner.get_parameters
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ptp_instance_get(uuid)
