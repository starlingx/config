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


def get_hosts(field, db_object):
    hosts = db_object['hosts']
    if not hosts:
        return []

    hostnames = []
    for h in hosts:
        hostnames.append(h.hostname)
    return hostnames


class PtpInstance(ptp_paramowner.PtpParameterOwner):

    dbapi = db_api.get_instance()

    fields = dict({
            'name': utils.str_or_none,
            'service': utils.str_or_none,
            'hosts': utils.list_of_strings_or_none
             }, **ptp_paramowner.PtpParameterOwner.fields)

    _foreign_fields = {
        'hosts': get_hosts
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ptp_instance_get(uuid)
