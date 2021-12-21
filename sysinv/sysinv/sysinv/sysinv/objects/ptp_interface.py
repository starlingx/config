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


def get_interfaces(field, db_object):
    interfaces = db_object['interfaces']
    if not interfaces:
        return []

    interfaces = []
    for i in interfaces:
        details = {}
        details['name'] = i.ifname
        details['type'] = i.iftype
        host = getattr(i, 'host')
        if host:
            details['host'] = host.hostname
        interfaces.append(details)

    return interfaces


class PtpInterface(ptp_paramowner.PtpParameterOwner):

    dbapi = db_api.get_instance()

    fields = dict({
            'name': utils.str_or_none,
            'ptp_instance_id': utils.int_or_none,
            'ptp_instance_uuid': utils.str_or_none,
            'ptp_instance_name': utils.str_or_none,
            'interfaces': list
             }, **ptp_paramowner.PtpParameterOwner.fields)

    _foreign_fields = {
        'ptp_instance_uuid': 'ptp_instance:uuid',
        'ptp_instance_name': 'ptp_instance:name',
        'interfaces': get_interfaces
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ptp_interface_get(uuid)
