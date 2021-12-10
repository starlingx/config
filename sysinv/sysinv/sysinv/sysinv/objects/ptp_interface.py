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
    interface_list = []
    if interfaces is not None:
        for i in interfaces:
            host = getattr(i, 'host')
            interface = '%s/%s' % (host.hostname, i.ifname)
            interface_list.append(interface)
    return interface_list


def get_hostnames(field, db_object):
    interfaces = db_object['interfaces']
    hostnames = []
    if interfaces is not None:
        for i in interfaces:
            host = getattr(i, 'host')
            hostnames.append(host.hostname)
    return hostnames


class PtpInterface(ptp_paramowner.PtpParameterOwner):

    dbapi = db_api.get_instance()

    fields = dict({
            'id': int,
            'name': utils.str_or_none,
            'ptp_instance_id': int,
            'ptp_instance_uuid': utils.str_or_none,
            'ptp_instance_name': utils.str_or_none,
            'interface_names': utils.list_of_strings_or_none,
            'hostnames': utils.list_of_strings_or_none,
            'parameters': utils.list_of_strings_or_none
             }, **ptp_paramowner.PtpParameterOwner.fields)

    _foreign_fields = {
        'ptp_instance_id': 'ptp_instance:id',
        'ptp_instance_uuid': 'ptp_instance:uuid',
        'ptp_instance_name': 'ptp_instance:name',
        'interface_names': get_interfaces,
        'hostnames': get_hostnames,
        'parameters': ptp_paramowner.get_parameters
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ptp_interface_get(uuid)
