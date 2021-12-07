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


def get_hostname(field, db_object):
    host = getattr(db_object['interface'], 'host')
    if not host:
        return None

    return host.hostname


def get_instance_name(field, db_object):
    instance = getattr(db_object['ptp_interface'], 'ptp_instance')
    if not instance:
        return None

    return instance.name


def get_instance_service(field, db_object):
    instance = getattr(db_object['ptp_interface'], 'ptp_instance')
    if not instance:
        return None

    return instance.service


class PtpInterfaceMap(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,

            'interface_id': int,
            'ifname': utils.str_or_none,
            'iftype': utils.str_or_none,
            'hostname': utils.str_or_none,

            'ptp_interface_id': int,
            'name': utils.str_or_none,
            'service': utils.str_or_none
             }

    _foreign_fields = {
        'interface_id': 'interface:id',
        'ifname': 'interface:ifname',
        'iftype': 'interface:iftype',
        'hostname': get_hostname,
        'ptp_interface_id': 'ptp_interface:id',
        'name': get_instance_name,
        'service': get_instance_service
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ptp_interface_map_get(uuid)
