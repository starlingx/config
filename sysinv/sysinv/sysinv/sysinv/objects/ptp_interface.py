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


class PtpInterface(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,

            'interface_uuid': utils.str_or_none,
            'interface_id': utils.int_or_none,

            'ptp_instance_uuid': utils.str_or_none,
            'ptp_instance_id': utils.int_or_none,
            'ptp_instance_name': utils.str_or_none,

            'ifname': utils.str_or_none,
            'forihostid': utils.int_or_none,

             }

    _foreign_fields = {
        'interface_uuid': 'interface:uuid',
        'interface_id': 'interface:id',
        'ptp_instance_uuid': 'ptp_instance:uuid',
        'ptp_instance_name': 'ptp_instance:name',
        'ifname': 'interface:ifname',
        'forihostid': 'interface:forihostid',
        'ptp_instance_host': 'ptp_instance:host_id'

    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ptp_interface_get(uuid)
