#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class DeviceLabel(base.SysinvObject):
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'uuid': utils.str_or_none,
        'host_id': utils.str_or_none,
        'host_uuid': utils.str_or_none,
        'label_key': utils.str_or_none,
        'label_value': utils.str_or_none,
        'pcidevice_id': utils.int_or_none,
        'pcidevice_uuid': utils.str_or_none,
        'capabilities': utils.dict_or_none,
    }

    _foreign_fields = {
        'host_uuid': 'host:uuid',
        'pcidevice_uuid': 'pcidevice:uuid',
        'fpgadevice_uuid': 'fpgadevice:uuid',
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.device_label_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.device_label_update(self.uuid,  # pylint: disable=no-member
                                       updates)
