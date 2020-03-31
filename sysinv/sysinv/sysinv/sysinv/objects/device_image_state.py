#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class DeviceImageState(base.SysinvObject):
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {'id': int,
              'uuid': utils.uuid_or_none,
              'host_id': utils.int_or_none,
              'host_uuid': utils.uuid_or_none,
              'pcidevice_id': utils.int_or_none,
              'pcidevice_uuid': utils.uuid_or_none,
              'image_id': utils.int_or_none,
              'image_uuid': utils.uuid_or_none,
              'status': utils.str_or_none,
              'update_start_time': utils.datetime_or_str_or_none,
              'capabilities': utils.dict_or_none,
              }

    _foreign_fields = {
        'host_uuid': 'host:uuid',
        'pcidevice_uuid': 'pcidevice:uuid',
        'image_uuid': 'image:uuid',
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.device_image_state_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.device_image_state_update(self.uuid,  # pylint: disable=no-member
                                             updates)
