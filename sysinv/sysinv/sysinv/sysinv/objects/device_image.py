#
# Copyright (c) 2020-2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class DeviceImage(base.SysinvObject):
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {'id': int,
              'uuid': utils.uuid_or_none,
              'bitstream_type': utils.str_or_none,
              'pci_vendor': utils.str_or_none,
              'pci_device': utils.str_or_none,
              'bitstream_id': utils.str_or_none,
              'key_signature': utils.str_or_none,
              'revoke_key_id': utils.int_or_none,
              'name': utils.str_or_none,
              'description': utils.str_or_none,
              'image_version': utils.str_or_none,
              'applied': utils.bool_or_none,
              'capabilities': utils.dict_or_none,
              'bmc': utils.bool_or_none,
              'retimer_included': utils.bool_or_none,
              }

    _optional_fields = {'bitstream_id',
                        'key_signature',
                        'revoke_key_id',
                        'name',
                        'description',
                        'image_version',
                        'bmc',
                        'retimer_included'}

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.deviceimage_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.device_image_update(self.uuid,  # pylint: disable=no-member
                                       updates)
