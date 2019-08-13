# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class Certificate(base.SysinvObject):
    # VERSION 1.0: Initial version
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {'uuid': utils.uuid_or_none,
              'certtype': utils.str_or_none,
              'issuer': utils.str_or_none,
              'signature': utils.str_or_none,
              'start_date': utils.datetime_or_str_or_none,
              'expiry_date': utils.datetime_or_str_or_none,
              }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.certificate_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.certificate_update(self.uuid,  # pylint: disable=no-member
                                      updates)
