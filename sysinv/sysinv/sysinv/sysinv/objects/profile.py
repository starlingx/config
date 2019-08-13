#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class Profile(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'recordtype': utils.str_or_none,

            # 'created_at': utils.datetime_str_or_none,
            # 'updated_at': utils.datetime_str_or_none,
            'hostname': utils.str_or_none,
            'personality': utils.str_or_none,
            # Host is working on a blocking process
            'reserved': utils.str_or_none,
            # NOTE: instance_uuid must be read-only when server is provisioned
            'uuid': utils.str_or_none,

            # NOTE: driver should be read-only after server is created
            'invprovision': utils.str_or_none,
            'mgmt_mac': utils.str_or_none,
            'mgmt_ip': utils.str_or_none,

            # Board management members
            'bm_ip': utils.str_or_none,
            'bm_mac': utils.str_or_none,
            'bm_type': utils.str_or_none,
            'bm_username': utils.str_or_none,

            'location': utils.dict_or_none,
            # 'reservation': utils.str_or_none,
            'serialid': utils.str_or_none,
            'administrative': utils.str_or_none,
            'operational': utils.str_or_none,
            'availability': utils.str_or_none,
            'action': utils.str_or_none,
            'task': utils.str_or_none,
            'uptime': utils.int_or_none,

            'boot_device': utils.str_or_none,
            'rootfs_device': utils.str_or_none,
            'install_output': utils.str_or_none,
            'console': utils.str_or_none,
            'tboot': utils.str_or_none,
             }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ihost_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.ihost_update(self.uuid,  # pylint: disable=no-member
                                updates)
