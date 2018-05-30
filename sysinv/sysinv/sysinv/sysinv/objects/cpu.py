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


class CPU(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,
            'forihostid': int,
            'ihost_uuid': utils.str_or_none,
            'forinodeid': utils.int_or_none,
            'inode_uuid': utils.str_or_none,
            'numa_node': utils.int_or_none,
            'cpu': int,
            'core': utils.int_or_none,
            'thread': utils.int_or_none,
            'cpu_family': utils.str_or_none,
            'cpu_model': utils.str_or_none,
            'allocated_function': utils.str_or_none,
            # 'coprocessors': utils.dict_or_none,
            'capabilities': utils.dict_or_none,
             }

    _foreign_fields = {'ihost_uuid': 'host:uuid',
                       'inode_uuid': 'node:uuid',
                       'numa_node': 'node:numa_node'}

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.icpu_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.icpu_update(self.uuid, updates)
