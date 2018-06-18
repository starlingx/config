#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class Memory(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,
            'forinodeid': utils.int_or_none,
            'inode_uuid': utils.str_or_none,
            'forihostid': int,
            'ihost_uuid': utils.str_or_none,
            'numa_node': utils.int_or_none,

            'memtotal_mib': utils.int_or_none,
            'memavail_mib': utils.int_or_none,
            'platform_reserved_mib': utils.int_or_none,
            'node_memtotal_mib': utils.int_or_none,

            'hugepages_configured': utils.str_or_none,

            'vswitch_hugepages_size_mib': utils.int_or_none,
            'vswitch_hugepages_reqd': utils.int_or_none,
            'vswitch_hugepages_nr': utils.int_or_none,
            'vswitch_hugepages_avail': utils.int_or_none,

            'vm_hugepages_nr_2M_pending': utils.int_or_none,
            'vm_hugepages_nr_1G_pending': utils.int_or_none,
            'vm_hugepages_nr_2M': utils.int_or_none,
            'vm_hugepages_avail_2M': utils.int_or_none,
            'vm_hugepages_nr_1G': utils.int_or_none,
            'vm_hugepages_avail_1G': utils.int_or_none,
            'vm_hugepages_nr_4K': utils.int_or_none,


            'vm_hugepages_use_1G': utils.str_or_none,
            'vm_hugepages_possible_2M': utils.int_or_none,
            'vm_hugepages_possible_1G': utils.int_or_none,
            'capabilities': utils.dict_or_none,
             }

    _foreign_fields = {'ihost_uuid': 'host:uuid',
                       'inode_uuid': 'node:uuid',
                       'numa_node': 'node:numa_node'}

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.imemory_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.imemory_update(self.uuid, updates)
