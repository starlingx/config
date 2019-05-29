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


class Port(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,
            'host_id': utils.int_or_none,
            'host_uuid': utils.str_or_none,
            'node_id': utils.int_or_none,
            'node_uuid': utils.str_or_none,
            'interface_id': utils.int_or_none,
            'interface_uuid': utils.str_or_none,
            'type': utils.str_or_none,
            'name': utils.str_or_none,
            'namedisplay': utils.str_or_none,
            'pciaddr': utils.str_or_none,
            'dev_id': utils.int_or_none,
            'pclass': utils.str_or_none,
            'pvendor': utils.str_or_none,
            'pdevice': utils.str_or_none,
            'psvendor': utils.str_or_none,
            'dpdksupport': utils.bool_or_none,
            'psdevice': utils.str_or_none,
            'numa_node': utils.int_or_none,
            'sriov_totalvfs': utils.int_or_none,
            'sriov_numvfs': utils.int_or_none,
            'sriov_vfs_pci_address': utils.str_or_none,
            'sriov_vf_driver': utils.str_or_none,
            'driver': utils.str_or_none,
            'capabilities': utils.dict_or_none,
             }

    _foreign_fields = {'host_uuid': 'host:uuid',
                       'node_uuid': 'node:uuid',
                       'interface_uuid': 'interface:uuid'}

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.port_get(uuid)
