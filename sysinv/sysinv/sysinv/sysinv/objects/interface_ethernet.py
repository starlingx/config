#
# Copyright (c) 2013-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.objects import base
from sysinv.objects import utils
from sysinv.objects import interface_base


class EthernetInterface(interface_base.InterfaceBase):

    fields = dict({
        'imtu': utils.int_or_none,
        'imac': utils.str_or_none,
    }, **interface_base.InterfaceBase.fields)

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ethernet_interface_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.ethernet_interface_update(self.uuid, updates)
