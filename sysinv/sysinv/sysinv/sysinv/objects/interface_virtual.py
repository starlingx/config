#
# Copyright (c) 2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.objects import base
from sysinv.objects import interface_ethernet


class VirtualInterface(interface_ethernet.EthernetInterface):

    fields = dict(**interface_ethernet.EthernetInterface.fields)

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.virtual_interface_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.virtual_interface_update(self.uuid,  # pylint: disable=no-member
                                            updates)
