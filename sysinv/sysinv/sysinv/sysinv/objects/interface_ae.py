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
from sysinv.objects import interface_ethernet


class AEInterface(interface_ethernet.EthernetInterface):

    fields = dict({
        'aemode': utils.str_or_none,
        'schedpolicy': utils.str_or_none,
        'txhashpolicy': utils.str_or_none,
        'ifcapabilities': utils.dict_or_none,
    }, **interface_ethernet.EthernetInterface.fields)

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ae_interface_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.ae_interface_update(self.uuid, updates)
