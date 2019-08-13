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
from sysinv.objects import port


class EthernetPort(port.Port):

    fields = dict({
            'mac': utils.str_or_none,
            'mtu': utils.int_or_none,
            'speed': utils.int_or_none,
            'link_mode': utils.str_or_none,
            'duplex': utils.int_or_none,
            'autoneg': utils.str_or_none,
            'bootp': utils.str_or_none},
        **port.Port.fields)

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.ethernet_port_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.ethernet_port_update(self.uuid,  # pylint: disable=no-member
                                        updates)
