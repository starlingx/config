#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


def get_range_values(field, db_object):
    """Retrieves the list of ranges associated to the address pool."""
    result = []
    for entry in getattr(db_object, 'ranges', []):
        result.append([entry.start, entry.end])
    return result


class AddressPool(base.SysinvObject):
    # VERSION 1.0: Initial version
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {'id': int,
              'uuid': utils.uuid_or_none,
              'name': utils.str_or_none,
              'order': utils.str_or_none,
              'family': utils.int_or_none,
              'network': utils.ip_str_or_none(),
              'prefix': utils.int_or_none,
              'controller0_address_id': utils.int_or_none,
              'controller1_address_id': utils.int_or_none,
              'floating_address_id': utils.int_or_none,
              'gateway_address_id': utils.int_or_none,
              'controller0_address': utils.ip_str_or_none(),
              'controller1_address': utils.ip_str_or_none(),
              'floating_address': utils.ip_str_or_none(),
              'gateway_address': utils.ip_str_or_none(),
              'ranges': list,
              }

    _foreign_fields = {
        'ranges': get_range_values,
        'controller0_address': 'controller0_address:address',
        'controller1_address': 'controller1_address:address',
        'floating_address': 'floating_address:address',
        'gateway_address': 'gateway_address:address',
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.address_pool_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.address_pool_update(self.uuid, updates)
