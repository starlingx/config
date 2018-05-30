# Copyright (c) 2015-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


def _get_firewall_sig(field, db_object):
    return db_object.value


class FirewallRules(base.SysinvObject):
    # VERSION 1.0: Initial version
    VERSION = '1.0'

    dbapi = db_api.get_instance()

    fields = {'uuid': utils.uuid_or_none,  # uuid of service_parameter
              'firewall_sig': _get_firewall_sig
              }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.service_parameter_get(uuid)

    def save_changes(self, context, updates):
        self.dbapi.service_parameter_update(self.uuid, updates)
