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


def _get_interface_name_list(field, db_object):
    ifnames = []
    for i in db_object[field]:
        ifnames.append(i['ifname'])
    return ifnames


class InterfaceBase(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
            'id': int,
            'uuid': utils.str_or_none,
            'forihostid': utils.int_or_none,
            'iftype': utils.str_or_none,
            'ifname': utils.str_or_none,
            'networktype': utils.str_or_none,
            'ifcapabilities': utils.dict_or_none,
            'farend': utils.dict_or_none,
            'uses': utils.list_of_strings_or_none,
            'used_by': utils.list_of_strings_or_none,
            'sriov_numvfs': utils.int_or_none
             }

    _foreign_fields = {
        'uses': _get_interface_name_list,
        'used_by': _get_interface_name_list,
    }

    @base.remotable_classmethod
    def get_by_uuid(cls, context, uuid):
        return cls.dbapi.interface_get(uuid)
