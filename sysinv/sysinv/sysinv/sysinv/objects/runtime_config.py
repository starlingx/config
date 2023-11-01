#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

from sysinv.db import api as db_api
from sysinv.objects import base
from sysinv.objects import utils


class RuntimeConfig(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'config_uuid': utils.str_or_none,
        'config_dict': utils.str_or_none,
        'state': utils.str_or_none,
        'forihostid': utils.int_or_none,
        'reserved_1': utils.str_or_none,
    }
