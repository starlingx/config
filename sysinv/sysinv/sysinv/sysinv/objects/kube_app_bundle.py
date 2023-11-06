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


class KubeAppBundle(base.SysinvObject):

    dbapi = db_api.get_instance()

    fields = {
        'id': int,
        'name': utils.str_or_none,
        'version': utils.str_or_none,
        'file_path': utils.str_or_none,
        'auto_update': utils.bool_or_none,
        'k8s_auto_update': utils.bool_or_none,
        'k8s_timing': utils.str_or_none,
        'k8s_minimum_version': utils.str_or_none,
        'k8s_maximum_version': utils.str_or_none,
        'reserved': utils.dict_or_none
    }
