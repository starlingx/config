#
# Copyright (c) 2020 Intel Corporation.
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.puppet import base
from sysinv.common.storage_backend_conf import StorageBackendConfig


class RookPuppet(base.BasePuppet):
    """Class to encapsulate puppet operations for rook"""

    def get_system_config(self):
        ceph_rook_backend = StorageBackendConfig.get_backend_conf(
            self.dbapi, constants.SB_TYPE_CEPH_ROOK)

        enable = False
        if ceph_rook_backend:
            enable = True

        config = {
            'platform::rook::params::service_enabled': enable,
        }
        return config
