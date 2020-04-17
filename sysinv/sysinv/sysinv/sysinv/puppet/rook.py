#
# Copyright (c) 2020 Intel Corporation.
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

    def get_host_config(self, host):
        config = {}
        config.update(self._get_lvm_config(host))
        return config

    def _get_lvm_config(self, host):
        rook_vgs = []

        # lvm named with ceph-xxxx is the disk provisioned by rook
        # system backup and restore will not erase these disk
        # when system restore, after unlock host, re-activate these vg
        pvs = self.dbapi.ipv_get_by_ihost(host.id)
        for pv in pvs:
            if pv.lvm_vg_name.startswith("ceph"):
                rook_vgs.append(pv.lvm_vg_name)

        return {
            'platform::rook::vg::rook_vg': rook_vgs,
        }
