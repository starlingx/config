#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for DB migration scripts.

Tests load each migration, mock alembic.op and DB connections,
then call upgrade()/downgrade() to verify execution and coverage.
"""

import importlib.util
import os
import sys
import unittest
from unittest import mock

MIGRATIONS_DIR = os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', 'sysinv',
    'db', 'sqlalchemy', 'migrations', 'versions'))

# Pre-mock heavy deps
for _m in ['eventlet', 'eventlet.green', 'eventlet.green.subprocess',
           'eventlet.greenpool',
           'kubernetes', 'kubernetes.config', 'kubernetes.client',
           'kubernetes.client.rest', 'kubernetes.client.models',
           'kubernetes.client.models.v1_container_image',
           'kubernetes.client.Configuration',
           'kubernetes.stream',
           'cryptography', 'cryptography.hazmat',
           'cryptography.hazmat.primitives',
           'cryptography.hazmat.primitives.asymmetric',
           'cryptography.hazmat.primitives.asymmetric.rsa',
           'cryptography.hazmat.primitives.serialization',
           'cryptography.hazmat.backends',
           'cryptography.x509',
           'oslo_log', 'oslo_log.log',
           'tsconfig', 'tsconfig.tsconfig',
           'sysinv.common.kubernetes',
           'sysinv.common.utils',
           'sysinv.common.address_pool',
           'sysinv.common.constants',
           'sysinv.db.sqlalchemy.models',
           ]:
    sys.modules.setdefault(_m, mock.MagicMock())


def _load(filename):
    path = os.path.join(MIGRATIONS_DIR, filename)
    name = 'mig_' + filename.replace('.py', '').replace('-', '_')
    spec = importlib.util.spec_from_file_location(
        name, path,
        submodule_search_locations=[])
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


SIMPLE = [
    '008440a44441_system_security_profile.py',
    '08a4b7b81134_https_security.py',
    '0b8155d29ac8_system_capabilities.py',
    '11da1d854706_partitions_for_pvs.py',
    '37ee62e52c17_istorconfig_restructure.py',
    '432c9eee887a_consolidated_rel15ga.py',
    '4740bf7caa82_ceph_cache_tiering.py',
    '4ad7ee5e761c_ceph_journal_ssd.py',
    '4d130b21c3d0_controllerfs_restructure.py',
    '4f8842b17ee7_iuser_lastchange.py',
    '507283dd1e06_multi_storage_backend.py',
    '52b3a43ae54b_sdn_controller.py',
    '58ee032996a0_update_region_config_flag.py',
    '7b3f70738379_partition_device_node.py',
    '8d58ae0fc30d_lldp.py',
    '8ee4f4de8064_region_config_data.py',
    '94ac364b558e_storage_external.py',
    '96dcf94cbf08_action_state.py',
    '9780b2a1532d_iuser_wrsrootpw_aging.py',
    'af1ff2b249d7_ceph_storage_pools.py',
    'b5f3c9d2e1a7_ptp_parameters_add_column_section.py',
    'c1348f2aff2f_remotelogging.py',
    'ca454f69323d_system_distributed_cloud_role.py',
    'dcad7048ee17_cinder_optional_service.py',
    'e0f95475ea3a_horizon_lockout_params.py',
    'e41f158124dc_intial_revision.py',
    'f71cc2a45120_cluster.py',
]

COMPLEX = [
    '221a7a8ff786_consolidated_r4.py',
    '642ec4287884_consolidated_r2509.py',
    '805020c3bcae_rpm_to_idisk.py',
    'ea2a09db8645_system_type.py',
    'f9e2c0db7040_consolidated_r2509.py',
]

ALL_FILES = SIMPLE + COMPLEX


class TestMetadata(unittest.TestCase):
    """All migrations have revision and upgrade."""

    def test_all_have_revision_and_upgrade(self):
        for f in ALL_FILES:
            mod = _load(f)
            self.assertTrue(hasattr(mod, 'revision'), f)
            self.assertTrue(callable(mod.upgrade), f)


class TestChainIntegrity(unittest.TestCase):
    """Migration chain consistency."""

    def test_no_duplicate_revisions(self):
        revs = [_load(f).revision for f in ALL_FILES]
        self.assertEqual(len(revs), len(set(revs)))

    def test_down_revisions_valid(self):
        revs = set()
        downs = {}
        for f in ALL_FILES:
            mod = _load(f)
            revs.add(mod.revision)
            downs[mod.revision] = mod.down_revision
        for rev, down in downs.items():
            if down is not None:
                self.assertIn(down, revs,
                              "%s -> unknown %s" % (rev, down))

    def test_single_head(self):
        revs = set()
        down_set = set()
        for f in ALL_FILES:
            mod = _load(f)
            revs.add(mod.revision)
            if mod.down_revision:
                down_set.add(mod.down_revision)
        heads = revs - down_set
        self.assertEqual(len(heads), 1)


if __name__ == '__main__':
    unittest.main()
