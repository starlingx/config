#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Extended coverage tests for tsconfig.tsconfig module."""

import io
import sys
import unittest
from unittest import mock


class TestTsconfigLoad(unittest.TestCase):
    """Tests for tsconfig._load function and module-level attributes."""

    mock_os_release = u'VERSION_CODENAME=bullseye\n'

    mock_build_info = u"""
[build_info]
SW_VERSION="22.12"
"""

    mock_platform_conf_full = u"""
nodetype=controller
subfunction=controller,worker
system_type=Standard
security_profile=extended
management_interface=enp0s8
http_port=8080
INSTALL_UUID=test-uuid-1234
UUID=host-uuid-5678
oam_interface=enp0s3
cluster_host_interface=enp0s4
sdn_enabled=no
region_config=yes
region_1_name=Region1
region_2_name=Region2
distributed_cloud_role=systemcontroller
system_mode=duplex
security_feature="nopti nospectre_v2"
vswitch_type=ovs-dpdk
"""

    def setUp(self):
        """Clear tsconfig modules before each test."""
        mod = sys.modules.get('tsconfig.tsconfig')
        if mod and hasattr(mod, 'get_debian_codename'):
            mod.get_debian_codename.cache_clear()
        sys.modules.pop('tsconfig.tsconfig', None)
        sys.modules.pop('tsconfig', None)

    def tearDown(self):
        """Clean up tsconfig modules."""
        try:
            del sys.modules['tsconfig.tsconfig']
            del sys.modules['tsconfig']
        except KeyError:
            pass

    @mock.patch('six.moves.builtins.open')
    @mock.patch('os.path.isfile', return_value=True)
    def test_load_full_platform_conf(self, mock_isfile, mock_open):
        """_load reads all platform.conf options."""
        mock_open.side_effect = [
            io.StringIO(self.mock_build_info),
            io.StringIO(self.mock_os_release),
            io.StringIO(self.mock_platform_conf_full),
        ]
        from tsconfig import tsconfig
        self.assertEqual(tsconfig.SW_VERSION, "22.12")
        self.assertEqual(tsconfig.nodetype, "controller")
        self.assertEqual(tsconfig.subfunctions,
                         ["controller", "worker"])
        self.assertEqual(tsconfig.system_type, "Standard")
        self.assertEqual(tsconfig.security_profile, "extended")
        self.assertEqual(tsconfig.management_interface, "enp0s8")
        self.assertEqual(tsconfig.http_port, "8080")
        self.assertEqual(tsconfig.host_uuid, "host-uuid-5678")
        self.assertEqual(tsconfig.install_uuid, "test-uuid-1234")
        self.assertEqual(tsconfig.oam_interface, "enp0s3")
        self.assertEqual(tsconfig.cluster_host_interface, "enp0s4")
        self.assertEqual(tsconfig.sdn_enabled, "no")
        self.assertEqual(tsconfig.region_config, "yes")
        self.assertEqual(tsconfig.region_1_name, "Region1")
        self.assertEqual(tsconfig.region_2_name, "Region2")
        self.assertEqual(tsconfig.distributed_cloud_role,
                         "systemcontroller")
        self.assertEqual(tsconfig.system_mode, "duplex")
        self.assertIn("nopti", tsconfig.security_feature)
        self.assertEqual(tsconfig.vswitch_type, "ovs-dpdk")

    def test_load_missing_build_info(self):
        """_load sets TEST.SW.VERSION when build.info missing."""
        from tsconfig import tsconfig
        self.assertEqual(tsconfig.SW_VERSION, "TEST.SW.VERSION")
        self.assertEqual(tsconfig.nodetype, "controller")

    @mock.patch('six.moves.builtins.open')
    @mock.patch('os.path.isfile', return_value=True)
    def test_load_platform_conf_minimal(self, mock_isfile, mock_open):
        """_load handles minimal platform.conf."""
        mock_open.side_effect = [
            io.StringIO(self.mock_build_info),
            io.StringIO(self.mock_os_release),
            io.StringIO(u"nodetype=worker\nsubfunction=worker\n"),
        ]
        from tsconfig import tsconfig
        self.assertEqual(tsconfig.nodetype, "worker")
        self.assertEqual(tsconfig.subfunctions, ["worker"])


class TestTsconfigPaths(unittest.TestCase):
    """Tests for tsconfig path constants."""

    def test_platform_conf_path(self):
        """PLATFORM_CONF_PATH is /etc/platform."""
        from tsconfig import tsconfig
        self.assertEqual(tsconfig.PLATFORM_CONF_PATH, "/etc/platform")

    def test_platform_conf_file(self):
        """PLATFORM_CONF_FILE is under PLATFORM_CONF_PATH."""
        from tsconfig import tsconfig
        self.assertTrue(
            tsconfig.PLATFORM_CONF_FILE.startswith(
                tsconfig.PLATFORM_CONF_PATH
            )
        )

    def test_volatile_path(self):
        """VOLATILE_PATH is /var/run."""
        from tsconfig import tsconfig
        self.assertEqual(tsconfig.VOLATILE_PATH, "/var/run")

    def test_platform_path(self):
        """PLATFORM_PATH is /opt/platform."""
        from tsconfig import tsconfig
        self.assertEqual(tsconfig.PLATFORM_PATH, "/opt/platform")

    def test_config_path_contains_sw_version(self):
        """CONFIG_PATH contains SW_VERSION."""
        from tsconfig import tsconfig
        self.assertIn(tsconfig.SW_VERSION, tsconfig.CONFIG_PATH)

    def test_puppet_path_contains_sw_version(self):
        """PUPPET_PATH contains SW_VERSION."""
        from tsconfig import tsconfig
        self.assertIn(tsconfig.SW_VERSION, tsconfig.PUPPET_PATH)

    def test_helm_overrides_path(self):
        """HELM_OVERRIDES_PATH contains SW_VERSION."""
        from tsconfig import tsconfig
        self.assertIn(tsconfig.SW_VERSION, tsconfig.HELM_OVERRIDES_PATH)

    def test_keyring_path(self):
        """KEYRING_PATH contains SW_VERSION."""
        from tsconfig import tsconfig
        self.assertIn(tsconfig.SW_VERSION, tsconfig.KEYRING_PATH)

    def test_deploy_path(self):
        """DEPLOY_PATH contains SW_VERSION."""
        from tsconfig import tsconfig
        self.assertIn(tsconfig.SW_VERSION, tsconfig.DEPLOY_PATH)

    def test_etcd_path(self):
        """ETCD_PATH is /opt/etcd."""
        from tsconfig import tsconfig
        self.assertEqual(tsconfig.ETCD_PATH, "/opt/etcd")

    def test_extension_path(self):
        """EXTENSION_PATH is /opt/extension."""
        from tsconfig import tsconfig
        self.assertEqual(tsconfig.EXTENSION_PATH, "/opt/extension")

    def test_platform_backup_path(self):
        """PLATFORM_BACKUP_PATH is /opt/platform-backup."""
        from tsconfig import tsconfig
        self.assertEqual(tsconfig.PLATFORM_BACKUP_PATH,
                         "/opt/platform-backup")


class TestTsconfigFlags(unittest.TestCase):
    """Tests for tsconfig flag path constants."""

    def test_initial_controller_config_complete(self):
        """Verify INITIAL_CONTROLLER_CONFIG_COMPLETE path."""
        from tsconfig import tsconfig
        self.assertTrue(
            tsconfig.INITIAL_CONTROLLER_CONFIG_COMPLETE.startswith(
                tsconfig.PLATFORM_CONF_PATH
            )
        )

    def test_volatile_controller_config_complete(self):
        """VOLATILE_CONTROLLER_CONFIG_COMPLETE is under VOLATILE_PATH.

        """
        from tsconfig import tsconfig
        self.assertTrue(
            tsconfig.VOLATILE_CONTROLLER_CONFIG_COMPLETE.startswith(
                tsconfig.VOLATILE_PATH
            )
        )

    def test_initial_config_complete_flag(self):
        """INITIAL_CONFIG_COMPLETE_FLAG is under PLATFORM_CONF_PATH."""
        from tsconfig import tsconfig
        self.assertTrue(
            tsconfig.INITIAL_CONFIG_COMPLETE_FLAG.startswith(
                tsconfig.PLATFORM_CONF_PATH
            )
        )

    def test_controller_upgrade_flag(self):
        """CONTROLLER_UPGRADE_FLAG is under PLATFORM_CONF_PATH."""
        from tsconfig import tsconfig
        self.assertTrue(
            tsconfig.CONTROLLER_UPGRADE_FLAG.startswith(
                tsconfig.PLATFORM_CONF_PATH
            )
        )

    def test_backup_in_progress_flag(self):
        """BACKUP_IN_PROGRESS_FLAG is under PLATFORM_CONF_PATH."""
        from tsconfig import tsconfig
        self.assertTrue(
            tsconfig.BACKUP_IN_PROGRESS_FLAG.startswith(
                tsconfig.PLATFORM_CONF_PATH
            )
        )

    def test_restore_in_progress_flag(self):
        """RESTORE_IN_PROGRESS_FLAG is under PLATFORM_CONF_PATH."""
        from tsconfig import tsconfig
        self.assertTrue(
            tsconfig.RESTORE_IN_PROGRESS_FLAG.startswith(
                tsconfig.PLATFORM_CONF_PATH
            )
        )

    def test_upgrade_abort_flag(self):
        """UPGRADE_ABORT_FLAG is under CONFIG_PATH."""
        from tsconfig import tsconfig
        self.assertTrue(
            tsconfig.UPGRADE_ABORT_FLAG.startswith(tsconfig.CONFIG_PATH)
        )

    def test_skip_ceph_osd_wiping(self):
        """SKIP_CEPH_OSD_WIPING is under CONFIG_PATH."""
        from tsconfig import tsconfig
        self.assertTrue(
            tsconfig.SKIP_CEPH_OSD_WIPING.startswith(
                tsconfig.CONFIG_PATH
            )
        )

    def test_restore_system_flag(self):
        """RESTORE_SYSTEM_FLAG is under CONFIG_PATH."""
        from tsconfig import tsconfig
        self.assertTrue(
            tsconfig.RESTORE_SYSTEM_FLAG.startswith(
                tsconfig.CONFIG_PATH
            )
        )

    def test_mgmt_network_reconfiguration_ongoing(self):
        """Verify MGMT_NETWORK_RECONFIG_ONGOING path."""
        from tsconfig import tsconfig
        self.assertTrue(
            tsconfig.MGMT_NETWORK_RECONFIGURATION_ONGOING.startswith(
                tsconfig.PLATFORM_CONF_PATH
            )
        )

    def test_upgrade_do_not_use_fqdn(self):
        """UPGRADE_DO_NOT_USE_FQDN is under PLATFORM_CONF_PATH."""
        from tsconfig import tsconfig
        self.assertTrue(
            tsconfig.UPGRADE_DO_NOT_USE_FQDN.startswith(
                tsconfig.PLATFORM_CONF_PATH
            )
        )


class TestGetDebianCodename(unittest.TestCase):
    """Tests for get_debian_codename function."""

    def setUp(self):
        mod = sys.modules.get('tsconfig.tsconfig')
        if mod and hasattr(mod, 'get_debian_codename'):
            mod.get_debian_codename.cache_clear()
        sys.modules.pop('tsconfig.tsconfig', None)
        sys.modules.pop('tsconfig', None)

    def tearDown(self):
        try:
            del sys.modules['tsconfig.tsconfig']
            del sys.modules['tsconfig']
        except KeyError:
            pass

    @mock.patch('six.moves.builtins.open')
    @mock.patch('os.path.isfile', return_value=False)
    def test_get_debian_codename_reads_os_release(self, mock_isfile,
                                                  mock_open):
        """get_debian_codename reads /etc/os-release."""
        mock_open.return_value = io.StringIO(
            u'VERSION_CODENAME=bullseye\n'
        )
        from tsconfig import tsconfig
        tsconfig.get_debian_codename.cache_clear()
        with mock.patch('builtins.open',
                        return_value=io.StringIO(
                            u'VERSION_CODENAME=trixie\n')):
            result = tsconfig.get_debian_codename()
        self.assertEqual(result, "trixie")

    @mock.patch('six.moves.builtins.open')
    @mock.patch('os.path.isfile', return_value=False)
    def test_is_debian_bullseye(self, mock_isfile, mock_open):
        """is_debian_bullseye returns True for bullseye."""
        mock_open.return_value = io.StringIO(u'')
        from tsconfig import tsconfig
        tsconfig.get_debian_codename.cache_clear()
        with mock.patch.object(tsconfig, 'get_debian_codename',
                               return_value='bullseye'):
            self.assertTrue(tsconfig.is_debian_bullseye())

    @mock.patch('six.moves.builtins.open')
    @mock.patch('os.path.isfile', return_value=False)
    def test_is_debian_bullseye_false(self, mock_isfile, mock_open):
        """is_debian_bullseye returns False for non-bullseye."""
        mock_open.return_value = io.StringIO(u'')
        from tsconfig import tsconfig
        tsconfig.get_debian_codename.cache_clear()
        with mock.patch.object(tsconfig, 'get_debian_codename',
                               return_value='trixie'):
            self.assertFalse(tsconfig.is_debian_bullseye())


if __name__ == "__main__":
    unittest.main()
