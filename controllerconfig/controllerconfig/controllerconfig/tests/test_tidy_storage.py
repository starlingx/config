#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for controllerconfig.tidy_storage module."""

import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

# Mock heavy external deps before importing tidy_storage
sys.modules['keystoneclient'] = mock.MagicMock()
sys.modules['keystoneclient.auth'] = mock.MagicMock()
sys.modules['keystoneclient.auth.identity'] = mock.MagicMock()
sys.modules['keystoneclient.auth.identity.v3'] = mock.MagicMock()
sys.modules['keystoneauth1'] = mock.MagicMock()
sys.modules['keystoneauth1.session'] = mock.MagicMock()
sys.modules['cinderclient'] = mock.MagicMock()
sys.modules['cinderclient.v3'] = mock.MagicMock()
sys.modules['cinderclient.v3.client'] = mock.MagicMock()
sys.modules['cinderclient.utils'] = mock.MagicMock()
sys.modules['glanceclient'] = mock.MagicMock()

from controllerconfig import tidy_storage  # noqa: E402
from controllerconfig.common.exceptions import TidyStorageFail  # noqa: E402,E501


class FmtStr(str):
    """String subclass whose encode() returns a formattable string."""

    def encode(self, *args, **kwargs):
        return FmtStr(str(self))


class TestOpenStackInit(unittest.TestCase):
    """Tests for OpenStack.__init__."""

    @mock.patch.dict(os.environ, {
        'OS_USERNAME': 'admin',
        'OS_PASSWORD': 'pass',
        'OS_PROJECT_NAME': 'admin',
        'OS_AUTH_URL': ('http://keystone.openstack'
                        '.svc.cluster.local:5000/v3'),
        'OS_REGION_NAME': 'RegionOne',
        'OS_USER_DOMAIN_NAME': 'Default',
        'OS_PROJECT_DOMAIN_NAME': 'Default',
    })
    def test_init_from_env(self):
        """OpenStack reads config from environment variables."""
        obj = tidy_storage.OpenStack()
        self.assertEqual(obj.conf['admin_user'], 'admin')
        self.assertEqual(obj.conf['admin_pwd'], 'pass')

    @mock.patch.dict(os.environ, {
        'OS_USERNAME': 'admin',
        'OS_PASSWORD': 'pass',
        'OS_PROJECT_NAME': 'admin',
        'OS_AUTH_URL': 'http://wrong-host:5000/v3',
        'OS_REGION_NAME': 'RegionOne',
        'OS_USER_DOMAIN_NAME': 'Default',
        'OS_PROJECT_DOMAIN_NAME': 'Default',
    })
    def test_init_wrong_auth_url(self):
        """OpenStack raises TidyStorageFail for wrong auth_url."""
        with self.assertRaises(TidyStorageFail):
            tidy_storage.OpenStack()

    @mock.patch.dict(os.environ, {}, clear=True)
    @mock.patch('builtins.open', side_effect=IOError("no file"))
    def test_init_no_env_no_file(self, _mock_open):
        """OpenStack raises TidyStorageFail when no env and no config
        file.
        """
        with self.assertRaises(TidyStorageFail):
            tidy_storage.OpenStack()

    @mock.patch.dict(os.environ, {}, clear=True)
    @mock.patch('builtins.open', mock.mock_open(read_data=(
        'clouds:\n'
        '  openstack_helm:\n'
        '    auth:\n'
        '      username: admin\n'
        '      password: pass\n'
        '      project_name: admin\n'
        '      auth_url: http://keystone'
        '.openstack.svc.cluster'
        '.local:5000/v3\n'
        '      user_domain_name: Default\n'
        '      project_domain_name: Default\n'
        '    region_name: RegionOne\n'
    )))
    def test_init_from_clouds_yaml(self):
        """OpenStack reads config from clouds.yaml."""
        obj = tidy_storage.OpenStack()
        self.assertEqual(obj.conf['admin_user'], 'admin')

    @mock.patch.dict(os.environ, {}, clear=True)
    @mock.patch('builtins.open',
                mock.mock_open(
                    read_data='clouds:\n  openstack_helm:\n    auth: {}\n'
                )
                )
    def test_init_clouds_yaml_missing_keys(self):
        """OpenStack raises TidyStorageFail for missing keys in
        clouds.yaml.
        """
        with self.assertRaises(TidyStorageFail):
            tidy_storage.OpenStack()


class TestOpenStackConnectDisconnect(unittest.TestCase):
    """Tests for OpenStack connect/disconnect."""

    def _make_openstack(self):
        with mock.patch.dict(os.environ, {
            'OS_USERNAME': 'admin',
            'OS_PASSWORD': 'pass',
            'OS_PROJECT_NAME': 'admin',
            'OS_AUTH_URL': ('http://keystone.openstack'
                            '.svc.cluster.local:5000/v3'),
            'OS_REGION_NAME': 'RegionOne',
            'OS_USER_DOMAIN_NAME': 'Default',
            'OS_PROJECT_DOMAIN_NAME': 'Default',
        }):
            return tidy_storage.OpenStack()

    @mock.patch('controllerconfig.tidy_storage.get_token',
                return_value='tok-123')
    def test_connect_success(self, _mock_token):
        """_connect returns True on success."""
        obj = self._make_openstack()
        self.assertTrue(obj._connect())
        self.assertEqual(obj.admin_token, 'tok-123')

    @mock.patch('controllerconfig.tidy_storage.get_token',
                return_value=None)
    @mock.patch('time.sleep')
    def test_connect_failure(self, _mock_sleep, _mock_token):
        """_connect returns False when token cannot be obtained."""
        obj = self._make_openstack()
        tidy_storage.KEYSTONE_AUTH_SERVER_RETRY_CNT = 2
        result = obj._connect()
        tidy_storage.KEYSTONE_AUTH_SERVER_RETRY_CNT = 60
        self.assertFalse(result)

    @mock.patch('controllerconfig.tidy_storage.get_token',
                return_value='tok-123')
    def test_disconnect(self, _mock_token):
        """_disconnect sets admin_token to None."""
        obj = self._make_openstack()
        obj._connect()
        obj._disconnect()
        self.assertIsNone(obj.admin_token)

    @mock.patch('controllerconfig.tidy_storage.get_token',
                return_value='tok-123')
    def test_context_manager(self, _mock_token):
        """OpenStack works as context manager."""
        obj = self._make_openstack()
        with obj as client:
            self.assertIsNotNone(client.admin_token)
        self.assertIsNone(obj.admin_token)

    @mock.patch('controllerconfig.tidy_storage.get_token',
                return_value=None)
    @mock.patch('time.sleep')
    def test_context_manager_connect_fail(self,
                                          _mock_sleep,
                                          _mock_token
                                          ):
        """OpenStack context manager raises on connect failure."""
        obj = self._make_openstack()
        tidy_storage.KEYSTONE_AUTH_SERVER_RETRY_CNT = 1
        with self.assertRaises(Exception):  # noqa: H202
            with obj:
                pass  # pragma: no cover
        tidy_storage.KEYSTONE_AUTH_SERVER_RETRY_CNT = 60

    @mock.patch('controllerconfig.tidy_storage.get_token',
                return_value='tok-123')
    def test_reconnect_disconnects_first(self, _mock_token):
        """_connect disconnects existing token before reconnecting."""
        obj = self._make_openstack()
        obj.admin_token = 'old-token'
        obj._connect()
        self.assertEqual(obj.admin_token, 'tok-123')


class TestOpenStackClients(unittest.TestCase):
    """Tests for get_cinder_client and get_glance_client properties."""

    def _make_openstack(self):
        with mock.patch.dict(os.environ, {
            'OS_USERNAME': 'admin',
            'OS_PASSWORD': 'pass',
            'OS_PROJECT_NAME': 'admin',
            'OS_AUTH_URL': ('http://keystone.openstack'
                            '.svc.cluster.local:5000/v3'),
            'OS_REGION_NAME': 'RegionOne',
            'OS_USER_DOMAIN_NAME': 'Default',
            'OS_PROJECT_DOMAIN_NAME': 'Default',
        }):
            return tidy_storage.OpenStack()

    @mock.patch('controllerconfig.tidy_storage.cinder_client_v3')
    @mock.patch('controllerconfig.tidy_storage.v3')
    @mock.patch('controllerconfig.tidy_storage.ksc_session')
    def test_get_cinder_client(self, _mock_sess, _mock_v3, mock_cinder):
        """get_cinder_client creates and caches client."""
        obj = self._make_openstack()
        client1 = obj.get_cinder_client
        client2 = obj.get_cinder_client
        self.assertIs(client1, client2)

    @mock.patch('controllerconfig.tidy_storage.Client')
    @mock.patch('controllerconfig.tidy_storage.v3')
    @mock.patch('controllerconfig.tidy_storage.ksc_session')
    def test_get_glance_client(self, _mock_sess, _mock_v3, mock_glance):
        """get_glance_client creates and caches client."""
        obj = self._make_openstack()
        client1 = obj.get_glance_client
        client2 = obj.get_glance_client
        self.assertIs(client1, client2)


class TestShowHelp(unittest.TestCase):
    """Tests for show_help function."""

    def test_show_help(self):
        """show_help prints usage info."""
        with mock.patch('builtins.print') as mock_print:
            tidy_storage.show_help()
        self.assertTrue(mock_print.called)


class TestMain(unittest.TestCase):
    """Tests for main function."""

    @mock.patch.object(tidy_storage, 'tidy_storage')
    @mock.patch.object(tidy_storage.log, 'configure')
    @mock.patch('builtins.open', mock.mock_open())
    def test_main_with_args(self, _mock_log, mock_tidy):
        """main calls tidy_storage with result file."""
        with mock.patch.object(
                sys,
                'argv',
                ['prog', '/tmp/result.txt']
        ):
            tidy_storage.main()
        mock_tidy.assert_called_once_with('/tmp/result.txt')

    def test_main_no_args(self):
        """main exits when no args provided."""
        with mock.patch.object(sys, 'argv', ['prog']):
            with self.assertRaises(SystemExit):
                tidy_storage.main()

    def test_main_help_flag(self):
        """main exits on --help."""
        with mock.patch.object(sys, 'argv', ['prog', '--help']):
            with self.assertRaises(SystemExit):
                tidy_storage.main()

    @mock.patch.object(tidy_storage.log, 'configure')
    @mock.patch('builtins.open', side_effect=IOError("no write"))
    def test_main_cannot_open_result_file(self, _mock_open, _mock_log):
        """main raises TidyStorageFail when result file cannot be
        opened.
        """
        with mock.patch.object(sys, 'argv', ['prog', '/bad/path']):
            with self.assertRaises(TidyStorageFail):
                tidy_storage.main()


class TestTidyStorage(unittest.TestCase):
    """Tests for tidy_storage function."""

    def _make_mock_openstack(self):
        """Create a mock OpenStack context manager."""
        mock_client = mock.MagicMock()
        mock_g_client = mock.MagicMock()
        mock_c_client = mock.MagicMock()

        # Glance images - empty
        mock_g_client.images.list.return_value = []
        mock_client.get_glance_client = mock_g_client

        # Cinder - empty
        mock_c_client.volume_snapshots.list.return_value = []
        mock_c_client.volumes.list.return_value = []
        mock_c_client.volume_types.default.return_value = None
        mock_c_client.availability_zones.list.return_value = []
        mock_c_client.pools.list.return_value = []
        mock_client.get_cinder_client = mock_c_client

        return mock_client

    @mock.patch('controllerconfig.tidy_storage.OpenStack')
    @mock.patch('subprocess.check_output')
    def test_tidy_storage_empty(self, mock_subproc, mock_os_cls):
        """tidy_storage handles empty glance/cinder/rbd."""
        mock_client = self._make_mock_openstack()
        mock_os_cls.return_value.__enter__ = mock.Mock(
            return_value=mock_client)
        mock_os_cls.return_value.__exit__ = (
            mock.Mock(return_value=False)
        )

        # rbd ls --pool images returns empty
        # rbd ls --pool cinder-volumes returns empty
        mock_subproc.return_value = ""

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt',
                                         delete=False) as f:
            result_file = f.name
        try:
            tidy_storage.tidy_storage(result_file)
            self.assertTrue(os.path.exists(result_file))
        finally:
            os.unlink(result_file)

    @mock.patch('controllerconfig.tidy_storage.OpenStack')
    @mock.patch('subprocess.check_output')
    def test_tidy_storage_rbd_images_fail(self,
                                          mock_subproc,
                                          mock_os_cls
                                          ):
        """tidy_storage raises when rbd images pool access fails."""
        mock_client = self._make_mock_openstack()
        mock_os_cls.return_value.__enter__ = mock.Mock(
            return_value=mock_client)
        mock_os_cls.return_value.__exit__ = (
            mock.Mock(return_value=False)
        )

        mock_subproc.side_effect = subprocess.CalledProcessError(
            1,
            "rbd"
        )

        with self.assertRaises(TidyStorageFail):
            tidy_storage.tidy_storage("/tmp/result.txt")

    @mock.patch('controllerconfig.tidy_storage.OpenStack')
    @mock.patch('subprocess.check_output')
    def test_tidy_storage_glance_list_fail(self,
                                           mock_subproc,
                                           mock_os_cls
                                           ):
        """tidy_storage raises when glance image list fails."""
        mock_client = self._make_mock_openstack()
        mock_client.get_glance_client.images.list.side_effect = \
            Exception("glance error")
        mock_os_cls.return_value.__enter__ = mock.Mock(
            return_value=mock_client)
        mock_os_cls.return_value.__exit__ = (
            mock.Mock(return_value=False)
        )

        with self.assertRaises(TidyStorageFail):
            tidy_storage.tidy_storage("/tmp/result.txt")

    @mock.patch('controllerconfig.tidy_storage.OpenStack')
    @mock.patch('subprocess.check_output')
    def test_tidy_storage_snap_no_backend_vol(self, mock_subproc,
                                              mock_os_cls):
        """tidy_storage logs snapshots whose backend volume is missing.
        """
        mock_client = self._make_mock_openstack()
        mock_os_cls.return_value.__enter__ = mock.Mock(
            return_value=mock_client)
        mock_os_cls.return_value.__exit__ = (
            mock.Mock(return_value=False)
        )

        mock_snap = mock.MagicMock()
        mock_snap.name = 'snap-orphan'
        mock_snap.id = FmtStr('snap-id-orphan')
        mock_snap.volume_id = 'vol-missing'

        mock_c = mock_client.get_cinder_client
        mock_c.volume_snapshots.list.return_value = [mock_snap]
        mock_c.volumes.list.return_value = []
        mock_c.volume_types.default.return_value = None
        mock_c.availability_zones.list.return_value = []
        mock_c.pools.list.return_value = []

        # rbd ls images: empty
        # rbd ls cinder-volumes (snap check): volume NOT found
        # rbd ls cinder-volumes (volume check): empty
        mock_subproc.side_effect = [
            "",   # rbd ls images
            "",   # rbd ls cinder-volumes (snap check) - vol not found
            "",   # rbd ls cinder-volumes (volume check)
        ]

        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt',
                                         delete=False) as f:
            result_file = f.name
        try:
            tidy_storage.tidy_storage(result_file)
            with open(result_file) as rf:
                content = rf.read()
            self.assertIn("snap-orphan", content)
        finally:
            os.unlink(result_file)

    @mock.patch('controllerconfig.tidy_storage.OpenStack')
    @mock.patch('subprocess.check_output')
    def test_tidy_storage_result_file_ioerror(self, mock_subproc,
                                              mock_os_cls):
        """tidy_storage raises TidyStorageFail on result file IOError.
        """
        mock_client = self._make_mock_openstack()
        mock_os_cls.return_value.__enter__ = mock.Mock(
            return_value=mock_client)
        mock_os_cls.return_value.__exit__ = (
            mock.Mock(return_value=False)
        )

        mock_c = mock_client.get_cinder_client
        mock_c.volume_snapshots.list.return_value = []
        mock_c.volumes.list.return_value = []
        mock_c.volume_types.default.return_value = None
        mock_c.availability_zones.list.return_value = []
        mock_c.pools.list.return_value = []

        mock_subproc.return_value = ""

        with self.assertRaises(TidyStorageFail):
            tidy_storage.tidy_storage("/nonexistent/dir/result.txt")


if __name__ == "__main__":
    unittest.main()
