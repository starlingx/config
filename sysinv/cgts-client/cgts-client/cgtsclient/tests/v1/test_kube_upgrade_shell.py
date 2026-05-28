#
# Copyright (c) 2019,2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from cgtsclient.tests import test_shell
from cgtsclient.v1.kube_upgrade import KubeUpgrade


class KubeUpgradeTest(test_shell.ShellTest):

    def setUp(self):
        super(KubeUpgradeTest, self).setUp()

    def tearDown(self):
        super(KubeUpgradeTest, self).tearDown()

    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.list')
    def test_kube_upgrade_show(self, mock_list):
        fake_kube_upgrade = {'from_version': 'v1.42.1',
                             'to_version': 'v1.42.2',
                             'state': 'upgrade-started',
                             'uuid': 'cb737aba-1820-4184-b0dc-9b073822af48',
                             'created_at': 'fake-created-time',
                             'updated_at': 'fake-updated-time',
                             }
        fake_kube_upgrade_list = [KubeUpgrade(None, fake_kube_upgrade, True)]
        mock_list.return_value = fake_kube_upgrade_list

        self.make_env()
        results = self.shell("kube-upgrade-show")
        self.assertIn(fake_kube_upgrade['from_version'], results)
        self.assertIn(fake_kube_upgrade['to_version'], results)
        self.assertIn(fake_kube_upgrade['state'], results)
        self.assertIn(fake_kube_upgrade['uuid'], results)
        self.assertIn(fake_kube_upgrade['created_at'], results)
        self.assertIn(fake_kube_upgrade['updated_at'], results)

    @mock.patch('cgtsclient.v1.kube_upgrade_shell.open',
                mock.mock_open(read_data='{"system_deploy": {"to_k8s_version": "v1.42.2"}}'),
                create=True)
    @mock.patch('cgtsclient.v1.kube_upgrade_shell.os.path.exists')
    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.create')
    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.get')
    def test_kube_upgrade_start_success(self, mock_get, mock_create, mock_exists):
        """Test kube_upgrade_start success when version string passed

        """
        fake_kube_upgrade = {'from_version': 'v1.42.1',
                             'to_version': 'v1.42.2',
                             'state': 'upgrade-started',
                             'uuid': 'cb737aba-1820-4184-b0dc-9b073822af48',
                             'created_at': 'fake-created-time',
                             'updated_at': 'fake-updated-time',
                             }
        mock_exists.return_value = False
        mock_create.return_value = KubeUpgrade(None, fake_kube_upgrade, True)
        mock_get.return_value = KubeUpgrade(None, fake_kube_upgrade, True)

        self.make_env()
        results = self.shell("kube-upgrade-start %s" %
                             fake_kube_upgrade['to_version'])
        self.assertIn(fake_kube_upgrade['from_version'], results)
        self.assertIn(fake_kube_upgrade['to_version'], results)
        self.assertIn(fake_kube_upgrade['state'], results)
        self.assertIn(fake_kube_upgrade['uuid'], results)
        self.assertIn(fake_kube_upgrade['created_at'], results)
        self.assertIn(fake_kube_upgrade['updated_at'], results)

    @mock.patch('cgtsclient.v1.kube_upgrade_shell.open',
                mock.mock_open(read_data='{"system_deploy": {"to_k8s_version": "v1.42.2"}}'),
                create=True)
    @mock.patch('cgtsclient.v1.kube_upgrade_shell.os.path.exists')
    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.create')
    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.get')
    def test_kube_upgrade_start_force(self, mock_get, mock_create, mock_exists):
        fake_kube_upgrade = {'from_version': 'v1.42.1',
                             'to_version': 'v1.42.2',
                             'state': 'upgrade-started',
                             'uuid': 'cb737aba-1820-4184-b0dc-9b073822af48',
                             'created_at': 'fake-created-time',
                             'updated_at': 'fake-updated-time',
                             }
        mock_exists.return_value = False
        mock_create.return_value = KubeUpgrade(None, fake_kube_upgrade, True)
        mock_get.return_value = KubeUpgrade(None, fake_kube_upgrade, True)

        self.make_env()
        results = self.shell("kube-upgrade-start %s --force" %
                             fake_kube_upgrade['to_version'])
        self.assertIn(fake_kube_upgrade['from_version'], results)
        self.assertIn(fake_kube_upgrade['to_version'], results)
        self.assertIn(fake_kube_upgrade['state'], results)
        self.assertIn(fake_kube_upgrade['uuid'], results)
        self.assertIn(fake_kube_upgrade['created_at'], results)
        self.assertIn(fake_kube_upgrade['updated_at'], results)

    @mock.patch('cgtsclient.v1.kube_upgrade_shell.open', side_effect=IOError("Fake error"))
    @mock.patch('cgtsclient.v1.kube_upgrade_shell.os.path.exists')
    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.create')
    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.get')
    def test_kube_upgrade_start_success_with_to_version_file_read_error(
            self, mock_get, mock_create, mock_exists, mock_open):
        """Test that to_version is provided and failed to read from SYSTEM_DEPLOY_JSON_FILE"""
        fake_kube_upgrade = {'from_version': 'v1.42.1',
                             'to_version': 'v1.42.2',
                             'state': 'upgrade-started',
                             'uuid': 'cb737aba-1820-4184-b0dc-9b073822af48',
                             'created_at': 'fake-created-time',
                             'updated_at': 'fake-updated-time',
                             }
        mock_exists.return_value = True
        mock_create.return_value = KubeUpgrade(None, fake_kube_upgrade, True)
        mock_get.return_value = KubeUpgrade(None, fake_kube_upgrade, True)

        self.make_env()
        results = self.shell("kube-upgrade-start %s" %
                             fake_kube_upgrade['to_version'])
        self.assertIn(fake_kube_upgrade['to_version'], results)
        mock_create.assert_called_once_with('v1.42.2', False)

    @mock.patch('cgtsclient.v1.kube_upgrade_shell.open',
                mock.mock_open(read_data='{"system_deploy": {"to_k8s_version": "v1.42.2"}}'),
                create=True)
    @mock.patch('cgtsclient.v1.kube_upgrade_shell.os.path.exists')
    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.create')
    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.get')
    def test_kube_upgrade_start_success_without_to_version(
            self, mock_get, mock_create, mock_exists):
        """Test that to_version is read from SYSTEM_DEPLOY_JSON_FILE when not provided."""
        fake_kube_upgrade = {'from_version': 'v1.42.1',
                             'to_version': 'v1.42.2',
                             'state': 'upgrade-started',
                             'uuid': 'cb737aba-1820-4184-b0dc-9b073822af48',
                             'created_at': 'fake-created-time',
                             'updated_at': 'fake-updated-time',
                             }
        mock_exists.return_value = True
        mock_create.return_value = KubeUpgrade(None, fake_kube_upgrade, True)
        mock_get.return_value = KubeUpgrade(None, fake_kube_upgrade, True)

        self.make_env()
        results = self.shell("kube-upgrade-start")
        self.assertIn(fake_kube_upgrade['to_version'], results)
        mock_create.assert_called_once_with('v1.42.2', False)

    @mock.patch('cgtsclient.v1.kube_upgrade_shell.open',
                mock.mock_open(read_data='{"system_deploy": {"to_k8s_version": "v1.42.2"}}'),
                create=True)
    @mock.patch('cgtsclient.v1.kube_upgrade_shell.os.path.exists')
    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.create')
    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.get')
    def test_kube_upgrade_start_fail_to_version_mismatch(self, mock_get, mock_create, mock_exists):
        """Test that mismatched to_version raises an exception."""
        mock_exists.return_value = True

        self.make_env()
        self.assertRaises(Exception, self.shell, "kube-upgrade-start v1.99.0")  # noqa: H202

    @mock.patch('cgtsclient.v1.kube_upgrade_shell.os.path.exists')
    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.create')
    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.get')
    def test_kube_upgrade_start_fail_to_version_unavailable(
            self, mock_get, mock_create, mock_exists):
        """Test that to_version neither passed nor available in system-deploy state file"""
        mock_exists.return_value = False

        self.make_env()
        self.assertRaises(Exception, self.shell, "kube-upgrade-start")  # noqa: H202

    @mock.patch('cgtsclient.v1.kube_upgrade_shell.open', side_effect=IOError("Fake error"))
    @mock.patch('cgtsclient.v1.kube_upgrade_shell.os.path.exists')
    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.create')
    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.get')
    def test_kube_upgrade_start_fail_to_version_read_error(
            self, mock_get, mock_create, mock_exists, mock_open):
        """Test that to_version not passed and failed to read from system-deploy state file"""
        mock_exists.return_value = False

        self.make_env()
        self.assertRaises(Exception, self.shell, "kube-upgrade-start")  # noqa: H202

    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.update')
    def test_kube_pre_application_update(self, mock_update):
        fake_kube_upgrade = {'from_version': 'v1.42.1',
                             'to_version': 'v1.42.2',
                             'state': 'pre-updating-apps',
                             'uuid': 'cb737aba-1820-4184-b0dc-9b073822af48',
                             'created_at': 'fake-created-time',
                             'updated_at': 'fake-updated-time',
                             }
        mock_update.return_value = KubeUpgrade(None, fake_kube_upgrade, True)

        self.make_env()
        results = self.shell("kube-pre-application-update")

        patch = {'op': 'replace',
                 'path': '/state',
                 'value': 'pre-updating-apps'
                 }
        mock_update.assert_called_once_with([patch])

        self.assertIn(fake_kube_upgrade['from_version'], results)
        self.assertIn(fake_kube_upgrade['to_version'], results)
        self.assertIn(fake_kube_upgrade['state'], results)
        self.assertIn(fake_kube_upgrade['uuid'], results)
        self.assertIn(fake_kube_upgrade['created_at'], results)
        self.assertIn(fake_kube_upgrade['updated_at'], results)

    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.update')
    def test_kube_upgrade_download_images(self, mock_update):
        fake_kube_upgrade = {'from_version': 'v1.42.1',
                             'to_version': 'v1.42.2',
                             'state': 'downloading-images',
                             'uuid': 'cb737aba-1820-4184-b0dc-9b073822af48',
                             'created_at': 'fake-created-time',
                             'updated_at': 'fake-updated-time',
                             }
        mock_update.return_value = KubeUpgrade(None, fake_kube_upgrade, True)

        self.make_env()
        results = self.shell("kube-upgrade-download-images")
        self.assertIn(fake_kube_upgrade['from_version'], results)
        self.assertIn(fake_kube_upgrade['to_version'], results)
        self.assertIn(fake_kube_upgrade['state'], results)
        self.assertIn(fake_kube_upgrade['uuid'], results)
        self.assertIn(fake_kube_upgrade['created_at'], results)
        self.assertIn(fake_kube_upgrade['updated_at'], results)

    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.update')
    def test_kube_upgrade_networking(self, mock_update):
        fake_kube_upgrade = {'from_version': 'v1.42.1',
                             'to_version': 'v1.42.2',
                             'state': 'upgrading-networking',
                             'uuid': 'cb737aba-1820-4184-b0dc-9b073822af48',
                             'created_at': 'fake-created-time',
                             'updated_at': 'fake-updated-time',
                             }
        mock_update.return_value = KubeUpgrade(None, fake_kube_upgrade, True)

        self.make_env()
        results = self.shell("kube-upgrade-networking")
        self.assertIn(fake_kube_upgrade['from_version'], results)
        self.assertIn(fake_kube_upgrade['to_version'], results)
        self.assertIn(fake_kube_upgrade['state'], results)
        self.assertIn(fake_kube_upgrade['uuid'], results)
        self.assertIn(fake_kube_upgrade['created_at'], results)
        self.assertIn(fake_kube_upgrade['updated_at'], results)

    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.update')
    def test_kube_post_application_update(self, mock_update):
        fake_kube_upgrade = {'from_version': 'v1.42.1',
                             'to_version': 'v1.42.2',
                             'state': 'post-updating-apps',
                             'uuid': 'cb737aba-1820-4184-b0dc-9b073822af48',
                             'created_at': 'fake-created-time',
                             'updated_at': 'fake-updated-time',
                             }
        mock_update.return_value = KubeUpgrade(None, fake_kube_upgrade, True)

        self.make_env()
        results = self.shell("kube-post-application-update")

        patch = {'op': 'replace',
                 'path': '/state',
                 'value': 'post-updating-apps'
                 }
        mock_update.assert_called_once_with([patch])

        self.assertIn(fake_kube_upgrade['from_version'], results)
        self.assertIn(fake_kube_upgrade['to_version'], results)
        self.assertIn(fake_kube_upgrade['state'], results)
        self.assertIn(fake_kube_upgrade['uuid'], results)
        self.assertIn(fake_kube_upgrade['created_at'], results)
        self.assertIn(fake_kube_upgrade['updated_at'], results)

    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.update')
    def test_kube_upgrade_complete(self, mock_update):
        fake_kube_upgrade = {'from_version': 'v1.42.1',
                             'to_version': 'v1.42.2',
                             'state': 'upgrade-complete',
                             'uuid': 'cb737aba-1820-4184-b0dc-9b073822af48',
                             'created_at': 'fake-created-time',
                             'updated_at': 'fake-updated-time',
                             }
        mock_update.return_value = KubeUpgrade(None, fake_kube_upgrade, True)

        self.make_env()
        results = self.shell("kube-upgrade-complete")
        self.assertIn(fake_kube_upgrade['from_version'], results)
        self.assertIn(fake_kube_upgrade['to_version'], results)
        self.assertIn(fake_kube_upgrade['state'], results)
        self.assertIn(fake_kube_upgrade['uuid'], results)
        self.assertIn(fake_kube_upgrade['created_at'], results)
        self.assertIn(fake_kube_upgrade['updated_at'], results)

    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.delete')
    def test_kube_upgrade_delete(self, mock_delete):
        self.make_env()
        results = self.shell("kube-upgrade-delete --yes")
        self.assertIn("Kubernetes upgrade deleted", results)
