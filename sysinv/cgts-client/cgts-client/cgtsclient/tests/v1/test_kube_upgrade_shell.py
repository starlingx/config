#
# Copyright (c) 2019 Wind River Systems, Inc.
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
    @mock.patch('cgtsclient.client._get_ksclient')
    @mock.patch('cgtsclient.client._get_endpoint')
    def test_kube_upgrade_show(self, mock_get_endpoint, mock_get_client,
                               mock_list):
        mock_get_endpoint.return_value = 'http://fakelocalhost:6385/v1'
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

    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.create')
    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.get')
    @mock.patch('cgtsclient.client._get_ksclient')
    @mock.patch('cgtsclient.client._get_endpoint')
    def test_kube_upgrade_start(self, mock_get_endpoint, mock_get_client,
                                mock_get, mock_create):
        mock_get_endpoint.return_value = 'http://fakelocalhost:6385/v1'
        fake_kube_upgrade = {'from_version': 'v1.42.1',
                             'to_version': 'v1.42.2',
                             'state': 'upgrade-started',
                             'uuid': 'cb737aba-1820-4184-b0dc-9b073822af48',
                             'created_at': 'fake-created-time',
                             'updated_at': 'fake-updated-time',
                             }
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

    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.create')
    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.get')
    @mock.patch('cgtsclient.client._get_ksclient')
    @mock.patch('cgtsclient.client._get_endpoint')
    def test_kube_upgrade_start_force(self, mock_get_endpoint, mock_get_client,
                                      mock_get, mock_create):
        mock_get_endpoint.return_value = 'http://fakelocalhost:6385/v1'
        fake_kube_upgrade = {'from_version': 'v1.42.1',
                             'to_version': 'v1.42.2',
                             'state': 'upgrade-started',
                             'uuid': 'cb737aba-1820-4184-b0dc-9b073822af48',
                             'created_at': 'fake-created-time',
                             'updated_at': 'fake-updated-time',
                             }
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

    @mock.patch('cgtsclient.v1.kube_upgrade.KubeUpgradeManager.update')
    @mock.patch('cgtsclient.client._get_ksclient')
    @mock.patch('cgtsclient.client._get_endpoint')
    def test_kube_upgrade_download_images(self, mock_get_endpoint,
                                          mock_get_client,
                                          mock_update):
        mock_get_endpoint.return_value = 'http://fakelocalhost:6385/v1'
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
    @mock.patch('cgtsclient.client._get_ksclient')
    @mock.patch('cgtsclient.client._get_endpoint')
    def test_kube_upgrade_networking(self, mock_get_endpoint, mock_get_client,
                                     mock_update):
        mock_get_endpoint.return_value = 'http://fakelocalhost:6385/v1'
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
    @mock.patch('cgtsclient.client._get_ksclient')
    @mock.patch('cgtsclient.client._get_endpoint')
    def test_kube_upgrade_complete(self, mock_get_endpoint, mock_get_client,
                                   mock_update):
        mock_get_endpoint.return_value = 'http://fakelocalhost:6385/v1'
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
    @mock.patch('cgtsclient.client._get_ksclient')
    @mock.patch('cgtsclient.client._get_endpoint')
    def test_kube_upgrade_delete(self, mock_get_endpoint, mock_get_client,
                                 mock_delete):
        mock_get_endpoint.return_value = 'http://fakelocalhost:6385/v1'

        self.make_env()
        results = self.shell("kube-upgrade-delete")
        self.assertIn("Kubernetes upgrade deleted", results)
