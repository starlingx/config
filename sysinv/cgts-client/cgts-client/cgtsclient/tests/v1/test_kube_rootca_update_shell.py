#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from cgtsclient.tests import test_shell
from cgtsclient.v1.ihost import ihost
from cgtsclient.v1.kube_rootca_update import KubeRootCAUpdate


class KubeRootCAUpdateTest(test_shell.ShellTest):

    def setUp(self):
        super(KubeRootCAUpdateTest, self).setUp()

        self.fake_kube_rootca_update = {
            'from_rootca_cert': 'oldCert',
            'to_rootca_cert': 'newCert',
            'state': 'update-started',
            'uuid': 'cb737aba-1820-4184-b0dc-9b073822af48',
            'capabilities': {},
            'created_at': 'fake-created-time',
            'updated_at': 'fake-updated-time',
        }
        self.fake_kube_rootca_host_update = {
            'hostname': 'fake-hostname',
            'uuid': '88d31a2d-c82e-429f-a52d-f03f860bb620',
            'personality': 'fake-personality',
            'state': 'None',
            'target_rootca_cert': 'fake-target_cert',
            'effective_rootca_cert': 'fake-effective_cert',
            'created_at': 'fake-created-time',
            'updated_at': 'fake-updated-time',
        }
        self.mock_get_endpoint_return_value = 'http://fakelocalhost:6385/v1'

    def tearDown(self):
        super(KubeRootCAUpdateTest, self).tearDown()

    def _check_rootca_update(self, fake_kube_rootca_update, results):
        self.assertIn(fake_kube_rootca_update['from_rootca_cert'], results)
        self.assertIn(fake_kube_rootca_update['to_rootca_cert'], results)
        self.assertIn(fake_kube_rootca_update['state'], results)
        self.assertIn(fake_kube_rootca_update['uuid'], results)
        self.assertIn(fake_kube_rootca_update['created_at'], results)
        self.assertIn(fake_kube_rootca_update['updated_at'], results)

    def _check_rootca_host_update(self, fake_kube_rootca_host_update, results):
        self.assertIn(fake_kube_rootca_host_update['effective_rootca_cert'], results)
        self.assertIn(fake_kube_rootca_host_update['target_rootca_cert'], results)
        self.assertIn(fake_kube_rootca_host_update['state'], results)
        self.assertIn(fake_kube_rootca_host_update['created_at'], results)
        self.assertIn(fake_kube_rootca_host_update['updated_at'], results)

    @mock.patch('cgtsclient.v1.kube_rootca_update.KubeRootCAUpdateManager.create')
    @mock.patch('cgtsclient.v1.kube_rootca_update.KubeRootCAUpdateManager.get')
    def test_kube_rootca_update_start(self, mock_get, mock_create):
        mock_create.return_value = KubeRootCAUpdate(None, self.fake_kube_rootca_update, True)
        mock_get.return_value = KubeRootCAUpdate(None, self.fake_kube_rootca_update, True)

        self.make_env()
        results = self.shell("kube-rootca-update-start")
        self._check_rootca_update(self.fake_kube_rootca_update, results)

    @mock.patch('cgtsclient.v1.kube_rootca_update.KubeRootCAUpdateManager.create')
    @mock.patch('cgtsclient.v1.kube_rootca_update.KubeRootCAUpdateManager.get_list')
    def test_kube_rootca_update_show_current_update(self,
                                                    mock_get_list,
                                                    mock_create):
        mock_create.return_value = KubeRootCAUpdate(None, self.fake_kube_rootca_update, True)
        mock_get_list.return_value = [KubeRootCAUpdate(None, self.fake_kube_rootca_update, True)]

        self.make_env()
        results = self.shell("kube-rootca-update-show")
        self._check_rootca_update(self.fake_kube_rootca_update, results)

    @mock.patch('cgtsclient.v1.kube_rootca_update.KubeRootCAUpdateManager.host_update_list')
    def test_kube_rootca_update_list_current_update(self, mock_update_list):
        mock_update_list.return_value = [KubeRootCAUpdate(None, self.fake_kube_rootca_host_update, True)]
        self.make_env()
        results = self.shell("kube-rootca-host-update-list")
        self.assertIn(self.fake_kube_rootca_host_update['hostname'], results)
        self.assertIn(self.fake_kube_rootca_host_update['personality'], results)
        self._check_rootca_host_update(self.fake_kube_rootca_host_update, results)

    @mock.patch('cgtsclient.v1.kube_rootca_update.KubeRootCAUpdateManager.create')
    @mock.patch('cgtsclient.v1.kube_rootca_update.KubeRootCAUpdateManager.rootCA_pods_update')
    def test_kube_rootca_pods_update(self, mock_pods_update, mock_create):
        self.fake_kube_rootca_update['state'] = 'updated-host-trust-both-cas'
        mock_create.return_value = KubeRootCAUpdate(None, self.fake_kube_rootca_update, True)
        self.fake_kube_rootca_update['state'] = 'updating-pods-trust-both-cas'
        mock_pods_update.return_value = KubeRootCAUpdate(None, self.fake_kube_rootca_update, True)

        self.make_env()
        results = self.shell("kube-rootca-pods-update --phase=trust-both-cas")
        self._check_rootca_update(self.fake_kube_rootca_update, results)

    @mock.patch('cgtsclient.v1.kube_rootca_update.KubeRootCAUpdateManager.create')
    @mock.patch('cgtsclient.v1.ihost.ihostManager.kube_update_rootca')
    @mock.patch('cgtsclient.v1.ihost._find_ihost')
    def test_kube_rootca_host_update(self,
                                     mock_get_host,
                                     mock_host_update,
                                     mock_create):
        fake_controller = {'id': '0',
                           'uuid': '1127ea5e-067b-11ec-9a03-0242ac130003',
                           'hostname': 'fake-hostname',
                           'personality': 'controller',
                           'administrative': 'unlocked',
                           'operational': 'enabled',
                           'availability': 'available'}
        self.fake_kube_rootca_host_update['state'] = 'updating-host-trust-both-cas'
        mock_get_host.return_value = ihost(None, fake_controller, True)
        mock_create.return_value = KubeRootCAUpdate(None, self.fake_kube_rootca_update, True)
        mock_host_update.return_value = KubeRootCAUpdate(None, self.fake_kube_rootca_host_update, True)

        self.make_env()
        results = self.shell("kube-rootca-host-update --phase=trust-both-cas fake-hostname")
        self._check_rootca_host_update(self.fake_kube_rootca_host_update, results)

    @mock.patch('cgtsclient.v1.kube_rootca_update.KubeRootCAUpdateManager.create')
    @mock.patch('cgtsclient.v1.kube_rootca_update.KubeRootCAUpdateManager.update_complete')
    def test_kube_rootca_update_complete(self,
                                         mock_update_complete,
                                         mock_create):
        self.fake_kube_rootca_update['state'] = 'updated-pods-trust-new-ca'
        mock_create.return_value = KubeRootCAUpdate(None, self.fake_kube_rootca_update, True)
        self.fake_kube_rootca_update['state'] = 'update-completed'
        mock_update_complete.return_value = KubeRootCAUpdate(None, self.fake_kube_rootca_update, True)

        self.make_env()
        results = self.shell("kube-rootca-update-complete")
        self._check_rootca_update(self.fake_kube_rootca_update, results)

    @mock.patch('cgtsclient.v1.kube_rootca_update.KubeRootCAUpdateManager.create')
    @mock.patch('cgtsclient.v1.kube_rootca_update.KubeRootCAUpdateManager.update_complete')
    def test_kube_rootca_update_abort(self,
                                      mock_update_complete,
                                      mock_create):
        mock_create.return_value = KubeRootCAUpdate(None, self.fake_kube_rootca_update, True)
        self.fake_kube_rootca_update['state'] = 'update-aborted'
        mock_update_complete.return_value = KubeRootCAUpdate(None, self.fake_kube_rootca_update, True)

        self.make_env()
        results = self.shell("kube-rootca-update-abort")
        self._check_rootca_update(self.fake_kube_rootca_update, results)
