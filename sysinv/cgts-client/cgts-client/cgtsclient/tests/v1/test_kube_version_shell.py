#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

from cgtsclient.tests import test_shell
from cgtsclient.v1.kube_version import KubeVersion


class KubeVersionTest(test_shell.ShellTest):

    def setUp(self):
        super(KubeVersionTest, self).setUp()

    def tearDown(self):
        super(KubeVersionTest, self).tearDown()

    @mock.patch('cgtsclient.v1.kube_version.KubeVersionManager.list')
    @mock.patch('cgtsclient.client._get_ksclient')
    @mock.patch('cgtsclient.client._get_endpoint')
    def test_kube_version_list(self, mock_get_endpoint, mock_get_client,
                               mock_list):
        mock_get_endpoint.return_value = 'http://fakelocalhost:6385/v1'
        fake_version = {'version': 'v1.42.2',
                        'upgrade_from': ['v1.42.1'],
                        'downgrade_to': [],
                        'applied_patches': ['KUBE.1', 'KUBE.2'],
                        'available_patches': ['KUBE.3'],
                        'target': True,
                        'state': 'TODO',
                        }

        mock_list.return_value = [KubeVersion(None, fake_version, True)]
        self.make_env()
        version_results = self.shell("kube-version-list")
        self.assertIn(fake_version['version'], version_results)
        self.assertIn(str(fake_version['target']), version_results)
        self.assertIn(fake_version['state'], version_results)
        self.assertNotIn(str(fake_version['upgrade_from']), version_results)
        self.assertNotIn(str(fake_version['downgrade_to']), version_results)
        self.assertNotIn(str(fake_version['applied_patches']), version_results)
        self.assertNotIn(str(fake_version['available_patches']),
                         version_results)

    @mock.patch('cgtsclient.v1.kube_version.KubeVersionManager.get')
    @mock.patch('cgtsclient.client._get_ksclient')
    @mock.patch('cgtsclient.client._get_endpoint')
    def test_kube_version_show(self, mock_get_endpoint, mock_get_client,
                               mock_get):
        mock_get_endpoint.return_value = 'http://fakelocalhost:6385/v1'
        fake_version = {'version': 'v1.42.2',
                        'upgrade_from': ['v1.42.1'],
                        'downgrade_to': [],
                        'applied_patches': ['KUBE.1', 'KUBE.2'],
                        'available_patches': ['KUBE.3'],
                        'target': True,
                        'state': 'TODO',
                        }

        mock_get.return_value = KubeVersion(None, fake_version, True)
        self.make_env()
        version_results = self.shell("kube-version-show %s" %
                                     fake_version['version'])
        self.assertIn(fake_version['version'], version_results)
        self.assertIn(str(fake_version['upgrade_from']), version_results)
        self.assertIn(str(fake_version['downgrade_to']), version_results)
        self.assertIn(str(fake_version['target']), version_results)
        self.assertIn(fake_version['state'], version_results)
        self.assertIn(str(fake_version['applied_patches']), version_results)
        self.assertIn(str(fake_version['available_patches']), version_results)
