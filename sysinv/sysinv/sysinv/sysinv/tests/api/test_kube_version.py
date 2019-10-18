#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /kube_version/ methods.
"""

import mock
import webtest.app

from sysinv.tests.api import base

FAKE_KUBE_VERSIONS = [
    {'version': 'v1.42.1',
     'upgrade_from': [],
     'downgrade_to': [],
     'applied_patches': [],
     'available_patches': [],
     },
    {'version': 'v1.42.2',
     'upgrade_from': ['v1.42.1'],
     'downgrade_to': [],
     'applied_patches': ['KUBE.1', 'KUBE.2'],
     'available_patches': ['KUBE.3'],
     },
    {'version': 'v1.43.1',
     'upgrade_from': ['v1.42.2'],
     'downgrade_to': [],
     'applied_patches': ['KUBE.11', 'KUBE.12'],
     'available_patches': ['KUBE.13'],
     },
    {'version': 'v1.43.2',
     'upgrade_from': ['v1.43.1', 'v1.42.2'],
     'downgrade_to': ['v1.43.1'],
     'applied_patches': ['KUBE.14', 'KUBE.15'],
     'available_patches': ['KUBE.16'],
     },
]


def mock_get_kube_versions():
    return FAKE_KUBE_VERSIONS


class TestKubeVersion(base.FunctionalTest):

    def setUp(self):
        super(TestKubeVersion, self).setUp()

        def mock_kube_get_version_states(obj):
            return {'v1.42.1': 'available',
                    'v1.42.2': 'available',
                    'v1.43.1': 'active',
                    'v1.43.2': 'available'}
        self.mocked_kube_get_version_states = mock.patch(
            'sysinv.common.kubernetes.KubeOperator.kube_get_version_states',
            mock_kube_get_version_states)
        self.mocked_kube_get_version_states.start()

    def tearDown(self):
        super(TestKubeVersion, self).tearDown()

        self.mocked_kube_get_version_states.stop()


@mock.patch('sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
class TestListKubeVersions(TestKubeVersion):

    def test_one(self):
        result = self.get_json('/kube_versions/v1.42.2')

        # Verify that the version has the expected attributes
        self.assertEqual(result['version'],
                         FAKE_KUBE_VERSIONS[1]['version'])
        self.assertEqual(result['upgrade_from'],
                         FAKE_KUBE_VERSIONS[1]['upgrade_from'])
        self.assertEqual(result['downgrade_to'],
                         FAKE_KUBE_VERSIONS[1]['downgrade_to'])
        self.assertEqual(result['applied_patches'],
                         FAKE_KUBE_VERSIONS[1]['applied_patches'])
        self.assertEqual(result['available_patches'],
                         FAKE_KUBE_VERSIONS[1]['available_patches'])
        self.assertEqual(result['state'], 'available')
        self.assertEqual(result['target'], False)

    def test_one_active(self):
        result = self.get_json('/kube_versions/v1.43.1')

        # Verify that the version has the expected attributes
        self.assertEqual(result['version'],
                         FAKE_KUBE_VERSIONS[2]['version'])
        self.assertEqual(result['upgrade_from'],
                         FAKE_KUBE_VERSIONS[2]['upgrade_from'])
        self.assertEqual(result['downgrade_to'],
                         FAKE_KUBE_VERSIONS[2]['downgrade_to'])
        self.assertEqual(result['applied_patches'],
                         FAKE_KUBE_VERSIONS[2]['applied_patches'])
        self.assertEqual(result['available_patches'],
                         FAKE_KUBE_VERSIONS[2]['available_patches'])
        self.assertEqual(result['state'], 'active')
        self.assertEqual(result['target'], True)

    def test_bad_version(self):
        self.assertRaises(webtest.app.AppError, self.get_json,
                          '/kube_versions/v1.42.2.unknown')

    def test_all(self):
        data = self.get_json('/kube_versions')
        self.assertEqual(len(FAKE_KUBE_VERSIONS), len(data['kube_versions']))
