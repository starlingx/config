#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock

import sysinv.common.exception
from sysinv.common import kubernetes
from sysinv import objects
from sysinv.tests import base

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


@mock.patch('sysinv.common.kubernetes.get_kube_versions',
            mock_get_kube_versions)
class TestKubeVersionObject(base.TestCase):

    def setUp(self):
        super(TestKubeVersionObject, self).setUp()
        kubernetes.KUBE_VERSIONS = FAKE_KUBE_VERSIONS

    def test_get_by_version(self):
        version_obj = objects.kube_version.get_by_version('v1.42.2')
        self.assertEqual(version_obj.version,
                         FAKE_KUBE_VERSIONS[1]['version'])
        self.assertEqual(version_obj.upgrade_from,
                         FAKE_KUBE_VERSIONS[1]['upgrade_from'])
        self.assertEqual(version_obj.downgrade_to,
                         FAKE_KUBE_VERSIONS[1]['downgrade_to'])
        self.assertEqual(version_obj.applied_patches,
                         FAKE_KUBE_VERSIONS[1]['applied_patches'])
        self.assertEqual(version_obj.available_patches,
                         FAKE_KUBE_VERSIONS[1]['available_patches'])
        self.assertEqual(version_obj.state, 'unknown')

    def test_get_by_version_fail(self):
        self.assertRaises(sysinv.common.exception.KubeVersionNotFound,
                          objects.kube_version.get_by_version,
                          'v1.42.22')

    def test_can_upgrade_from(self):
        version = objects.kube_version.get_by_version('v1.43.2')

        self.assertEqual(version.can_upgrade_from('v1.43.1'), True)
        self.assertEqual(version.can_upgrade_from('v1.42.2'), True)
        self.assertEqual(version.can_upgrade_from('v1.42.1'), False)

    def test_can_downgrade_to(self):
        version = objects.kube_version.get_by_version('v1.43.2')

        self.assertEqual(version.can_downgrade_to('v1.43.1'), True)
        self.assertEqual(version.can_downgrade_to('v1.42.1'), False)
