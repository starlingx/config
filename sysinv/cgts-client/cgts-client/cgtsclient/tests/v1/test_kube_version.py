#
# Copyright 2013 Hewlett-Packard Development Company, L.P.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2019 Wind River Systems, Inc.
#


import testtools

from cgtsclient.tests import utils
import cgtsclient.v1.kube_version

KUBE_VERSION = {'version': 'v1.42.2',
                'upgrade_from': ['v1.42.1'],
                'downgrade_to': [],
                'applied_patches': ['KUBE.1', 'KUBE.2'],
                'available_patches': ['KUBE.3'],
                'target': True,
                'state': 'TODO',
                }

KUBE_VERSION_2 = {'version': 'v1.42.3',
                  'upgrade_from': ['v1.42.2'],
                  'downgrade_to': ['v1.42.2'],
                  'applied_patches': ['KUBE.3', 'KUBE.4'],
                  'available_patches': ['KUBE.5'],
                  'target': False,
                  'state': 'TODO',
                  }

fixtures = {
    '/v1/kube_versions':
    {
        'GET': (
            {},
            {"kube_versions": [KUBE_VERSION, KUBE_VERSION_2]},
        ),
    },
    '/v1/kube_versions/%s' % KUBE_VERSION['version']:
    {
        'GET': (
            {},
            KUBE_VERSION,
        ),
    },
}


class KubeVersionManagerTest(testtools.TestCase):

    def setUp(self):
        super(KubeVersionManagerTest, self).setUp()
        self.api = utils.FakeAPI(fixtures)
        self.mgr = cgtsclient.v1.kube_version.KubeVersionManager(self.api)

    def test_kube_version_list(self):
        kube_versions = self.mgr.list()
        expect = [
            ('GET', '/v1/kube_versions', {}, None),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(len(kube_versions), 2)

    def test_kube_version_show(self):
        kube_version = self.mgr.get(KUBE_VERSION['version'])
        expect = [
            ('GET', '/v1/kube_versions/%s' % KUBE_VERSION['version'], {}, None),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(kube_version.version,
                         KUBE_VERSION['version'])
        self.assertEqual(kube_version.upgrade_from,
                         KUBE_VERSION['upgrade_from'])
        self.assertEqual(kube_version.downgrade_to,
                         KUBE_VERSION['downgrade_to'])
        self.assertEqual(kube_version.applied_patches,
                         KUBE_VERSION['applied_patches'])
        self.assertEqual(kube_version.available_patches,
                         KUBE_VERSION['available_patches'])
        self.assertEqual(kube_version.target,
                         KUBE_VERSION['target'])
        self.assertEqual(kube_version.state,
                         KUBE_VERSION['state'])
