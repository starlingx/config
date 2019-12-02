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
import cgtsclient.v1.kube_host_upgrade


KUBE_HOST_UPGRADE = {'id': 1,
                     'uuid': 'cb737aba-1820-4184-b0dc-9b073822af48',
                     'target_version': 'v1.42.3',
                     'status': 'fake status',
                     'control_plane_version': 'v1.42.2',
                     'kubelet_version': 'v1.42.2',
                     'host_id': 1,
                     'created_at': 'fake-created-time',
                     'updated_at': 'fake-updated-time',
                     }


fixtures = {
    '/v1/kube_host_upgrades':
    {
        'GET': (
            {},
            {"kube_host_upgrades": [KUBE_HOST_UPGRADE]},
        ),
    },
    '/v1/kube_host_upgrades/%s' % KUBE_HOST_UPGRADE['uuid']:
    {
        'GET': (
            {},
            KUBE_HOST_UPGRADE,
        ),
    },
}


class KubeHostUpgradeManagerTest(testtools.TestCase):

    def setUp(self):
        super(KubeHostUpgradeManagerTest, self).setUp()
        self.api = utils.FakeAPI(fixtures)
        self.mgr = cgtsclient.v1.kube_host_upgrade.KubeHostUpgradeManager(
            self.api)

    def test_list(self):
        kube_host_upgrade_list = self.mgr.list()
        expect = [
            ('GET', '/v1/kube_host_upgrades', {}, None),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(len(kube_host_upgrade_list), 1)

    def test_get(self):
        kube_host_upgrade_list = self.mgr.get(KUBE_HOST_UPGRADE['uuid'])
        expect = [
            ('GET', '/v1/kube_host_upgrades/%s' % KUBE_HOST_UPGRADE['uuid'],
             {}, None),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(kube_host_upgrade_list.uuid,
                         KUBE_HOST_UPGRADE['uuid'])
