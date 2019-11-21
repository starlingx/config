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
import cgtsclient.v1.kube_upgrade
import cgtsclient.v1.kube_upgrade_shell


KUBE_UPGRADE = {'from_version': 'v1.42.1',
                'to_version': 'v1.42.2',
                'state': 'upgrade-started',
                'uuid': 'cb737aba-1820-4184-b0dc-9b073822af48',
                'created_at': 'fake-created-time',
                'updated_at': 'fake-updated-time',
                }

CREATE_KUBE_UPGRADE = {'to_version': 'v1.42.2',
                       'force': False}

UPDATED_KUBE_UPGRADE = {'from_version': 'v1.42.1',
                        'to_version': 'v1.42.2',
                        'state': 'upgrading-networking',
                        'uuid': 'cb737aba-1820-4184-b0dc-9b073822af48',
                        'created_at': 'fake-created-time',
                        'updated_at': 'fake-updated-time',
                        }


fixtures = {
    '/v1/kube_upgrade':
    {
        'POST': (
            {},
            KUBE_UPGRADE,
        ),
        'GET': (
            {},
            {"kube_upgrades": [KUBE_UPGRADE]},
        ),
        'DELETE': (
            {},
            None,
        ),
        'PATCH': (
            {},
            UPDATED_KUBE_UPGRADE,
        ),
    },
    '/v1/kube_upgrade/%s' % KUBE_UPGRADE['uuid']:
    {
        'GET': (
            {},
            KUBE_UPGRADE,
        ),
    },
}


class KubeUpgradeManagerTest(testtools.TestCase):

    def setUp(self):
        super(KubeUpgradeManagerTest, self).setUp()
        self.api = utils.FakeAPI(fixtures)
        self.mgr = cgtsclient.v1.kube_upgrade.KubeUpgradeManager(self.api)

    def test_list(self):
        kube_upgrade_list = self.mgr.list()
        expect = [
            ('GET', '/v1/kube_upgrade', {}, None),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(len(kube_upgrade_list), 1)

    def test_get(self):
        kube_upgrade = self.mgr.get(KUBE_UPGRADE['uuid'])
        expect = [
            ('GET', '/v1/kube_upgrade/%s' % KUBE_UPGRADE['uuid'], {}, None),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(kube_upgrade.from_version,
                         KUBE_UPGRADE['from_version'])
        self.assertEqual(kube_upgrade.to_version,
                         KUBE_UPGRADE['to_version'])
        self.assertEqual(kube_upgrade.state,
                         KUBE_UPGRADE['state'])
        self.assertEqual(kube_upgrade.uuid,
                         KUBE_UPGRADE['uuid'])
        self.assertEqual(kube_upgrade.created_at,
                         KUBE_UPGRADE['created_at'])
        self.assertEqual(kube_upgrade.updated_at,
                         KUBE_UPGRADE['updated_at'])

    def test_create(self):
        kube_upgrade = self.mgr.create(**CREATE_KUBE_UPGRADE)
        expect = [
            ('POST', '/v1/kube_upgrade', {}, CREATE_KUBE_UPGRADE),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(kube_upgrade.from_version,
                         KUBE_UPGRADE['from_version'])
        self.assertEqual(kube_upgrade.to_version,
                         KUBE_UPGRADE['to_version'])
        self.assertEqual(kube_upgrade.state,
                         KUBE_UPGRADE['state'])
        self.assertEqual(kube_upgrade.uuid,
                         KUBE_UPGRADE['uuid'])
        self.assertEqual(kube_upgrade.created_at,
                         KUBE_UPGRADE['created_at'])
        self.assertEqual(kube_upgrade.updated_at,
                         KUBE_UPGRADE['updated_at'])

    def test_delete(self):
        self.mgr.delete()
        expect = [
            ('DELETE', '/v1/kube_upgrade', {}, None),
        ]
        self.assertEqual(self.api.calls, expect)

    def test_update(self):
        patch = {'op': 'replace',
                 'value': 'upgrading-networking',
                 'path': '/state'}
        kube_upgrade = self.mgr.update(patch=patch)
        expect = [
            ('PATCH', '/v1/kube_upgrade', {}, patch),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(kube_upgrade.state,
                         cgtsclient.v1.kube_upgrade_shell.
                         KUBE_UPGRADE_STATE_UPGRADING_NETWORKING)
