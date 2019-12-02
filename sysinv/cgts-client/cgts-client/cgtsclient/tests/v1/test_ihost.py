# -*- encoding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 softtabstop=4
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
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#


import copy
import testtools

from cgtsclient.tests import utils
import cgtsclient.v1.ihost

IHOST = {'id': 123,
         'uuid': '66666666-7777-8888-9999-000000000000',
         'hostname': 'cgtshost',
         'personality': 'controller',
         'mgmt_mac': '11:22:33:44:55:66',
         'mgmt_ip': '192.168.24.11',
         'serialid': 'sn123456',
         'location': {'City': 'Ottawa'},
         'boot_device': 'sda',
         'rootfs_device': 'sda',
         'install_output': "text",
         'console': 'ttyS0,115200',
         'tboot': ''}

PORT = {'id': 456,
        'uuid': '11111111-2222-3333-4444-555555555555',
        'ihost_id': 123,
        'address': 'AA:AA:AA:AA:AA:AA',
        'extra': {}}

CREATE_IHOST = copy.deepcopy(IHOST)
del CREATE_IHOST['id']
del CREATE_IHOST['uuid']

UPDATED_IHOST = copy.deepcopy(IHOST)
NEW_LOC = 'newlocOttawa'
UPDATED_IHOST['location'] = NEW_LOC


fixtures = {
    '/v1/ihosts':
    {
        'GET': (
            {},
            {"ihosts": [IHOST]},
        ),
        'POST': (
            {},
            CREATE_IHOST,
        ),
    },
    '/v1/ihosts/%s' % IHOST['uuid']:
    {
        'GET': (
            {},
            IHOST,
        ),
        'DELETE': (
            {},
            None,
        ),
        'PATCH': (
            {},
            UPDATED_IHOST,
        ),
    },
    '/v1/ihosts/%s/ports' % IHOST['uuid']:
    {
        'GET': (
            {},
            {"ports": [PORT]},
        ),
    },
}


class HostManagerTest(testtools.TestCase):

    def setUp(self):
        super(HostManagerTest, self).setUp()
        self.api = utils.FakeAPI(fixtures)
        self.mgr = cgtsclient.v1.ihost.ihostManager(self.api)

    def test_ihost_list(self):
        ihost = self.mgr.list()
        expect = [
            ('GET', '/v1/ihosts', {}, None),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(len(ihost), 1)

    def test_ihost_show(self):
        ihost = self.mgr.get(IHOST['uuid'])
        expect = [
            ('GET', '/v1/ihosts/%s' % IHOST['uuid'], {}, None),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(ihost.uuid, IHOST['uuid'])

    def test_create(self):
        ihost = self.mgr.create(**CREATE_IHOST)
        expect = [
            ('POST', '/v1/ihosts', {}, CREATE_IHOST),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertTrue(ihost)

    def test_delete(self):
        ihost = self.mgr.delete(ihost_id=IHOST['uuid'])
        expect = [
            ('DELETE', '/v1/ihosts/%s' % IHOST['uuid'], {}, None),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertTrue(ihost is None)

    def test_update(self):
        patch = {'op': 'replace',
                 'value': NEW_LOC,
                 'path': '/location'}
        ihost = self.mgr.update(ihost_id=IHOST['uuid'],
                                patch=patch)
        expect = [
            ('PATCH', '/v1/ihosts/%s' % IHOST['uuid'], {}, patch),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(ihost.location, NEW_LOC)
