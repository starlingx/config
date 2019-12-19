#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy
import testtools

from cgtsclient.tests import utils
import cgtsclient.v1.controller_fs

CONTROLLER_FS = {
    'uuid': '66666666-7777-8888-9999-000000000000',
    'name': 'cfs',
    'size': 10,
    'logical_volume': 'cfs-lv',
    'replicated': True,
    'state': 'available'
}

UPDATED_CONTROLLER_FS = copy.deepcopy(CONTROLLER_FS)
NEW_SIZE = 20
UPDATED_CONTROLLER_FS['size'] = NEW_SIZE
SYSTEM_UUID = "11111111-2222-3333-4444-5555-000000000000"

fixtures = {
    '/v1/controller_fs':
    {
        'GET': (
            {},
            {"controller_fs": [CONTROLLER_FS]},
        ),
    },
    '/v1/controller_fs/%s' % CONTROLLER_FS['uuid']:
    {
        'GET': (
            {},
            CONTROLLER_FS,
        ),
        'PATCH': (
            {},
            UPDATED_CONTROLLER_FS,
        ),
    },
    '/v1/isystems/%s/controller_fs/update_many' % SYSTEM_UUID:
    {
        'PUT': (
            {},
            {},
        ),
    },
}


class ControllerFsManagerTest(testtools.TestCase):

    def setUp(self):
        super(ControllerFsManagerTest, self).setUp()
        self.api = utils.FakeAPI(fixtures)
        self.mgr = cgtsclient.v1.controller_fs.ControllerFsManager(self.api)

    def test_controller_fs_list(self):
        controllerfs = self.mgr.list()
        expect = [
            ('GET', '/v1/controller_fs', {}, None),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(len(controllerfs), 1)

    def test_controller_fs_show(self):
        controllerfs = self.mgr.get(CONTROLLER_FS['uuid'])
        expect = [
            ('GET', '/v1/controller_fs/%s' % CONTROLLER_FS['uuid'], {}, None),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(controllerfs.uuid, CONTROLLER_FS['uuid'])

    def test_controller_fs_update(self):
        patch = [
            {
                'op': 'replace',
                'value': NEW_SIZE,
                'path': '/size'
            },
            {
                'op': 'replace',
                'value': CONTROLLER_FS['name'],
                'path': '/name'
            }
        ]
        controllerfs = self.mgr.update(CONTROLLER_FS['uuid'], patch)
        expect = [
            ('PATCH', '/v1/controller_fs/%s' % CONTROLLER_FS['uuid'], {}, patch),
        ]
        self.assertEqual(self.api.calls, expect)
        self.assertEqual(controllerfs.size, NEW_SIZE)

    def test_controller_fs_update_many(self):
        # One patch is a list of two dictionaries.
        # for update_many, this is a list of lists
        patches = [
            [
                {
                    'op': 'replace',
                    'value': NEW_SIZE,
                    'path': '/size'
                },
                {
                    'op': 'replace',
                    'value': CONTROLLER_FS['name'],
                    'path': '/name'
                }
            ]
        ]
        self.mgr.update_many(SYSTEM_UUID, patches)
        expect = [
            ('PUT', '/v1/isystems/%s/controller_fs/update_many' % SYSTEM_UUID, {}, patches),
        ]

        # Since update_many is just a PUT, we don't expect any output from it, so we can't
        # do a proper asert here. We just check if the request made is the one we expected.
        self.assertEqual(self.api.calls, expect)
