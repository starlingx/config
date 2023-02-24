#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import testtools

from cgtsclient.exc import InvalidAttribute
from cgtsclient.tests import utils
from cgtsclient.v1.load import Load
from cgtsclient.v1.load import LoadManager


class LoadManagerTest(testtools.TestCase):
    def setUp(self):
        super(LoadManagerTest, self).setUp()

        self.load = {
            'id': '1',
            'uuid': 'c0d71e4c-f327-45a7-8349-11821a9d44df',
            'state': 'IMPORTED',
            'software_version': '6.0',
            'compatible_version': '6.0',
            'required_patches': '',
        }
        fixtures = {
            '/v1/loads/import_load':
            {
                'POST': (
                    {},
                    self.load,
                ),
            },
        }
        self.api = utils.FakeAPI(fixtures)
        self.mgr = LoadManager(self.api)


class LoadImportTest(LoadManagerTest):
    def setUp(self):
        super(LoadImportTest, self).setUp()

        self.load_patch = {
            'path_to_iso': '/home/bootimage.iso',
            'path_to_sig': '/home/bootimage.sig',
            'inactive': False,
            'active': False,
            'local': False,
        }
        self.load_patch_request_body = {
            'path_to_iso': '/home/bootimage.iso',
            'path_to_sig': '/home/bootimage.sig',
        }

    def test_load_import(self):
        expected = [
            (
                'POST', '/v1/loads/import_load',
                {},
                self.load_patch_request_body,
                {'active': 'false', 'inactive': 'false'},
            )
        ]

        load = self.mgr.import_load(**self.load_patch)

        self.assertEqual(self.api.calls, expected)
        self.assertIsInstance(load, Load)

    def test_load_import_active(self):
        self.load_patch['active'] = True

        expected = [
            (
                'POST', '/v1/loads/import_load',
                {},
                self.load_patch_request_body,
                {'active': 'true', 'inactive': 'false'},
            )
        ]

        load = self.mgr.import_load(**self.load_patch)

        self.assertEqual(self.api.calls, expected)
        self.assertIsInstance(load, Load)

    def test_load_import_local(self):
        self.load_patch['local'] = True
        self.load_patch_request_body['active'] = 'false'
        self.load_patch_request_body['inactive'] = 'false'

        expected = [
            (
                'POST', '/v1/loads/import_load',
                {},
                self.load_patch_request_body,
            )
        ]

        load = self.mgr.import_load(**self.load_patch)

        self.assertEqual(self.api.calls, expected)
        self.assertIsInstance(load, Load)

    def test_load_import_inactive(self):
        self.load_patch['inactive'] = True

        expected = [
            (
                'POST', '/v1/loads/import_load',
                {},
                self.load_patch_request_body,
                {'active': 'false', 'inactive': 'true'}
            )
        ]

        load = self.mgr.import_load(**self.load_patch)

        self.assertEqual(self.api.calls, expected)
        self.assertIsInstance(load, Load)

    def test_load_import_invalid_attribute(self):
        self.load_patch['foo'] = 'bar'

        self.assertRaises(
            InvalidAttribute,
            self.mgr.import_load,
            **self.load_patch
        )

        self.assertEqual(self.api.calls, [])
