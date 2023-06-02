#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


import os
import webtest.app

from mock import patch
from mock import MagicMock
from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.tests.db import utils
from sysinv.openstack.common.rpc import common


class FakeConductorAPI(object):
    def __init__(self):
        self.import_load = MagicMock()
        self.delete_load = MagicMock()
        self.start_import_load = MagicMock()
        self.start_import_load.return_value = utils.create_test_load()


class TestLoad(base.FunctionalTest):
    def setUp(self):
        super(TestLoad, self).setUp()

        self.API_HEADERS = {'User-Agent': 'sysinv-test'}

        self.PATH_PREFIX = '/loads'

        conductor_api = patch('sysinv.conductor.rpcapiproxy.ConductorAPI')
        self.mock_conductor_api = conductor_api.start()
        self.fake_conductor_api = FakeConductorAPI()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(conductor_api.stop)

        socket_gethostname = patch('socket.gethostname')
        self.mock_socket_gethostname = socket_gethostname.start()
        self.mock_socket_gethostname.return_value = 'controller-0'
        self.addCleanup(socket_gethostname.stop)

        # TODO: Improve these unit test to don't mock this method.
        upload_file = patch(
            'sysinv.api.controllers.v1.load.LoadController._upload_file'
        )
        self.mock_upload_file = upload_file.start()
        self.mock_upload_file.return_value = '/tmp/iso/'
        self.addCleanup(upload_file.stop)


@patch('sysinv.common.utils.is_space_available', lambda x, y: True)
class TestLoadImport(TestLoad):
    def setUp(self):
        super(TestLoadImport, self).setUp()

        path_import = '%s/import_load' % self.PATH_PREFIX
        iso = os.path.join(
            os.path.dirname(__file__), "data", "bootimage.iso"
        )
        sig = os.path.join(
            os.path.dirname(__file__), "data", "bootimage.sig"
        )

        self.request_json = {
            'path': path_import,
            'params': {
                'path_to_iso': iso,
                'path_to_sig': sig,
                'active': 'false',
                'inactive': 'false',
            },
            'headers': self.API_HEADERS,
        }

        upload_files = [('path_to_iso', iso), ('path_to_sig', sig)]
        self.request_multiform = {
            'path': path_import,
            'params': {'active': 'false', 'inactive': 'false'},
            'upload_files': upload_files,
            'headers': self.API_HEADERS,
            'expect_errors': False,
        }

    def _assert_load(self, load):
        self.assertEqual(load['software_version'], utils.SW_VERSION)
        self.assertEqual(load['compatible_version'], 'N/A')
        self.assertEqual(load['required_patches'], 'N/A')
        self.assertEqual(load['state'], constants.ACTIVE_LOAD_STATE)

    def test_load_import(self):
        response = self.post_with_files(**self.request_multiform)

        self._assert_load(response.json)
        self.fake_conductor_api.start_import_load.assert_called_once()
        self.fake_conductor_api.import_load.assert_called_once()

    def test_load_import_local(self):
        response = self.post_json(**self.request_json)

        self._assert_load(response.json)
        self.fake_conductor_api.start_import_load.assert_called_once()
        self.fake_conductor_api.import_load.assert_called_once()

    def test_load_import_active(self):
        isystem_get_one = self.dbapi.isystem_get_one
        self.dbapi.isystem_get_one = MagicMock()
        self.dbapi.isystem_get_one.return_value.distributed_cloud_role = \
            constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER

        self.request_multiform['params']['active'] = 'true'
        response = self.post_with_files(**self.request_multiform)

        self.dbapi.isystem_get_one = isystem_get_one

        self._assert_load(response.json)
        self.fake_conductor_api.start_import_load.assert_called_once()
        self.fake_conductor_api.import_load.assert_not_called()

    def test_load_import_inactive(self):
        isystem_get_one = self.dbapi.isystem_get_one
        self.dbapi.isystem_get_one = MagicMock()
        self.dbapi.isystem_get_one.return_value.distributed_cloud_role = \
            constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER

        self.request_multiform['params']['inactive'] = 'true'
        response = self.post_with_files(**self.request_multiform)

        self.dbapi.isystem_get_one = isystem_get_one

        self._assert_load(response.json)
        self.fake_conductor_api.start_import_load.assert_called_once()
        self.fake_conductor_api.import_load.assert_called_once()

    def test_load_import_invalid_hostname(self):
        self.mock_socket_gethostname.return_value = 'controller-1'

        self.assertRaises(
            webtest.app.AppError,
            self.post_with_files,
            **self.request_multiform,
        )

        self.fake_conductor_api.start_import_load.assert_not_called()
        self.fake_conductor_api.import_load.assert_not_called()

    def test_load_import_empty_request(self):
        self.request_multiform['upload_files'] = None

        self.assertRaises(
            webtest.app.AppError,
            self.post_with_files,
            **self.request_multiform,
        )

        self.fake_conductor_api.start_import_load.assert_not_called()
        self.fake_conductor_api.import_load.assert_not_called()

    def test_load_import_missing_required_file(self):
        self.request_multiform['upload_files'].pop()

        self.assertRaises(
            webtest.app.AppError,
            self.post_with_files,
            **self.request_multiform,
        )

        self.fake_conductor_api.start_import_load.assert_not_called()
        self.fake_conductor_api.import_load.assert_not_called()

    def test_load_import_failed_to_create_load_conductor(self):
        self.fake_conductor_api.start_import_load.return_value = None

        self.assertRaises(
            webtest.app.AppError,
            self.post_with_files,
            **self.request_multiform,
        )

        self.fake_conductor_api.start_import_load.assert_called_once()
        self.fake_conductor_api.import_load.assert_not_called()

    def test_load_import_failed_to_import_load_conductor(self):
        self.fake_conductor_api.import_load.side_effect = common.RemoteError()

        self.assertRaises(
            webtest.app.AppError,
            self.post_with_files,
            **self.request_multiform,
        )

        self.fake_conductor_api.start_import_load.assert_called_once()
        self.fake_conductor_api.import_load.assert_called_once()


class TestLoadDelete(TestLoad):
    def setUp(self):
        super(TestLoadDelete, self).setUp()

        load_data = {
            "software_version": "1.0",
            "state": constants.INACTIVE_LOAD_STATE,
        }

        self.load = utils.create_test_load(**load_data)

        self.request_json = {
            'path': f'{self.PATH_PREFIX}/{self.load.id}',
            'headers': self.API_HEADERS,
        }

    def tearDown(self):
        super(TestLoadDelete, self).tearDown()

    def test_load_delete(self):
        response = self.delete(**self.request_json)

        self.assertEqual(response.status_int, 200)

        self.fake_conductor_api.delete_load.assert_called_once()

    def test_load_delete_used_by_software_upgrade(self):
        software_upgrade_get_one = self.dbapi.software_upgrade_get_one

        self.dbapi.software_upgrade_get_one = MagicMock()

        upgrade = utils.create_test_upgrade(**{'to_load': self.load.id})

        self.dbapi.software_upgrade_get_one.return_value = upgrade

        self.assertRaises(
            webtest.app.AppError,
            self.delete,
            **self.request_json,
        )

        self.dbapi.software_upgrade_get_one = software_upgrade_get_one

        self.fake_conductor_api.delete_load.assert_not_called()

    def test_load_delete_used_by_host(self):
        self.dbapi.host_upgrade_get_list = MagicMock()

        self.dbapi.host_upgrade_get_list.return_value = {"target_load": self.load.id}

        self.assertRaises(
            webtest.app.AppError,
            self.delete,
            **self.request_json,
        )

        self.fake_conductor_api.delete_load.assert_not_called()

    def test_load_delete_invalid_state(self):
        utils.update_test_load(
            self.load.id,
            **{'state': constants.IMPORTING_LOAD_STATE},
        )

        self.assertRaises(
            webtest.app.AppError,
            self.delete,
            **self.request_json,
        )

        self.fake_conductor_api.delete_load.assert_not_called()
