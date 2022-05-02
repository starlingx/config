#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import copy
import mock

from cgtsclient.tests import test_shell
from cgtsclient.v1.controller_fs import ControllerFs
from cgtsclient.v1.isystem import isystem

FAKE_CONTROLLER_FS = {
    'uuid': '66666666-7777-8888-9999-000000000000',
    'name': 'fake',
    'size': 10,
    'logical_volume': 'fake-lv',
    'replicated': True,
    'state': 'available',
    'created_at': None,
    'updated_at': None
}

FAKE_ISYSTEM = {
    'uuid': '11111111-2222-3333-4444-5555-000000000000'
}

MODIFY_CONTROLLER_FS = copy.deepcopy(FAKE_CONTROLLER_FS)
MODIFY_CONTROLLER_FS['size'] = 15
MODIFY_CONTROLLER_FS['state'] = 'drbd_fs_resizing_in_progress'


class ControllerFsTest(test_shell.ShellTest):

    def setUp(self):
        super(ControllerFsTest, self).setUp()

        # Mock the ControllerFsManager
        self.controller_fs_manager_list_result = [
            ControllerFs(None, FAKE_CONTROLLER_FS, True)]

        def mock_controller_fs_manager_list(obj):
            return self.controller_fs_manager_list_result
        self.mocked_controller_fs_manager_list = mock.patch(
            'cgtsclient.v1.controller_fs.ControllerFsManager.list',
            mock_controller_fs_manager_list)
        self.mocked_controller_fs_manager_list.start()
        self.addCleanup(self.mocked_controller_fs_manager_list.stop)

        self.controller_fs_manager_get_result = \
            ControllerFs(None, FAKE_CONTROLLER_FS, True)

        def mock_controller_fs_manager_get(obj):
            return self.controller_fs_manager_get_result
        self.mocked_controller_fs_manager_get = mock.patch(
            'cgtsclient.v1.controller_fs.ControllerFsManager.get',
            mock_controller_fs_manager_get)
        self.mocked_controller_fs_manager_get.start()
        self.addCleanup(self.mocked_controller_fs_manager_get.stop)

        def mock_controller_fs_manager_update_many(obj, system_uuid, patch_list):
            return None

        self.mocked_controller_fs_manager_update_many = mock.patch(
            'cgtsclient.v1.controller_fs.ControllerFsManager.update_many',
            mock_controller_fs_manager_update_many)
        self.mocked_controller_fs_manager_update_many.start()
        self.addCleanup(self.mocked_controller_fs_manager_update_many.stop)

        # Mock isystemManager
        self.isystem_manager_list_result = [
            isystem(None, FAKE_ISYSTEM, None)]

        def mock_isystem_manager_list(obj):
            return self.isystem_manager_list_result

        self.mocked_isystem_manager_list = mock.patch(
            'cgtsclient.v1.isystem.isystemManager.list',
            mock_isystem_manager_list)
        self.mocked_isystem_manager_list.start()
        self.addCleanup(self.mocked_isystem_manager_list.stop)

    def test_controller_fs_list(self):
        self.make_env()

        results = self.shell("controllerfs-list --nowrap")

        self.assertIn(str(FAKE_CONTROLLER_FS['uuid']), results)
        self.assertIn(str(FAKE_CONTROLLER_FS['name']), results)
        self.assertIn(str(FAKE_CONTROLLER_FS['size']), results)
        self.assertIn(str(FAKE_CONTROLLER_FS['logical_volume']), results)
        self.assertIn(str(FAKE_CONTROLLER_FS['replicated']), results)
        self.assertIn(str(FAKE_CONTROLLER_FS['state']), results)

    def test_controller_fs_show(self):
        self.make_env()

        result = self.shell("controllerfs-show fake")
        self.assertIn(str(FAKE_CONTROLLER_FS['uuid']), result)
        self.assertIn(str(FAKE_CONTROLLER_FS['name']), result)
        self.assertIn(str(FAKE_CONTROLLER_FS['size']), result)
        self.assertIn(str(FAKE_CONTROLLER_FS['logical_volume']), result)
        self.assertIn(str(FAKE_CONTROLLER_FS['replicated']), result)
        self.assertIn(str(FAKE_CONTROLLER_FS['state']), result)
        self.assertIn(str(FAKE_CONTROLLER_FS['created_at']), result)
        self.assertIn(str(FAKE_CONTROLLER_FS['updated_at']), result)

    def test_controller_fs_modify(self):
        self.make_env()
        self.controller_fs_manager_list_result = [
            ControllerFs(None, MODIFY_CONTROLLER_FS, True)]

        results = self.shell("controllerfs-modify fake=15")

        self.assertIn(str(MODIFY_CONTROLLER_FS['uuid']), results)
        self.assertIn(str(MODIFY_CONTROLLER_FS['name']), results)
        self.assertIn(str(MODIFY_CONTROLLER_FS['size']), results)
        self.assertIn(str(MODIFY_CONTROLLER_FS['logical_volume']), results)
        self.assertIn(str(MODIFY_CONTROLLER_FS['replicated']), results)
        self.assertIn(str(MODIFY_CONTROLLER_FS['state']), results)
