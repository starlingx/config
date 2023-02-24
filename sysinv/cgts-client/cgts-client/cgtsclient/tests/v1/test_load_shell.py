#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from mock import patch

from cgtsclient.exc import CommandError
from cgtsclient.tests import test_shell
from cgtsclient.v1.load import Load


class LoadImportShellTest(test_shell.ShellTest):
    def setUp(self):
        super(LoadImportShellTest, self).setUp()

        load_import = patch('cgtsclient.v1.load.LoadManager.import_load')
        self.mock_load_import = load_import.start()
        self.addCleanup(load_import.stop)

        load_show = patch('cgtsclient.v1.load_shell._print_load_show')
        self.mock_load_show = load_show.start()
        self.addCleanup(load_show.stop)

        load_list = patch('cgtsclient.v1.load.LoadManager.list')
        self.mock_load_list = load_list.start()
        self.addCleanup(load_list.stop)

        load_resource = {
            'software_version': '6.0',
            'compatible_version': '5.0',
            'required_patches': '',
        }
        self.load_resouce = Load(
            manager=None,
            info=load_resource,
            loaded=True,
        )

        self.mock_load_import.return_value = self.load_resouce
        self.mock_load_list.return_value = []
        self.mock_load_show.return_value = {}

        self.patch_expected = {
            'path_to_iso': '/home/bootimage.iso',
            'path_to_sig': '/home/bootimage.sig',
            'active': False,
            'local': False,
            'inactive': False,
        }

    @patch('os.path.isfile', lambda x: True)
    def test_load_import(self):
        self.make_env()

        cmd = 'load-import /home/bootimage.iso /home/bootimage.sig'
        self.shell(cmd)

        self.mock_load_import.assert_called_once()
        self.mock_load_list.assert_called_once()
        self.mock_load_show.assert_called_once()

        self.mock_load_import.assert_called_with(**self.patch_expected)

    @patch('os.path.abspath')
    @patch('os.path.isfile', lambda x: True)
    def test_load_import_relative_path(self, mock_abspath):
        self.make_env()

        mock_abspath.side_effect = [
            '/home/bootimage.iso',
            '/home/bootimage.sig',
        ]

        cmd = 'load-import bootimage.iso bootimage.sig'
        self.shell(cmd)

        self.mock_load_import.assert_called_once()
        self.mock_load_list.assert_called_once()
        self.mock_load_show.assert_called_once()

        self.mock_load_import.assert_called_with(**self.patch_expected)

    @patch('os.path.isfile', lambda x: True)
    def test_load_import_active(self):
        self.make_env()

        self.patch_expected['active'] = True

        cmd = '''
            load-import --active
            /home/bootimage.iso
            /home/bootimage.sig
        '''
        self.shell(cmd)

        self.mock_load_import.assert_called_once()
        self.mock_load_show.assert_called_once()

        self.mock_load_import.assert_called_with(**self.patch_expected)

        self.mock_load_list.assert_not_called()

    @patch('os.path.isfile', lambda x: True)
    def test_load_import_active_short_form(self):
        self.make_env()

        self.patch_expected['active'] = True

        cmd = '''
            load-import -a
            /home/bootimage.iso
            /home/bootimage.sig
        '''
        self.shell(cmd)

        self.mock_load_import.assert_called_once()
        self.mock_load_show.assert_called_once()

        self.mock_load_import.assert_called_with(**self.patch_expected)

        self.mock_load_list.assert_not_called()

    @patch('os.path.isfile', lambda x: True)
    def test_load_import_local(self):
        self.make_env()

        self.patch_expected['local'] = True

        cmd = '''
            load-import --local
            /home/bootimage.iso
            /home/bootimage.sig
        '''
        self.shell(cmd)

        self.mock_load_import.assert_called_once()
        self.mock_load_list.assert_called_once()
        self.mock_load_show.assert_called_once()

        self.mock_load_import.assert_called_with(**self.patch_expected)

    @patch('os.path.isfile', lambda x: True)
    def test_load_import_inactive(self):
        self.make_env()

        self.patch_expected['inactive'] = True

        cmd = '''
            load-import --inactive
            /home/bootimage.iso
            /home/bootimage.sig
        '''
        self.shell(cmd)

        self.mock_load_import.assert_called_once()
        self.mock_load_show.assert_called_once()
        self.mock_load_list.assert_not_called()

        self.mock_load_import.assert_called_with(**self.patch_expected)

    @patch('os.path.isfile', lambda x: True)
    def test_load_import_inactive_short_form(self):
        self.make_env()

        self.patch_expected['inactive'] = True

        cmd = '''
            load-import -i
            /home/bootimage.iso
            /home/bootimage.sig
        '''
        self.shell(cmd)

        self.mock_load_import.assert_called_once()
        self.mock_load_show.assert_called_once()
        self.mock_load_list.assert_not_called()

        self.mock_load_import.assert_called_with(**self.patch_expected)

    @patch('os.path.isfile', lambda x: True)
    def test_load_import_max_imported(self):
        self.make_env()

        self.mock_load_list.return_value = [
            {
                'id': 1,
                'state': 'ACTIVE',
                'software_version': '5',
            },
            {
                'id': 2,
                'state': 'IMPORTED',
                'software_version': '6',
            },
        ]

        cmd = 'load-import bootimage.iso bootimage.sig'
        self.assertRaises(CommandError, self.shell, cmd)

        self.mock_load_list.assert_called_once()

        self.mock_load_import.assert_not_called()
        self.mock_load_show.assert_not_called()

    def test_load_import_invalid_path(self):
        self.make_env()

        cmd = 'load-import bootimage.iso bootimage.sig'
        self.assertRaises(CommandError, self.shell, cmd)

        self.mock_load_import.assert_not_called()
        self.mock_load_list.assert_not_called()
        self.mock_load_show.assert_not_called()
