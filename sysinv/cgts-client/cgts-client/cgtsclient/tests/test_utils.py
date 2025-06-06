# Copyright 2013 OpenStack LLC.
# All Rights Reserved.
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


import sys

from cgtsclient.common import utils
from cgtsclient.common.utils import _is_service_impacting_command
from cgtsclient.common.utils import prompt_cli_confirmation
from cgtsclient import exc
from cgtsclient.tests import utils as test_utils
from six.moves import cStringIO as StringIO
from unittest import mock


class UtilsTest(test_utils.BaseTestCase):

    def test_prettytable(self):
        class Struct:
            def __init__(self, **entries):
                self.__dict__.update(entries)

        # test that the prettytable output is wellformatted (left-aligned)
        saved_stdout = sys.stdout
        try:
            sys.stdout = output_dict = StringIO()
            utils.print_dict({'K': 'k', 'Key': 'Value'})

        finally:
            sys.stdout = saved_stdout

        self.assertEqual(output_dict.getvalue(), '''\
+----------+-------+
| Property | Value |
+----------+-------+
| K        | k     |
| Key      | Value |
+----------+-------+
''')

    def test_args_array_to_dict(self):
        my_args = {
            'matching_metadata': ['metadata.key=metadata_value'],
            'other': 'value'
        }
        cleaned_dict = utils.args_array_to_dict(my_args,
                                                "matching_metadata")
        self.assertEqual(cleaned_dict, {
            'matching_metadata': {'metadata.key': 'metadata_value'},
            'other': 'value'
        })

    def test_args_array_to_patch(self):
        my_args = {
            'attributes': ['foo=bar', '/extra/bar=baz'],
            'op': 'add',
        }
        patch = utils.args_array_to_patch(my_args['op'],
                                          my_args['attributes'])
        self.assertEqual(patch, [{'op': 'add',
                                  'value': 'bar',
                                  'path': '/foo'},
                                 {'op': 'add',
                                  'value': 'baz',
                                  'path': '/extra/bar'}])

    def test_args_array_to_patch_format_error(self):
        my_args = {
            'attributes': ['foobar'],
            'op': 'add',
        }
        self.assertRaises(exc.CommandError, utils.args_array_to_patch,
                          my_args['op'], my_args['attributes'])

    def test_args_array_to_patch_remove(self):
        my_args = {
            'attributes': ['/foo', 'extra/bar'],
            'op': 'remove',
        }
        patch = utils.args_array_to_patch(my_args['op'],
                                          my_args['attributes'])
        self.assertEqual(patch, [{'op': 'remove', 'path': '/foo'},
                                 {'op': 'remove', 'path': '/extra/bar'}])


@prompt_cli_confirmation
def risky_func(*args, **kwargs):
    return "executed"


class TestPromptCLIConfirmation(test_utils.BaseTestCase):

    @mock.patch("cgtsclient.common.utils.input", return_value="yes")
    @mock.patch("cgtsclient.common.utils._is_cliconfirmation_param_enabled", return_value=True)
    @mock.patch("cgtsclient.common.utils.signal.alarm")
    @mock.patch("cgtsclient.common.utils.signal.signal")
    def test_user_accepts_prompt(self, mock_signal, mock_alarm, mock_flag, mock_input):
        result = risky_func("arg1", mock.Mock(yes=False))
        self.assertEqual(result, "executed")

    @mock.patch("cgtsclient.common.utils.input", return_value="no")
    @mock.patch("cgtsclient.common.utils._is_cliconfirmation_param_enabled", return_value=True)
    @mock.patch("cgtsclient.common.utils.signal.alarm")
    @mock.patch("cgtsclient.common.utils.signal.signal")
    def test_user_rejects_prompt(self, mock_signal, mock_alarm, mock_flag, mock_input):
        self.assertRaises(SystemExit, risky_func, "arg1", mock.Mock(yes=False))

    @mock.patch("cgtsclient.common.utils.input", side_effect=TimeoutError)
    @mock.patch("cgtsclient.common.utils._is_cliconfirmation_param_enabled", return_value=True)
    @mock.patch("cgtsclient.common.utils.signal.alarm")
    @mock.patch("cgtsclient.common.utils.signal.signal")
    def test_user_timeout(self, mock_signal, mock_alarm, mock_flag, mock_input):
        self.assertRaises(SystemExit, risky_func, "arg1", mock.Mock(yes=False))

    def test_yes_flag_skips_prompt(self):
        result = risky_func("arg1", mock.Mock(yes=True))
        self.assertEqual(result, "executed")

    @mock.patch("cgtsclient.common.utils._is_cliconfirmation_param_enabled", return_value=False)
    def test_confirmation_feature_disabled(self, mock_flag):
        result = risky_func("arg1", mock.Mock(yes=False))
        self.assertEqual(result, "executed")

    def test_command_contains_delete(self):
        self.assertTrue(_is_service_impacting_command("system host-delete"))
        self.assertTrue(_is_service_impacting_command("volume-delete"))
        self.assertTrue(_is_service_impacting_command("delete-tenant"))

    def test_command_contains_remove(self):
        self.assertTrue(_is_service_impacting_command("remove-node"))
        self.assertTrue(_is_service_impacting_command("system remove-host"))

    def test_safe_commands(self):
        self.assertFalse(_is_service_impacting_command("host-unlock"))
        self.assertFalse(_is_service_impacting_command("list-hosts"))
        self.assertFalse(_is_service_impacting_command("show-platform"))
