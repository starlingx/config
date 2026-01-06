# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
import json

from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.api.controllers.v1 import vim_api


class VimApiTestCase(base.FunctionalTest):

    def setUp(self):
        super(VimApiTestCase, self).setUp()

    @mock.patch('sysinv.api.controllers.v1.vim_api.rest_api_request')
    def test_vim_host_action_audit(self, mock_rest_api_request):
        # Mock the rest_api_request response
        mock_rest_api_request.return_value = {'status': 'success'}

        # Test parameters
        token = None
        uuid = '1be26c0b-03f2-4d2e-ae87-c02d7f33c123'
        hostname = 'controller-0'
        action = constants.HOST_AUDIT_ACTION
        timeout = constants.VIM_DEFAULT_TIMEOUT_IN_SECS

        # Call the function
        result = vim_api.vim_host_action(token, uuid, hostname, action, timeout)

        # Verify the result
        self.assertEqual(result, {'status': 'success'})

        # Verify rest_api_request was called with the correct parameters
        expected_url = "http://localhost:30001/nfvi-plugins/v1/hosts/%s" % uuid
        expected_headers = {
            'Content-type': 'application/json',
            'User-Agent': 'sysinv/1.0'
        }
        expected_payload = {
            'uuid': uuid,
            'hostname': hostname,
            'action': action
        }

        mock_rest_api_request.assert_called_once_with(
            token,
            "PATCH",
            expected_url,
            expected_headers,
            json.dumps(expected_payload),
            timeout
        )

    def test_vim_host_action_invalid_action(self):
        # Test with an invalid action
        token = None
        uuid = '1be26c0b-03f2-4d2e-ae87-c02d7f33c123'
        hostname = 'controller-0'
        action = 'invalid-action'
        timeout = constants.VIM_DEFAULT_TIMEOUT_IN_SECS

        # Call the function
        result = vim_api.vim_host_action(token, uuid, hostname, action, timeout)

        # Verify the result is None for invalid action
        self.assertIsNone(result)

    @mock.patch('sysinv.api.controllers.v1.vim_api.rest_api_request')
    def test_vim_host_action_valid_actions(self, mock_rest_api_request):
        # Test that all valid actions are accepted
        mock_rest_api_request.return_value = {'status': 'success'}

        token = None
        uuid = '1be26c0b-03f2-4d2e-ae87-c02d7f33c123'
        hostname = 'controller-0'
        timeout = constants.VIM_DEFAULT_TIMEOUT_IN_SECS

        valid_actions = [
            constants.UNLOCK_ACTION,
            constants.LOCK_ACTION,
            constants.FORCE_LOCK_ACTION,
            constants.FORCE_UNSAFE_LOCK_ACTION,
            constants.HOST_AUDIT_ACTION
        ]

        for action in valid_actions:
            result = vim_api.vim_host_action(token, uuid, hostname, action, timeout)
            self.assertEqual(result, {'status': 'success'})
