# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /ihosts/<uuid>/vim methods.
"""
import mock
from six.moves import http_client
from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase


class TestVIM(base.FunctionalTest, dbbase.BaseHostTestCase):
    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    def _get_path(self, host_uuid):
        return f'/ihosts/{host_uuid}/vim'

    def _create_host(self, personality, subfunction=None,
                     mgmt_mac=None, mgmt_ip=None,
                     admin=None,
                     invprovision=constants.PROVISIONED, **kw):
        host = self._create_test_host(personality=personality,
                                      subfunction=subfunction,
                                      administrative=(admin or
                                      constants.ADMIN_UNLOCKED),
                                      invprovision=invprovision,
                                      **kw)
        return host


class VIMHostAuditTestCase(TestVIM):
    @mock.patch('sysinv.api.controllers.v1.vim_api.vim_host_action')
    def test_vim_host_audit(self, mock_vim_host_action):
        worker = self._create_host(constants.WORKER,
                                   admin=constants.ADMIN_LOCKED)
        host_uuid = worker['uuid']
        data = {"vim_event": "host-audit"}
        response = self.post_json(self._get_path(host_uuid), data, headers=self.API_HEADERS)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.json['vim_event'], constants.HOST_AUDIT_ACTION)
        self.assertEqual(response.json['ihost_uuid'], host_uuid)
        self.assertEqual(response.json['hostname'], worker['hostname'])
        mock_vim_host_action.assert_called_once_with(
            token=mock.ANY,
            uuid=worker["uuid"],
            hostname=worker["hostname"],
            action=constants.HOST_AUDIT_ACTION,
            timeout=constants.VIM_DEFAULT_TIMEOUT_IN_SECS
        )

    @mock.patch('sysinv.api.controllers.v1.vim_api.vim_host_action')
    def test_vim_host_audit_invalid_action(self, mock_vim_host_action):
        worker = self._create_host(constants.WORKER,
                                   admin=constants.ADMIN_LOCKED)
        host_uuid = worker['uuid']
        data = {"vim_event": "invalid-action"}
        response = self.post_json(self._get_path(host_uuid), data, headers=self.API_HEADERS,
                                  expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertIn("Unsupported action", response.json['error_message'])
        mock_vim_host_action.assert_not_called()
