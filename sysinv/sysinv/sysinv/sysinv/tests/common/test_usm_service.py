#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from unittest import TestCase
from unittest import mock
from sysinv.common.usm_service import get_platform_upgrade
from sysinv.common.usm_service import UsmUpgrade
from sysinv.common.usm_service import get_host_deploy


class TestUSMService(TestCase):
    @mock.patch('sysinv.common.usm_service.is_usm_authapi_ready', lambda: True)
    @mock.patch('sysinv.common.usm_service.get_software_upgrade')
    def test_get_platform_upgrade_with_usm_service(self, mock_get_software_upgrade):
        usm_deploy = {
            "from_release": "1.0",
            "to_release": "2.0",
            "state": "in_progress"
        }
        expected_response = UsmUpgrade(
                "in_progress",
                "1.0",
                "2.0")
        mock_get_software_upgrade.return_value = usm_deploy
        mock_dbapi = mock.Mock()
        mock_dbapi.software_upgrade_get_one.return_value = None

        result = get_platform_upgrade(mock_dbapi)

        self.assertEqual(result, expected_response)

    @mock.patch('sysinv.common.usm_service.get_usm_endpoint')
    @mock.patch('sysinv.common.usm_service._get_token')
    @mock.patch('sysinv.common.usm_service.get_region_name')
    @mock.patch('sysinv.common.usm_service.rest_api_request')
    def test_get_host_deploy(self,
                             mock_rest_api_request,
                             mock_get_region_name,
                             mock_get_token,
                             mock_get_usm_endpoint):

        mock_get_region_name.return_value = "RegionOne"
        mock_get_token.return_value = None
        mock_get_usm_endpoint.return_value = "localhost:3000"

        host_deploy_controller_0 = {
            "hostname": "controller-0",
            "software_release": "24.09.0",
            "target_release": "24.09.1",
            "reboot_required": "true",
            "host_state": "pending"
        }

        host_deploy_controller_1 = {
            "hostname": "controller-1",
            "software_release": "24.09.0",
            "target_release": "24.09.1",
            "reboot_required": "true",
            "host_state": "pending"
        }

        valid_host_deploy_list = [
            host_deploy_controller_0,
            host_deploy_controller_1
        ]

        class FakeObject(object):
            a = 0
            b = 'c'
            d = None

        error_string = "HTTP Error e.code=401 e=HTTP Error 401: Unauthorized"

        mock_dbapi = mock.Mock()
        hostname = 'controller-0'

        # Handle variety of responses from rest api
        mock_rest_api_request.side_effect = [
            None,
            {},
            FakeObject(),
            error_string,
            valid_host_deploy_list,
        ]

        # None
        result = get_host_deploy(mock_dbapi, hostname)
        self.assertEqual(result, None)

        # {} - empty dict
        result = get_host_deploy(mock_dbapi, hostname)
        self.assertEqual(result, None)

        # FakeObject
        result = get_host_deploy(mock_dbapi, hostname)
        self.assertEqual(result, None)

        # error string
        result = get_host_deploy(mock_dbapi, hostname)
        self.assertEqual(result, None)

        # valid_host_deploy_list
        result = get_host_deploy(mock_dbapi, hostname)
        self.assertDictEqual(result, host_deploy_controller_0)
