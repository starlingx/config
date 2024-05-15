#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from unittest import TestCase
from unittest import mock
from sysinv.common.usm_service import get_platform_upgrade
from sysinv.common.usm_service import UsmUpgrade


class TestUSMService(TestCase):
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

    def test_get_platform_upgrade_without_usm_service(self):
        mock_dbapi_response = {
            "from_release": "1.0",
            "to_release": "2.0",
            "state": "in_progress"
        }

        mock_dbapi = mock.Mock()
        mock_dbapi.software_upgrade_get_one.return_value = mock_dbapi_response

        result = get_platform_upgrade(mock_dbapi)

        self.assertEqual(result, mock_dbapi_response)
