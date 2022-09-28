#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /upgrade/ methods.
"""

import mock
from six.moves import http_client

from sysinv.common import constants
from sysinv.common import kubernetes

from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class FakeConductorAPI(object):

    def __init__(self):
        self.start_upgrade = mock.MagicMock()
        self.get_system_health_return = (True, "System is super healthy")

    def get_system_health(self, context, force=False, upgrade=False,
                          kube_upgrade=False, alarm_ignore_list=None):
        if force:
            return True, "System is healthy because I was forced to say that"
        else:
            return self.get_system_health_return


class TestUpgrade(base.FunctionalTest, dbbase.BaseSystemTestCase):

    def setUp(self):
        super(TestUpgrade, self).setUp()

        # Mock the Conductor API
        self.fake_conductor_api = FakeConductorAPI()
        p = mock.patch('sysinv.conductor.rpcapiproxy.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)

        # Behave as if the API is running on controller-0
        p = mock.patch('socket.gethostname')
        self.mock_socket_gethostname = p.start()
        self.mock_socket_gethostname.return_value = 'controller-0'
        self.addCleanup(p.stop)


class TestPostUpgrade(TestUpgrade, dbbase.ControllerHostTestCase):

    def test_create(self):
        # Create the to load
        dbutils.create_test_load(software_version=dbutils.SW_VERSION_NEW,
                                 compatible_version=dbutils.SW_VERSION,
                                 state=constants.IMPORTED_LOAD_STATE)

        # Test creation of upgrade
        create_dict = dbutils.get_test_upgrade()
        result = self.post_json('/upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'})

        # Verify that the upgrade was started
        self.fake_conductor_api.start_upgrade.assert_called_once()

        # Verify that the upgrade has the expected attributes
        self.assertEqual(result.json['from_release'], dbutils.SW_VERSION)
        self.assertEqual(result.json['to_release'], dbutils.SW_VERSION_NEW)
        self.assertEqual(result.json['state'], constants.UPGRADE_STARTING)

    def test_create_kube_upgrade_exists(self):
        # Test creation of upgrade when a kubernetes upgrade exists
        dbutils.create_test_kube_upgrade(
            from_version='v1.42.1',
            to_version='v1.42.2',
            state=kubernetes.KUBE_UPGRADING_FIRST_MASTER,
        )

        # Test creation of upgrade
        create_dict = dbutils.get_test_upgrade()
        result = self.post_json('/upgrade', create_dict,
                                headers={'User-Agent': 'sysinv-test'},
                                expect_errors=True)

        # Verify the failure
        self.assertEqual(result.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, result.status_int)
        self.assertIn("cannot be done while a kubernetes upgrade",
                      result.json['error_message'])
