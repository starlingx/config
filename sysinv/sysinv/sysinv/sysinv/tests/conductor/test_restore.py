#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identilfier: Apache-2.0
#

"""
Tests for the restore logic
"""

import mock
from oslo_context import context

from fm_api import fm_api
from sysinv.common import constants
from sysinv.conductor import manager
from sysinv.db import api as dbapi
from sysinv.tests.db import base


class RestoreTestCase(base.BaseHostTestCase):

    def setUp(self):
        super(RestoreTestCase, self).setUp()

        # Set up objects for testing
        self.service = manager.ConductorManager('test-host', 'test-topic')
        self.service.dbapi = dbapi.get_instance()
        self.service.fm_api = fm_api.FaultAPIs()
        self.context = context.get_admin_context()
        self.valid_restore_states = [
            constants.RESTORE_PROGRESS_ALREADY_COMPLETED,
            constants.RESTORE_PROGRESS_STARTED,
            constants.RESTORE_PROGRESS_ALREADY_IN_PROGRESS,
            constants.RESTORE_PROGRESS_NOT_IN_PROGRESS,
            constants.RESTORE_PROGRESS_IN_PROGRESS,
            constants.RESTORE_PROGRESS_COMPLETED]

        # Mock os.path.exists to return True by default for all tests
        self.mock_path_exists = mock.patch('os.path.exists', return_value=True)
        self.mock_path_exists.start()

    def tearDown(self):
        self.mock_path_exists.stop()
        super(RestoreTestCase, self).tearDown()

    def _create_controller(self, which, **kw):
        return self._create_test_host(
            personality=constants.CONTROLLER,
            subfunction=None,
            numa_nodes=1,
            unit=which,
            **kw)

    def test_restore_transitions(self):
        # Create controller-0
        _ = self._create_controller(
            which=0,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_AVAILABLE)

        self.service._rook_ceph_recovery_is_running = mock.Mock()

        self.assertEqual(self.service.get_restore_state(self.context),
                         constants.RESTORE_PROGRESS_NOT_IN_PROGRESS)
        self.assertEqual(self.service.complete_restore(self.context),
                         constants.RESTORE_PROGRESS_ALREADY_COMPLETED)

        self.assertEqual(self.service.start_restore(self.context),
                         constants.RESTORE_PROGRESS_STARTED)
        self.assertEqual(self.service.get_restore_state(self.context),
                         constants.RESTORE_PROGRESS_IN_PROGRESS)

        self.assertEqual(self.service.start_restore(self.context),
                         constants.RESTORE_PROGRESS_ALREADY_IN_PROGRESS)
        self.assertEqual(self.service.get_restore_state(self.context),
                         constants.RESTORE_PROGRESS_IN_PROGRESS)

        self.assertEqual(self.service.complete_restore(self.context),
                         constants.RESTORE_PROGRESS_COMPLETED)
        self.assertEqual(self.service.get_restore_state(self.context),
                         constants.RESTORE_PROGRESS_NOT_IN_PROGRESS)

    def test_restore_complete_rejection(self):
        # Create controller-0
        _ = self._create_controller(
            which=0,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_AVAILABLE)

        # Create controller-1
        _ = self._create_controller(
            which=1,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_DISABLED,
            availability=constants.AVAILABILITY_OFFLINE)

        self.assertEqual(self.service.get_restore_state(self.context),
                         constants.RESTORE_PROGRESS_NOT_IN_PROGRESS)
        self.assertTrue(self.service.complete_restore(self.context)
                        not in self.valid_restore_states)

        self.assertEqual(self.service.start_restore(self.context),
                         constants.RESTORE_PROGRESS_STARTED)
        self.assertEqual(self.service.get_restore_state(self.context),
                         constants.RESTORE_PROGRESS_IN_PROGRESS)

        self.assertEqual(self.service.start_restore(self.context),
                         constants.RESTORE_PROGRESS_ALREADY_IN_PROGRESS)
        self.assertEqual(self.service.get_restore_state(self.context),
                         constants.RESTORE_PROGRESS_IN_PROGRESS)

        self.assertTrue(self.service.complete_restore(self.context)
                        not in self.valid_restore_states)
        self.assertEqual(self.service.get_restore_state(self.context),
                         constants.RESTORE_PROGRESS_IN_PROGRESS)

    def test_complete_restore_sysinv_not_ready(self):
        # Create controller-0
        _ = self._create_controller(
            which=0,
            invprovision=constants.PROVISIONED,
            administrative=constants.ADMIN_UNLOCKED,
            operational=constants.OPERATIONAL_ENABLED,
            availability=constants.AVAILABILITY_AVAILABLE)

        self.service._rook_ceph_recovery_is_running = mock.Mock(return_value=False)

        # Start restore to create restore record in database
        self.assertEqual(self.service.start_restore(self.context),
                         constants.RESTORE_PROGRESS_STARTED)
        self.assertEqual(self.service.get_restore_state(self.context),
                         constants.RESTORE_PROGRESS_IN_PROGRESS)

        # Override mock to return False for complete_restore
        with mock.patch('os.path.exists', return_value=False):
            result = self.service.complete_restore(self.context)
            self.assertIn("System is not ready to apply runtime config", result)
