#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identilfier: Apache-2.0
#

"""
Tests for the restore logic
"""

from oslo_context import context

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
        self.context = context.get_admin_context()
        self.valid_restore_states = [
            constants.RESTORE_PROGRESS_ALREADY_COMPLETED,
            constants.RESTORE_PROGRESS_STARTED,
            constants.RESTORE_PROGRESS_ALREADY_IN_PROGRESS,
            constants.RESTORE_PROGRESS_NOT_IN_PROGRESS,
            constants.RESTORE_PROGRESS_IN_PROGRESS,
            constants.RESTORE_PROGRESS_COMPLETED]

    def tearDown(self):
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
