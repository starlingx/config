#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2020 Intel Corporation
# Copyright (c) 2026 Wind River Systems, Inc.
#
# All Rights Reserved.
#

"""Test class for Sysinv kube_app AppOperator."""

import fixtures
import re

from unittest import mock

from oslo_context import context

from sysinv.common import constants
from sysinv.common import exception
from sysinv.conductor import kube_app
from sysinv.conductor import manager
from sysinv.db import api as dbapi
from sysinv.db.sqlalchemy import models
from sysinv.helm import helm
from sysinv.helm.lifecycle_constants import LifecycleConstants
from sysinv.helm.lifecycle_hook import LifecycleHookInfo
from sysinv.objects import kube_app as obj_app

from sysinv.tests.db import base
from sysinv.tests.db import utils as dbutils


class AppOperatorTestCase(base.DbTestCase):

    def setUp(self):
        super(AppOperatorTestCase, self).setUp()

        # Manager holds apps_metadata dict
        self.service = manager.ConductorManager('test-host', 'test-topic')

        # Set up objects for testing
        self.helm_operator = helm.HelmOperator(dbapi.get_instance())
        self.app_operator = kube_app.AppOperator(dbapi.get_instance(),
                                                 self.helm_operator,
                                                 self.service.apps_metadata)
        self.context = context.get_admin_context()
        self.dbapi = dbapi.get_instance()
        self.temp_dir = self.useFixture(fixtures.TempDir())

    def test_activate(self):
        # Create kubernetes apps
        dbutils.create_test_app(name='test-app-1',
                                active=True)
        test_app_1 = obj_app.get_by_name(self.context, 'test-app-1')
        self.assertEqual(test_app_1.active, True)
        res = self.app_operator.activate(test_app_1)
        # check was_active
        self.assertEqual(res, True)
        # check current active
        self.assertEqual(test_app_1.active, True)

        dbutils.create_test_app(name='test-app-2',
                                active=False)
        test_app_2 = obj_app.get_by_name(self.context, 'test-app-2')
        self.assertEqual(test_app_2.active, False)
        res = self.app_operator.activate(test_app_2)
        # check was_active
        self.assertEqual(res, False)
        # check current active
        self.assertEqual(test_app_2.active, True)

    def test_deactivate(self):
        # Create kubernetes apps
        dbutils.create_test_app(name='test-app-1',
                                active=True)
        test_app_1 = obj_app.get_by_name(self.context, 'test-app-1')
        self.assertEqual(test_app_1.active, True)
        res = self.app_operator.deactivate(test_app_1)
        # check was_active
        self.assertEqual(res, True)
        # check current active
        self.assertEqual(test_app_1.active, False)

        dbutils.create_test_app(name='test-app-2',
                                active=False)
        test_app_2 = obj_app.get_by_name(self.context, 'test-app-2')
        self.assertEqual(test_app_2.active, False)
        res = self.app_operator.deactivate(test_app_2)
        # check was_active
        self.assertEqual(res, False)
        # check current active
        self.assertEqual(test_app_2.active, False)

    def test_get_appname(self):
        test_app_name = 'test-app-1'
        dbutils.create_test_app(name=test_app_name,
                                status=constants.APP_APPLY_SUCCESS)
        test_app_1 = obj_app.get_by_name(self.context, 'test-app-1')
        app_name = self.app_operator.get_appname(test_app_1)
        self.assertEqual(test_app_name, app_name)

    def test_is_app_active(self):
        dbutils.create_test_app(name='test-app-1',
                                active=True)
        test_app_1 = obj_app.get_by_name(self.context, 'test-app-1')
        self.app_operator.activate(test_app_1)
        is_active = self.app_operator.is_app_active(test_app_1)
        self.assertEqual(is_active, True)
        self.app_operator.deactivate(test_app_1)
        is_active = self.app_operator.is_app_active(test_app_1)
        self.assertEqual(is_active, False)

    def test_reapply(self):
        dbutils.create_test_app(name='test-app-1',
                                active=True)
        constants.APP_PENDING_REAPPLY_FLAG = self.temp_dir.path + "/.app_reapply"
        self.app_operator.set_reapply('test-app-1')
        result = self.app_operator.needs_reapply('test-app-1')
        self.assertEqual(result, True)
        self.app_operator.clear_reapply('test-app-1')
        result = self.app_operator.needs_reapply('test-app-1')
        self.assertEqual(result, False)

    def test_is_app_aborted(self):
        self.app_operator.abort_requested["test_app"] = True
        res = self.app_operator.is_app_aborted("test_app")
        self.assertEqual(res, True)
        res = self.app_operator.is_app_aborted("test_app_123")
        self.assertEqual(res, False)

    def test_load_application_metadata_from_database_with_metadata(self):
        metadata = {"desired_state": "applied", "maintain_user_overrides": True}
        dbutils.create_test_app(name="test-app-1", app_metadata=metadata)
        test_app = obj_app.get_by_name(self.context, "test-app-1")

        self.app_operator.load_application_metadata_from_database(test_app)

        self.assertIn("test-app-1", self.service.apps_metadata["apps"])
        self.assertEqual(self.service.apps_metadata["apps"]["test-app-1"], metadata)

    def test_load_application_metadata_from_database_without_metadata(self):
        dbutils.create_test_app(name="test-app-2", app_metadata=None)
        test_app = obj_app.get_by_name(self.context, "test-app-2")

        with fixtures.MockPatchObject(
            self.app_operator, "load_application_metadata_from_file"
        ) as mock_load:
            self.app_operator.load_application_metadata_from_database(test_app)
            self.assertEqual(mock_load.mock.call_count, 1)

    def test_clear_stuck_applications_recovers_update_starting(self):
        """An app interrupted (e.g. by a controller swact) while in the
        'update-starting' status must be recovered by
        _clear_stuck_applications() on the next conductor start, the same
        way 'updating' (APP_UPDATE_IN_PROGRESS) already is.

        Before the fix, APP_UPDATE_STARTING was missing from the status
        list checked by _clear_stuck_applications(), so the app was left
        stuck forever and the "Application Update In Progress" alarm was
        never cleared.

        See https://bugs.launchpad.net/starlingx/+bug/2164738
        """
        dbutils.create_test_app(name='test-app-1',
                                status=constants.APP_UPDATE_STARTING)

        self.app_operator._clear_stuck_applications()

        updated_app = obj_app.get_by_name(self.context, 'test-app-1')
        self.assertNotEqual(updated_app.status,
                            constants.APP_UPDATE_STARTING)
        self.assertEqual(updated_app.status, constants.APP_APPLY_FAILURE)

    def test_clear_stuck_applications_recovers_update_starting_platform_managed(self):
        """For platform-managed apps stuck in 'update-starting', recovery
        should set the status back to 'uploaded' (not 'apply-failed') so
        that the periodic app audit can safely reapply it, matching the
        existing behavior for APP_UPDATE_IN_PROGRESS.
        """
        dbutils.create_test_app(name='platform-integ-apps',
                                status=constants.APP_UPDATE_STARTING)
        self.service.apps_metadata[
            constants.APP_METADATA_PLATFORM_MANAGED_APPS][
                'platform-integ-apps'] = {}

        self.app_operator._clear_stuck_applications()

        updated_app = obj_app.get_by_name(self.context, 'platform-integ-apps')
        self.assertEqual(updated_app.status, constants.APP_UPLOAD_SUCCESS)

    def test_abort_operation_handles_update_starting(self):
        """_abort_operation() must have explicit handling for
        APP_UPDATE_STARTING instead of falling through to the
        'No abort handling code for app status' error path.
        """
        dbutils.create_test_app(name='test-app-1',
                                status=constants.APP_UPDATE_STARTING)
        test_app = obj_app.get_by_name(self.context, 'test-app-1')
        app = kube_app.AppOperator.Application(test_app)

        with fixtures.MockPatchObject(
            self.app_operator, "app_lifecycle_actions"
        ):
            self.app_operator._abort_operation(
                app, app.status, reset_status=True)

        updated_app = obj_app.get_by_name(self.context, 'test-app-1')
        self.assertEqual(updated_app.status, constants.APP_APPLY_FAILURE)

    def test_reset_recovery_attempts_clears_counter(self):
        """A successful apply must clear the auto-recovery attempt counter.

        A transient failure that is later recovered must not leave
        recovery_attempts elevated, or a future failure inherits a
        reduced retry budget.
        """
        dbutils.create_test_app(name='test-app-1',
                                status=constants.APP_APPLY_SUCCESS,
                                recovery_attempts=3)
        test_app = obj_app.get_by_name(self.context, 'test-app-1')
        app = kube_app.AppOperator.Application(test_app)
        self.assertEqual(app.recovery_attempts, 3)

        app.reset_recovery_attempts()

        updated_app = obj_app.get_by_name(self.context, 'test-app-1')
        self.assertEqual(updated_app.recovery_attempts, 0)

    def test_reset_recovery_attempts_noop_when_already_zero(self):
        """Resetting an already-zero counter should not raise or persist."""
        dbutils.create_test_app(name='test-app-1',
                                status=constants.APP_APPLY_SUCCESS,
                                recovery_attempts=0)
        test_app = obj_app.get_by_name(self.context, 'test-app-1')
        app = kube_app.AppOperator.Application(test_app)

        app.reset_recovery_attempts()

        updated_app = obj_app.get_by_name(self.context, 'test-app-1')
        self.assertEqual(updated_app.recovery_attempts, 0)

    def test_clear_stuck_applications_reports_missing_dependent_apps(self):
        """When a platform-managed app is reset back to 'uploaded', the
        progress message must keep reporting its missing dependent apps,
        matching what perform_app_upload does. Otherwise the reason the
        app cannot be applied is lost from the progress column.
        """
        dbutils.create_test_app(name='platform-integ-apps',
                                status=constants.APP_UPDATE_STARTING)
        self.service.apps_metadata[
            constants.APP_METADATA_PLATFORM_MANAGED_APPS][
                'platform-integ-apps'] = {}

        metadata = {
            constants.APP_METADATA_DEPENDENT_APPS: [
                {'name': 'dependency-app', 'version': '1.0-1'}
            ]
        }
        with fixtures.MockPatchObject(
            self.app_operator, "retrieve_application_metadata_from_file",
            return_value=metadata
        ):
            self.app_operator._clear_stuck_applications()

        updated_app = obj_app.get_by_name(self.context, 'platform-integ-apps')
        self.assertEqual(updated_app.status, constants.APP_UPLOAD_SUCCESS)
        self.assertIn('dependency-app', updated_app.progress)
        self.assertIn('missing apps', updated_app.progress)

    def test_clear_stuck_applications_no_missing_dependent_apps(self):
        """With no missing dependent apps, the progress message must be
        left untouched by the dependency evaluation.
        """
        dbutils.create_test_app(name='platform-integ-apps',
                                status=constants.APP_UPDATE_STARTING)
        self.service.apps_metadata[
            constants.APP_METADATA_PLATFORM_MANAGED_APPS][
                'platform-integ-apps'] = {}

        with fixtures.MockPatchObject(
            self.app_operator, "retrieve_application_metadata_from_file",
            return_value={}
        ):
            self.app_operator._clear_stuck_applications()

        updated_app = obj_app.get_by_name(self.context, 'platform-integ-apps')
        self.assertEqual(updated_app.status, constants.APP_UPLOAD_SUCCESS)
        self.assertNotIn('missing apps', updated_app.progress)

    def test_clear_stuck_applications_progress_fits_db_column(self):
        """The progress message must fit the 'progress' column.

        The message is assembled from an unbounded list of missing
        dependent apps, so with enough dependencies it can exceed the
        column width. Persisting it then raises DBError from inside
        AppOperator.__init__, which propagates out of
        ConductorManager._start() and prevents the conductor from ever
        starting its RPC server, leaving every subsequent RPC to time
        out.

        This cannot be caught by a DB round-trip: the test backend does
        not enforce VARCHAR lengths, so the length is asserted directly.
        """
        progress_max_length = models.KubeApp.progress.type.length

        dbutils.create_test_app(name='platform-integ-apps',
                                status=constants.APP_UPDATE_STARTING)
        self.service.apps_metadata[
            constants.APP_METADATA_PLATFORM_MANAGED_APPS][
                'platform-integ-apps'] = {}

        # Enough dependencies to overflow the column on their own
        metadata = {
            constants.APP_METADATA_DEPENDENT_APPS: [
                {'name': 'dependency-app-%d' % i, 'version': r'\d+\.\d+-\d+'}
                for i in range(10)
            ]
        }
        with fixtures.MockPatchObject(
            self.app_operator, "retrieve_application_metadata_from_file",
            return_value=metadata
        ):
            self.app_operator._clear_stuck_applications()

        updated_app = obj_app.get_by_name(self.context, 'platform-integ-apps')
        self.assertEqual(updated_app.status, constants.APP_UPLOAD_SUCCESS)
        self.assertLessEqual(len(updated_app.progress), progress_max_length)
        # The reason must still be reported, not truncated away entirely
        self.assertIn('missing apps', updated_app.progress)

    def test_abort_operation_progress_fits_db_column(self):
        """_abort_operation must bound the progress message it persists.

        Guards the reset_status=True branch, which writes to the DB
        directly instead of going through _update_app_status().
        """
        progress_max_length = models.KubeApp.progress.type.length

        dbutils.create_test_app(name='platform-integ-apps',
                                status=constants.APP_APPLY_IN_PROGRESS)
        self.service.apps_metadata[
            constants.APP_METADATA_PLATFORM_MANAGED_APPS][
                'platform-integ-apps'] = {}
        test_app = obj_app.get_by_name(self.context, 'platform-integ-apps')
        app = kube_app.AppOperator.Application(test_app)

        oversized_msg = 'x' * (progress_max_length * 2)
        with fixtures.MockPatchObject(
            self.app_operator, "_append_missing_dependent_apps_msg",
            return_value=oversized_msg
        ):
            self.app_operator._abort_operation(app, app.status,
                                               reset_status=True)

        updated_app = obj_app.get_by_name(self.context, 'platform-integ-apps')
        self.assertEqual(updated_app.status, constants.APP_UPLOAD_SUCCESS)
        self.assertLessEqual(len(updated_app.progress), progress_max_length)


class _FakeCondition(object):
    def __init__(self, cond_type, status, reason=None):
        self.type = cond_type
        self.status = status
        self.reason = reason


class _FakePodStatus(object):
    def __init__(self, phase=None, conditions=None, reason=None, message=None):
        self.phase = phase
        self.conditions = conditions
        self.reason = reason
        self.message = message


class _FakeMeta(object):
    def __init__(self, name):
        self.name = name


class _FakePod(object):
    def __init__(self, name, *, phase=None, ready=None, ready_reason=None,
                 reason=None, has_status=True):
        self.metadata = _FakeMeta(name)
        if not has_status:
            self.status = None
            return
        conditions = None
        if ready is not None:
            status = 'True' if ready else 'False'
            conditions = [_FakeCondition('Ready', status, ready_reason)]
        self.status = _FakePodStatus(phase=phase, conditions=conditions,
                                     reason=reason)


class VerifyPodsStatusForReleaseTestCase(base.DbTestCase):
    """Tests for FluxCDHelper.verify_pods_status_for_release().

    An orphaned 'Failed' pod (left by a node reboot) must not block the
    release, as long as the live replacement pod is ready. A genuinely
    not-ready pod must still block it.
    """

    def setUp(self):
        super(VerifyPodsStatusForReleaseTestCase, self).setUp()
        self.dbapi = dbapi.get_instance()
        self.kube = mock.MagicMock()
        self.fluxcd = kube_app.FluxCDHelper(self.dbapi, self.kube)
        self.chart_obj = {"chart_label": "dex", "namespace": "kube-system"}

        # Force the AIO-SX code path (the check is a no-op otherwise).
        p = mock.patch(
            'sysinv.common.utils.is_aio_simplex_system', return_value=True)
        p.start()
        self.addCleanup(p.stop)

    def _set_pods(self, pods):
        self.kube.kube_get_pods_by_selector.return_value = pods

    def test_orphaned_failed_pod_with_ready_replacement_is_ready(self):
        # Orphaned Failed pod next to a ready replacement -> release ready.
        self._set_pods([
            _FakePod('oidc-dex-old-orphan', phase='Failed', ready=False,
                     reason='Terminated'),
            _FakePod('oidc-dex-new', phase='Running', ready=True),
        ])
        self.assertTrue(
            self.fluxcd.verify_pods_status_for_release(self.chart_obj))

    def test_genuinely_not_ready_pod_blocks(self):
        # A live pod that is simply not ready yet must still gate readiness.
        self._set_pods([
            _FakePod('oidc-dex-new', phase='Running', ready=False),
        ])
        self.assertFalse(
            self.fluxcd.verify_pods_status_for_release(self.chart_obj))

    def test_all_pods_ready(self):
        self._set_pods([
            _FakePod('oidc-dex-a', phase='Running', ready=True),
            _FakePod('oidc-dex-b', phase='Running', ready=True),
        ])
        self.assertTrue(
            self.fluxcd.verify_pods_status_for_release(self.chart_obj))

    def test_completed_job_pod_is_ready(self):
        # A completed Job pod (Succeeded/PodCompleted) is treated as ready
        # via check_pod_completed(), not skipped as a failure.
        self._set_pods([
            _FakePod('some-job', phase='Succeeded', ready=False,
                     ready_reason='PodCompleted'),
        ])
        self.assertTrue(
            self.fluxcd.verify_pods_status_for_release(self.chart_obj))

    def test_failed_pod_alone_still_reports_ready(self):
        # Only a Failed orphan and no live pod -> release is ready.
        self._set_pods([
            _FakePod('oidc-dex-old-orphan', phase='Failed', ready=False,
                     reason='Terminated'),
        ])
        self.assertTrue(
            self.fluxcd.verify_pods_status_for_release(self.chart_obj))

    def test_pod_with_no_status_is_skipped(self):
        # A pod with no status yet is skipped (not an error); a ready pod
        # still keeps the result True.
        self._set_pods([
            _FakePod('pending-pod', has_status=False),
            _FakePod('oidc-dex-new', phase='Running', ready=True),
        ])
        self.assertTrue(
            self.fluxcd.verify_pods_status_for_release(self.chart_obj))

    def test_no_pods_is_ready(self):
        self._set_pods([])
        self.assertTrue(
            self.fluxcd.verify_pods_status_for_release(self.chart_obj))


class AppOperatorLifecycleHookTestCase(base.DbTestCase):
    """Tests for the lifecycle hook dispatch observability.

    The lifecycle operator is mocked here, since what is under test is the
    dispatch performed by AppOperator.app_lifecycle_actions() and not the
    behaviour of any particular application plugin.
    """

    EXECUTION_ID_RE = re.compile(
        r"Execution id: "
        r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")

    def setUp(self):
        super(AppOperatorLifecycleHookTestCase, self).setUp()

        # Manager holds apps_metadata dict
        self.service = manager.ConductorManager('test-host', 'test-topic')

        self.helm_operator = mock.MagicMock()
        self.app_operator = kube_app.AppOperator(dbapi.get_instance(),
                                                 self.helm_operator,
                                                 self.service.apps_metadata)
        self.context = context.get_admin_context()

    def _dispatch_lifecycle_hook(self, app_name='test-hook-app',
                                 hook_side_effect=None,
                                 activate_side_effect=None):
        """Dispatch a lifecycle hook with a mocked lifecycle operator."""
        dbutils.create_test_app(name=app_name)
        rpc_app = obj_app.get_by_name(self.context, app_name)

        hook_info = LifecycleHookInfo()
        hook_info.init(LifecycleConstants.APP_LIFECYCLE_MODE_MANUAL,
                       LifecycleConstants.APP_LIFECYCLE_TYPE_OPERATION,
                       LifecycleConstants.APP_LIFECYCLE_TIMING_PRE,
                       constants.APP_APPLY_OP)

        lifecycle_op = mock.MagicMock()
        lifecycle_op.app_lifecycle_actions.side_effect = hook_side_effect

        self.helm_operator.get_app_lifecycle_operator.return_value = lifecycle_op
        self.helm_operator.plugins.activate_plugins.side_effect = \
            activate_side_effect

        self.app_operator.app_lifecycle_actions(
            None, None, rpc_app, hook_info)

    def test_logs_start_and_finish(self):
        """A successful hook execution must log both a start and a finish
        message, sharing the same execution id, and the finish message must
        report how long the hook took.
        """
        self._dispatch_lifecycle_hook()

        output = self.log_fixture.output
        execution_ids = self.EXECUTION_ID_RE.findall(output)

        self.assertIn('started', output)
        self.assertEqual(len(execution_ids), 2)
        self.assertEqual(execution_ids[0], execution_ids[1])
        self.assertIsNotNone(
            re.search(r"completed in \d+\.\d{3} seconds", output))

    def test_logs_finish_on_failure(self):
        """A hook that raises must still log the finish message, reporting
        the failure, and the exception must be propagated to the caller.
        """
        self.assertRaises(
            exception.SysinvException,
            self._dispatch_lifecycle_hook,
            hook_side_effect=exception.SysinvException("hook exploded"))

        output = self.log_fixture.output
        execution_ids = self.EXECUTION_ID_RE.findall(output)

        self.assertEqual(len(execution_ids), 2)
        self.assertEqual(execution_ids[0], execution_ids[1])
        self.assertIn('failed (SysinvException: hook exploded)', output)

    def test_logs_rejection_as_rejected(self):
        """An operation rejected by a semantic check is expected behaviour,
        not a failure, and must be reported as such.
        """
        self.assertRaises(
            exception.LifecycleSemanticCheckException,
            self._dispatch_lifecycle_hook,
            hook_side_effect=exception.LifecycleSemanticCheckException())

        output = self.log_fixture.output

        self.assertIn('rejected (LifecycleSemanticCheckException', output)
        self.assertNotIn('failed (', output)

    def test_logs_finish_on_plugin_activation_failure(self):
        """Plugin activation failures must not leave a start message without
        its matching finish message.
        """
        self.assertRaises(
            exception.SysinvException,
            self._dispatch_lifecycle_hook,
            activate_side_effect=exception.SysinvException("no plugins"))

        output = self.log_fixture.output
        execution_ids = self.EXECUTION_ID_RE.findall(output)

        self.assertEqual(len(execution_ids), 2)
        self.assertEqual(execution_ids[0], execution_ids[1])
        self.assertIn('failed (SysinvException: no plugins)', output)

    def test_execution_ids_are_unique(self):
        """Each hook execution must get its own id, so that concurrent
        executions can be told apart.
        """
        self._dispatch_lifecycle_hook(app_name='test-hook-app-1')
        self._dispatch_lifecycle_hook(app_name='test-hook-app-2')

        execution_ids = self.EXECUTION_ID_RE.findall(self.log_fixture.output)

        self.assertEqual(len(execution_ids), 4)
        self.assertEqual(execution_ids[0], execution_ids[1])
        self.assertEqual(execution_ids[2], execution_ids[3])
        self.assertNotEqual(execution_ids[0], execution_ids[2])
