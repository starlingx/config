#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# All Rights Reserved.
#

"""Tests for rollback behavior on a failed application-update.

Covers the update_failure_no_rollback policy in AppOperator.perform_app_update
(recover/rollback by default, skip recovery when the target app opts out) and
the _get_metadata_value warnings that keep a missing/empty metadata file from
failing silently.
"""

import os

import fixtures

from unittest import mock

from oslo_context import context

import yaml

from sysinv.common import constants
from sysinv.common import exception
from sysinv.conductor import kube_app
from sysinv.conductor import manager
from sysinv.db import api as dbapi
from sysinv.helm import helm
from sysinv.helm.lifecycle_hook import LifecycleHookInfo
from sysinv.objects import kube_app as obj_app

from sysinv.tests.db import base
from sysinv.tests.db import utils as dbutils


class _MetadataHandlingTestCase(base.DbTestCase):
    """Common setup: an AppOperator with an isolated APP_INSTALL_PATH."""

    def setUp(self):
        super(_MetadataHandlingTestCase, self).setUp()

        self.service = manager.ConductorManager('test-host', 'test-topic')
        self.helm_operator = helm.HelmOperator(dbapi.get_instance())
        self.app_operator = kube_app.AppOperator(dbapi.get_instance(),
                                                 self.helm_operator,
                                                 self.service.apps_metadata)
        self.context = context.get_admin_context()
        self.dbapi = dbapi.get_instance()
        self.temp_dir = self.useFixture(fixtures.TempDir())

        # Point APP_INSTALL_PATH at a temp dir so Application.inst_path is
        # writable and isolated from the host.
        self.useFixture(fixtures.MonkeyPatch(
            'sysinv.common.constants.APP_INSTALL_PATH', self.temp_dir.path))

    def _make_app(self, name, version, status, app_metadata=None):
        rpc_app = dbutils.create_test_app(name=name, app_version=version,
                                          status=status,
                                          app_metadata=app_metadata)
        app = kube_app.AppOperator.Application(rpc_app)
        os.makedirs(app.inst_path, exist_ok=True)
        return app

    def _write_metadata(self, app, content):
        with open(os.path.join(app.inst_path,
                               constants.APP_METADATA_FILE), 'w') as f:
            f.write(content)


class GetMetadataValueWarningTestCase(_MetadataHandlingTestCase):
    """_get_metadata_value must warn distinctly for missing vs empty files
    so a metadata problem is never silent.
    """

    def setUp(self):
        super(GetMetadataValueWarningTestCase, self).setUp()
        self.app = self._make_app('meta-warn-app', '1.0-0',
                                  constants.APP_UPLOAD_SUCCESS)

    def test_warns_when_metadata_file_missing(self):
        # No metadata file written.
        with mock.patch.object(kube_app, 'LOG') as m_log:
            value = self.app_operator._get_metadata_value(
                self.app, 'some_key', default='fallback')

        self.assertEqual(value, 'fallback')
        m_log.warning.assert_called_once()
        self.assertIn('not found', m_log.warning.call_args[0][0])

    def test_warns_when_metadata_file_empty(self):
        self._write_metadata(self.app, '')

        with mock.patch.object(kube_app, 'LOG') as m_log:
            value = self.app_operator._get_metadata_value(
                self.app, 'some_key', default='fallback')

        self.assertEqual(value, 'fallback')
        m_log.warning.assert_called_once()
        self.assertIn('is empty', m_log.warning.call_args[0][0])

    def test_no_warning_when_metadata_file_has_content(self):
        self._write_metadata(self.app,
                             yaml.safe_dump({'some_key': 'real_value'}))

        with mock.patch.object(kube_app, 'LOG') as m_log:
            value = self.app_operator._get_metadata_value(
                self.app, 'some_key', default='fallback')

        self.assertEqual(value, 'real_value')
        m_log.warning.assert_not_called()


class UpdateFailureRollbackTestCase(_MetadataHandlingTestCase):
    """A failed application-update recovers (rolls back) by default, but must
    NOT roll back when the target app enables update_failure_no_rollback.

    perform_app_update reads the skip_recovery flag from the target metadata
    that perform_app_upload extracts to disk, so these tests drive the policy
    by writing (or omitting) upgrades.update_failure_no_rollback in the
    uploaded metadata.
    """

    FROM_VERSION = '1.0-0'
    TO_VERSION = '2.0-0'
    # from_app and to_app use distinct names so each can be fetched with a
    # context (a context-attached object is required for status .save()).
    FROM_NAME = 'rollback-app-from'
    TO_NAME = 'rollback-app-to'

    def setUp(self):
        super(UpdateFailureRollbackTestCase, self).setUp()

        # activate-rollback must not itself short-circuit recovery.
        self.useFixture(fixtures.MockPatchObject(
            kube_app.cutils, 'verify_activate_rollback_in_progress',
            return_value=False))

        # Mock the collaborators perform_app_update calls around the apply.
        # load_application_metadata_from_file is mocked out; the skip_recovery
        # flag is read separately by _get_metadata_value from the metadata
        # file written to disk by the mocked upload below.
        for meth in ['_register_app_abort', '_raise_app_alarm',
                     '_suspend_helm_releases', '_cleanup_helm_charts',
                     'app_lifecycle_actions',
                     'load_application_metadata_from_file',
                     '_cleanup_post_update', '_clear_app_alarm',
                     '_deregister_app_abort']:
            self.useFixture(fixtures.MockPatchObject(
                kube_app.AppOperator, meth))
        self.useFixture(fixtures.MockPatchObject(self.helm_operator,
                                                 'plugins'))
        self.useFixture(fixtures.MockPatchObject(self.app_operator, '_utils'))

        self.m_recover = self.useFixture(fixtures.MockPatchObject(
            kube_app.AppOperator, '_perform_app_recover')).mock

    def _install_upload_mock(self, no_rollback):
        """Mock perform_app_upload to write the target metadata to disk.

        This mirrors the real upload/extract: the new version's metadata only
        becomes readable on disk after upload. When no_rollback is True the
        metadata opts out of automatic recovery.
        """
        def _upload(to_rpc_app, tarfile, transitory_state=None):
            to_app = kube_app.AppOperator.Application(to_rpc_app)
            os.makedirs(to_app.inst_path, exist_ok=True)
            upgrades = {'auto_update': False}
            if no_rollback:
                upgrades[
                    constants.APP_METADATA_UPDATE_FAILURE_SKIP_RECOVERY] = True
            meta = {constants.APP_METADATA_UPGRADES: upgrades}
            with open(os.path.join(to_app.inst_path,
                                   constants.APP_METADATA_FILE), 'w') as f:
                yaml.safe_dump(meta, f)
            return to_app
        self.useFixture(fixtures.MockPatchObject(
            kube_app.AppOperator, 'perform_app_upload', side_effect=_upload))

    def _run_update(self, no_rollback):
        self._install_upload_mock(no_rollback)
        dbutils.create_test_app(
            name=self.FROM_NAME, app_version=self.FROM_VERSION,
            status=constants.APP_APPLY_SUCCESS)
        dbutils.create_test_app(
            name=self.TO_NAME, app_version=self.TO_VERSION,
            status=constants.APP_UPDATE_IN_PROGRESS)
        # Fetch with a context so the wrapped Application can persist status.
        from_rpc = obj_app.get_by_name(self.context, self.FROM_NAME)
        to_rpc = obj_app.get_by_name(self.context, self.TO_NAME)
        hook = LifecycleHookInfo()
        self.app_operator.perform_app_update(
            from_rpc, to_rpc, '/tmp/fake.tgz', hook)

    def _to_app_status(self):
        return obj_app.get_by_name(self.context, self.TO_NAME).status

    # ---- default behavior: rollback on failure -------------------------

    def test_recovers_when_apply_returns_false_and_recovery_allowed(self):
        # helm/manifest failure -> perform_app_apply returns False.
        self.useFixture(fixtures.MockPatchObject(
            kube_app.AppOperator, 'perform_app_apply', return_value=False))

        self._run_update(no_rollback=False)

        self.m_recover.assert_called_once()

    def test_recovers_when_apply_raises_and_recovery_allowed(self):
        # image download failure -> perform_app_apply raises.
        self.useFixture(fixtures.MockPatchObject(
            kube_app.AppOperator, 'perform_app_apply',
            side_effect=exception.KubeAppApplyFailure(
                name=self.TO_NAME, version=self.TO_VERSION,
                reason='forced failure')))

        self._run_update(no_rollback=False)

        self.m_recover.assert_called_once()

    # ---- update_failure_no_rollback: no rollback on failure ------------

    def test_no_recover_when_apply_returns_false_and_recovery_skipped(self):
        self.useFixture(fixtures.MockPatchObject(
            kube_app.AppOperator, 'perform_app_apply', return_value=False))

        self._run_update(no_rollback=True)

        self.m_recover.assert_not_called()
        # On the post-apply path the target is left as apply-failed.
        self.assertEqual(self._to_app_status(),
                         constants.APP_APPLY_FAILURE)

    def test_no_recover_when_apply_raises_and_recovery_skipped(self):
        self.useFixture(fixtures.MockPatchObject(
            kube_app.AppOperator, 'perform_app_apply',
            side_effect=exception.KubeAppApplyFailure(
                name=self.TO_NAME, version=self.TO_VERSION,
                reason='forced failure')))

        self._run_update(no_rollback=True)

        self.m_recover.assert_not_called()
