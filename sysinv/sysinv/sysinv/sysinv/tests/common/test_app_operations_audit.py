#
# Copyright (c) 2023-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# All Rights Reserved.
#

import unittest
from unittest.mock import MagicMock
from unittest.mock import patch

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common.app_operations_audit import AppOperationsAudit


class TestAppOperationsAudit(unittest.TestCase):
    def setUp(self):
        # Mock of a real metadata.yaml file
        self.apps_metadata = {
            "platform_managed_apps_list": {
                "oidc-auth-apps": None,
                "cert-manager": None,
                "platform-integ-apps": None,
                "deployment-manager": None,
                "nginx-ingress-controller": None,
                "ipsec-policy-operator": None,
                "rook-ceph": None,
                "dell-storage": None,
                "openbao": None,
                "sriov-fec-operator": None,
                "ptp-notification": None,
                "vault": None,
                "security-profiles-operator": None,
                "kubernetes-power-manager": None,
                "istio": None,
                "kubevirt-app": None,
                "node-feature-discovery": None,
                "metrics-server": None,
                "snmp": None,
            },
            "desired_states": {
                "oidc-auth-apps": "applied",
                "cert-manager": "applied",
                "platform-integ-apps": "applied",
                "ipsec-policy-operator": "uploaded",
                "rook-ceph": "applied",
                "dell-storage": "uploaded",
            },
            "ordered_apps": {
                "class": {
                    "critical": ["cert-manager", "nginx-ingress-controller"],
                    "storage": ["platform-integ-apps", "rook-ceph", "dell-storage"],
                    "discovery": [],
                    "optional": [],
                    "reporting": [],
                },
                "independent_apps": [
                    "deployment-manager",
                    "ipsec-policy-operator",
                    "istio",
                    "kubevirt-app",
                    "metrics-server",
                    "node-feature-discovery",
                    "ptp-notification",
                    "security-profiles-operator",
                    "snmp",
                    "sriov-fec-operator",
                ],
                "dependent_apps": [
                    "oidc-auth-apps",
                    "openbao",
                    "vault",
                    "kubernetes-power-manager",
                ],
            },
        }

        # Create mocks
        self.mock_dbapi = MagicMock()
        self.mock_context = MagicMock()
        self.mock_app_operator = MagicMock()
        self.mock_perform_parallel = MagicMock()
        self.mock_execute_sync = MagicMock()

        # Create the audit instance
        self.audit = AppOperationsAudit(
            dbapi=self.mock_dbapi,
            context=self.mock_context,
            app_operator=self.mock_app_operator,
            apps_metadata=self.apps_metadata,
            perform_automatic_operation_in_parallel_fn=self.mock_perform_parallel,
            execute_automatic_operation_sync=self.mock_execute_sync,
        )

    def _create_app_statuses(self, default_status=constants.APP_APPLY_SUCCESS, **overrides):
        """
        Helper method to create app_statuses dictionary.

        Args:
            default_status: Default status for all apps
            **overrides: Keyword arguments to override specific app statuses.
                        Use underscores instead of hyphens in app names.
                        E.g., cert_manager=constants.APP_NOT_PRESENT

        Returns:
            Dictionary with all 19 apps and their statuses
        """
        # Convert underscore-separated kwargs to hyphen-separated app names
        override_dict = {}
        for key, value in overrides.items():
            app_name = key.replace('_', '-')
            override_dict[app_name] = value

        # Create complete app_statuses with all 27 apps
        app_statuses = {}
        for app_name in self.audit._managed_apps:
            app_statuses[app_name] = override_dict.get(app_name, default_status)

        return app_statuses

    def test_init(self):
        """Test initialization of AppOperationsAudit"""
        self.assertEqual(self.audit._dbapi, self.mock_dbapi)
        self.assertEqual(self.audit._context, self.mock_context)
        self.assertEqual(self.audit._app_operator, self.mock_app_operator)
        self.assertEqual(self.audit._apps_metadata, self.apps_metadata)
        self.assertEqual(len(self.audit._managed_apps), 19)  # 19 managed apps
        self.assertIn("cert-manager", self.audit._managed_apps)
        self.assertIn("oidc-auth-apps", self.audit._managed_apps)

    def test_load_app_status_all_present(self):
        """Test loading app status when all apps are present"""
        mock_app = MagicMock()
        mock_app.status = constants.APP_APPLY_SUCCESS
        self.mock_dbapi.kube_app_get.return_value = mock_app

        result = self.audit._load_app_status()

        self.assertEqual(len(result), len(self.audit._managed_apps))
        for app_name in self.audit._managed_apps:
            self.assertEqual(result[app_name], constants.APP_APPLY_SUCCESS)

    def test_load_app_status_some_missing(self):
        """Test loading app status when some apps are missing"""
        def mock_get_app(app_name):
            if app_name == "cert-manager":
                mock_app = MagicMock()
                mock_app.status = constants.APP_APPLY_SUCCESS
                return mock_app
            else:
                raise exception.KubeAppNotFound(name=app_name)

        self.mock_dbapi.kube_app_get.side_effect = mock_get_app

        result = self.audit._load_app_status()

        self.assertEqual(result["cert-manager"], constants.APP_APPLY_SUCCESS)
        self.assertEqual(result["oidc-auth-apps"], constants.APP_NOT_PRESENT)

    def test_upload_missing_apps_not_present(self):
        """Test uploading apps that are not present"""
        self.audit._app_statuses = self._create_app_statuses(
            cert_manager=constants.APP_NOT_PRESENT,
            platform_integ_apps=constants.APP_NOT_PRESENT,
            ipsec_policy_operator=constants.APP_NOT_PRESENT,
        )

        self.audit.upload_missing_apps()

        # Should upload cert-manager, platform-integ-apps, and ipsec-policy-operator
        # (all have desired states and are not present)
        self.mock_perform_parallel.assert_called_once()
        call_args = self.mock_perform_parallel.call_args[0]
        self.assertEqual(call_args[0], self.mock_context)
        self.assertIn("cert-manager", call_args[1])
        self.assertIn("platform-integ-apps", call_args[1])
        self.assertIn("ipsec-policy-operator", call_args[1])
        self.assertEqual(call_args[2], constants.APP_UPLOAD_OP)

    def test_upload_missing_apps_upload_failure(self):
        """Test uploading apps that failed to upload"""
        self.audit._app_statuses = self._create_app_statuses(
            cert_manager=constants.APP_UPLOAD_FAILURE,
        )

        self.audit.upload_missing_apps()

        self.mock_perform_parallel.assert_called_once()
        call_args = self.mock_perform_parallel.call_args[0]
        self.assertIn("cert-manager", call_args[1])

    def test_upload_missing_apps_no_apps_to_upload(self):
        """Test upload when no apps need uploading"""
        self.audit._app_statuses = self._create_app_statuses()

        self.audit.upload_missing_apps()

        self.mock_perform_parallel.assert_not_called()

    def test_execute_apply_operation(self):
        """Test executing apply operation"""
        self.audit._app_statuses = self._create_app_statuses(
            cert_manager=constants.APP_UPLOAD_SUCCESS,
            oidc_auth_apps=constants.APP_UPLOAD_SUCCESS,
        )
        self.mock_perform_parallel.return_value = (True, None, None)

        apps_list = ["cert-manager", "oidc-auth-apps", "platform-integ-apps"]
        self.audit._execute_apply_reapply_recover_update(
            apps_list,
            constants.APP_APPLY_OP,
            self.mock_perform_parallel
        )

        # Should apply cert-manager and oidc-auth-apps (uploaded and desired state is applied)
        self.mock_perform_parallel.assert_called_once()
        call_args = self.mock_perform_parallel.call_args[0]
        self.assertEqual(call_args[0], self.mock_context)
        self.assertIn("cert-manager", call_args[1])
        self.assertIn("oidc-auth-apps", call_args[1])
        self.assertNotIn("platform-integ-apps", call_args[1])  # Already applied
        self.assertEqual(call_args[2], constants.APP_APPLY_OP)

    def test_execute_reapply_operation(self):
        """Test executing reapply operation"""
        self.audit._app_statuses = self._create_app_statuses()
        self.mock_app_operator.needs_reapply.side_effect = lambda x: x == "cert-manager"
        self.mock_perform_parallel.return_value = (True, None, None)

        apps_list = ["cert-manager", "oidc-auth-apps"]
        self.audit._execute_apply_reapply_recover_update(
            apps_list,
            constants.APP_REAPPLY_OP,
            self.mock_perform_parallel
        )

        # Should only reapply cert-manager (needs_reapply returns True)
        self.mock_perform_parallel.assert_called_once()
        call_args = self.mock_perform_parallel.call_args[0]
        self.assertEqual(call_args[1], ["cert-manager"])
        self.assertEqual(call_args[2], constants.APP_REAPPLY_OP)

    def test_execute_recover_operation(self):
        """Test executing recover operation"""
        self.audit._app_statuses = self._create_app_statuses(
            cert_manager=constants.APP_APPLY_FAILURE,
        )
        self.mock_perform_parallel.return_value = (True, None, None)

        apps_list = ["cert-manager", "oidc-auth-apps"]
        self.audit._execute_apply_reapply_recover_update(
            apps_list,
            constants.APP_RECOVER_OP,
            self.mock_perform_parallel
        )

        # Should only recover cert-manager (has failed status)
        self.mock_perform_parallel.assert_called_once()
        call_args = self.mock_perform_parallel.call_args[0]
        self.assertEqual(call_args[1], ["cert-manager"])
        self.assertEqual(call_args[2], constants.APP_RECOVER_OP)

    def test_execute_update_operation(self):
        """Test executing update operation"""
        self.audit._app_statuses = self._create_app_statuses(
            oidc_auth_apps=constants.APP_UPLOAD_SUCCESS,
        )
        self.mock_perform_parallel.return_value = (True, None, None)

        apps_list = ["cert-manager", "oidc-auth-apps"]
        self.audit._execute_apply_reapply_recover_update(
            apps_list,
            constants.APP_UPDATE_OP,
            self.mock_perform_parallel
        )

        # Should only update cert-manager (status is applied)
        self.mock_perform_parallel.assert_called_once()
        call_args = self.mock_perform_parallel.call_args[0]
        call_kwargs = self.mock_perform_parallel.call_args[1]
        self.assertEqual(call_args[1], ["cert-manager"])
        self.assertEqual(call_args[2], constants.APP_UPDATE_OP)
        self.assertEqual(call_kwargs['async_update'], False)

    @patch('sysinv.common.app_operations_audit.LOG')
    def test_execute_operation_result_none(self, mock_log):
        """Test when operation returns None (skipped)"""
        self.audit._app_statuses = self._create_app_statuses(
            cert_manager=constants.APP_UPLOAD_SUCCESS,
        )
        self.mock_perform_parallel.return_value = (None, None, None)

        self.audit._execute_apply_reapply_recover_update(
            ["cert-manager"],
            constants.APP_APPLY_OP,
            self.mock_perform_parallel
        )

        mock_log.warning.assert_called_once()

    @patch('sysinv.common.app_operations_audit.LOG')
    def test_execute_operation_result_false(self, mock_log):
        """Test when operation returns False (error)"""
        self.audit._app_statuses = self._create_app_statuses(
            cert_manager=constants.APP_UPLOAD_SUCCESS,
        )
        self.mock_perform_parallel.return_value = (False, None, None)

        self.audit._execute_apply_reapply_recover_update(
            ["cert-manager"],
            constants.APP_APPLY_OP,
            self.mock_perform_parallel
        )

        mock_log.error.assert_called_once()

    def test_execute_operation_skip_non_managed_apps(self):
        """Test that non-managed apps are skipped"""
        self.audit._app_statuses = self._create_app_statuses(
            cert_manager=constants.APP_UPLOAD_SUCCESS,
        )
        self.mock_perform_parallel.return_value = (True, None, None)

        apps_list = ["cert-manager", "non-existent-app"]
        self.audit._execute_apply_reapply_recover_update(
            apps_list,
            constants.APP_APPLY_OP,
            self.mock_perform_parallel
        )

        # Should only process cert-manager
        if self.mock_perform_parallel.called:
            call_args = self.mock_perform_parallel.call_args[0]
            self.assertNotIn("non-existent-app", call_args[1])

    @patch.object(AppOperationsAudit, '_execute_apply_reapply_recover_update')
    def test_apply_missing_apps(self, mock_execute):
        """Test apply_missing_apps calls execute with correct parameters"""
        self.audit.apply_missing_apps()

        # Should call for class apps (2 classes with apps), independent apps, and dependent apps
        self.assertEqual(mock_execute.call_count, 4)

        # Verify class apps calls
        calls = mock_execute.call_args_list
        self.assertEqual(calls[0][0][1], constants.APP_APPLY_OP)
        self.assertEqual(calls[0][0][2], self.mock_perform_parallel)

    @patch.object(AppOperationsAudit, '_execute_apply_reapply_recover_update')
    def test_reapply_apps(self, mock_execute):
        """Test reapply_apps calls execute with correct parameters"""
        self.audit.reapply_apps()

        # Should call for class apps (2 classes), independent apps, and dependent apps
        self.assertEqual(mock_execute.call_count, 4)

        calls = mock_execute.call_args_list
        # Check that reapply operation is used
        for call in calls:
            self.assertEqual(call[0][1], constants.APP_REAPPLY_OP)

    @patch.object(AppOperationsAudit, '_execute_apply_reapply_recover_update')
    def test_recover_failed_apps(self, mock_execute):
        """Test recover_failed_apps calls execute with correct parameters"""
        self.audit.recover_failed_apps()

        # Should call for class apps (2 classes), independent apps, and dependent apps
        self.assertEqual(mock_execute.call_count, 4)

        calls = mock_execute.call_args_list
        # Check that recover operation is used
        for call in calls:
            self.assertEqual(call[0][1], constants.APP_RECOVER_OP)

    @patch.object(AppOperationsAudit, '_execute_apply_reapply_recover_update')
    def test_update_apps(self, mock_execute):
        """Test update_apps calls execute with correct parameters"""
        self.audit.update_apps()

        # Should call for class apps (2 classes), independent apps, and dependent apps
        self.assertEqual(mock_execute.call_count, 4)

        calls = mock_execute.call_args_list
        # Check that update operation is used
        for call in calls:
            self.assertEqual(call[0][1], constants.APP_UPDATE_OP)

    @patch.object(AppOperationsAudit, 'update_apps')
    @patch.object(AppOperationsAudit, 'recover_failed_apps')
    @patch.object(AppOperationsAudit, 'reapply_apps')
    @patch.object(AppOperationsAudit, 'apply_missing_apps')
    @patch.object(AppOperationsAudit, 'upload_missing_apps')
    @patch.object(AppOperationsAudit, '_load_app_status')
    def test_trigger_automatic_operations(self, mock_load, mock_upload, mock_apply,
                                          mock_reapply, mock_recover, mock_update):
        """Test trigger_automatic_operations calls all operations in order"""
        mock_load.return_value = {"cert-manager": constants.APP_APPLY_SUCCESS}

        self.audit.trigger_automatic_operations()

        # Verify all methods are called
        mock_load.assert_called_once()
        mock_upload.assert_called_once()
        mock_apply.assert_called_once()
        mock_reapply.assert_called_once()
        mock_recover.assert_called_once()
        mock_update.assert_called_once()

        # Verify _app_statuses is set
        self.assertEqual(self.audit._app_statuses, {"cert-manager": constants.APP_APPLY_SUCCESS})

    def test_apply_missing_apps_with_empty_class_lists(self):
        """Test apply_missing_apps handles empty class lists correctly"""
        # Modify metadata to have empty class lists
        self.audit._ordered_class_apps = {
            "critical": [],
            "storage": ["rook-ceph"],
            "discovery": [],
        }

        with patch.object(self.audit, '_execute_apply_reapply_recover_update') as mock_execute:
            self.audit.apply_missing_apps()

            # Should skip empty lists
            calls = mock_execute.call_args_list
            # Should be called for storage class, independent apps, and dependent apps
            self.assertEqual(len(calls), 3)

    def test_operation_strategy_function_selection(self):
        """Test that correct strategy function is used for each app category"""
        self.audit._app_statuses = self._create_app_statuses(
            cert_manager=constants.APP_UPLOAD_SUCCESS,
        )

        with patch.object(self.audit, '_execute_apply_reapply_recover_update') as mock_execute:
            self.audit.apply_missing_apps()

            calls = mock_execute.call_args_list
            # Check that parallel function is used for class and independent apps
            # and sync function is used for dependent apps
            for call in calls[:-1]:  # All but last (dependent apps)
                self.assertEqual(call[0][2], self.mock_perform_parallel)
            # Last call should use sync function
            self.assertEqual(calls[-1][0][2], self.mock_execute_sync)
