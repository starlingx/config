import unittest
from types import SimpleNamespace
from unittest import mock
from sysinv.common import app_update_manager
from sysinv.common import constants
from sysinv.common.retrying import RetryError


class TestAppUpdateManager(unittest.TestCase):

    def setUp(self):
        self.mock_db_handler = mock.Mock()
        self.mock_update_strategy_fn = mock.Mock(return_value=(None, []))
        self.manager = app_update_manager.AppUpdateManager(
            self.mock_db_handler, self.mock_update_strategy_fn
        )
        self.context = mock.Mock()

    # Tests for _get_apps_update_order method
    def test_get_apps_update_order_classification(self):
        # Mock app_metadata.get_reorder_apps
        mock_metadata = {
            'class': {
                'critical': ['app_critical'],
                'storage': ['app_storage'],
                'discovery': ['app_discovery'],
                'optional': ['app_optional'],
                'reporting': ['app_reporting'],
            },
            'independent_apps': ['app_independent'],
            'dependent_apps': ['app_dependent']
        }
        with mock.patch('sysinv.common.app_metadata.get_reorder_apps', return_value=mock_metadata):
            # Mock kube_app_get_all to return apps with different statuses
            self.mock_db_handler.kube_app_get_all.return_value = [
                SimpleNamespace(name='app_critical', status=constants.APP_APPLY_SUCCESS),
                SimpleNamespace(name='app_storage', status=constants.APP_UPLOAD_SUCCESS),
                SimpleNamespace(name='app_independent', status=constants.APP_APPLY_FAILURE),
                SimpleNamespace(name='app_discovery', status=constants.APP_APPLY_SUCCESS),
                SimpleNamespace(name='app_optional', status=constants.APP_UPLOAD_FAILURE),
                SimpleNamespace(name='app_reporting', status=constants.APP_APPLY_FAILURE),
                SimpleNamespace(name='app_dependent', status=constants.APP_APPLY_SUCCESS),
            ]

            self.manager._get_apps_update_order()

            # Check apps_to_update
            update_ops = self.manager.apps_to_update[constants.APP_UPDATE_OP]
            upload_ops = self.manager.apps_to_update[constants.APP_UPLOAD_OP]
            recover_ops = self.manager.apps_to_update[constants.APP_RECOVER_UPDATE_OP]

            self.assertIn({'class_type': 'critical', 'apps': ['app_critical']}, update_ops)
            self.assertIn({'class_type': 'discovery', 'apps': ['app_discovery']}, update_ops)
            self.assertIn({'class_type': 'dependent_apps', 'apps': ['app_dependent']}, update_ops)
            self.assertIn('app_storage', upload_ops)
            self.assertIn('app_optional', upload_ops)
            self.assertIn('app_independent', recover_ops)
            self.assertIn('app_reporting', recover_ops)

    def test_get_apps_update_order_empty_metadata_and_apps(self):
        with mock.patch(
            "sysinv.common.app_metadata.get_reorder_apps",
            return_value={"class": {}, "independent_apps": [], "dependent_apps": []},
        ):
            self.mock_db_handler.kube_app_get_all.return_value = []
            self.manager._get_apps_update_order()
            self.assertEqual(self.manager.apps_to_update[constants.APP_UPDATE_OP], [])
            self.assertEqual(self.manager.apps_to_update[constants.APP_UPLOAD_OP], [])
            self.assertEqual(
                self.manager.apps_to_update[constants.APP_RECOVER_UPDATE_OP], []
            )

    def test_get_apps_update_order_malformed_metadata(self):
        # Test with malformed metadata structure
        mock_metadata = {
            'class': {
                'critical': ['app_critical'],
                'storage': ['app_storage'],
            },
            'independent_apps': ['app_independent'],
            'dependent_apps': ['app_dependent']
        }
        with mock.patch('sysinv.common.app_metadata.get_reorder_apps', return_value=mock_metadata):
            # Malform the metadata by making 'class' an invalid type
            with mock.patch.object(
                app_update_manager, "app_metadata", new_callable=mock.PropertyMock
            ) as mock_app_metadata:
                mock_app_metadata.return_value = {'class': 'invalid_type'}
                with self.assertRaises((TypeError, AttributeError, KeyError)):
                    self.manager._get_apps_update_order()

    def test_get_apps_update_order_no_apps_in_db(self):
        # Test when no apps exist in the database
        mock_metadata = {
            'class': {
                'critical': ['app_critical'],
                'storage': ['app_storage'],
            },
            'independent_apps': ['app_independent'],
            'dependent_apps': ['app_dependent']
        }
        with mock.patch('sysinv.common.app_metadata.get_reorder_apps', return_value=mock_metadata):
            self.mock_db_handler.kube_app_get_all.return_value = []  # No apps in database
            self.manager._get_apps_update_order()

            # Should be no operations since no apps exist
            self.assertEqual(self.manager.apps_to_update[constants.APP_UPDATE_OP], [])
            self.assertEqual(self.manager.apps_to_update[constants.APP_UPLOAD_OP], [])
            self.assertEqual(
                self.manager.apps_to_update[constants.APP_RECOVER_UPDATE_OP], []
            )

    def test_get_apps_update_order_apps_in_metadata_but_not_in_db(self):
        # Test when metadata references apps that don't exist in the database
        mock_metadata = {
            'class': {
                'critical': ['app_missing1', 'app_missing2'],
                'storage': ['app_missing3'],
            },
            'independent_apps': ['app_missing4'],
            'dependent_apps': ['app_missing5']
        }
        with mock.patch('sysinv.common.app_metadata.get_reorder_apps', return_value=mock_metadata):
            self.mock_db_handler.kube_app_get_all.return_value = [
                SimpleNamespace(name='app_existing', status=constants.APP_APPLY_SUCCESS),
            ]
            self.manager._get_apps_update_order()

            # No classified operations since metadata apps don't exist in DB
            self.assertEqual(self.manager.apps_to_update[constants.APP_UPDATE_OP], [])
            self.assertEqual(self.manager.apps_to_update[constants.APP_UPLOAD_OP], [])
            self.assertEqual(self.manager.apps_to_update[constants.APP_RECOVER_UPDATE_OP], [])

    def test_get_apps_update_order_status_preservation_across_calls(self):
        # Test that calling _get_apps_update_order multiple times doesn't accumulate results
        mock_metadata = {
            'class': {
                'critical': ['app_critical'],
            },
            'independent_apps': [],
            'dependent_apps': []
        }
        with mock.patch('sysinv.common.app_metadata.get_reorder_apps', return_value=mock_metadata):
            self.mock_db_handler.kube_app_get_all.return_value = [
                SimpleNamespace(name='app_critical', status=constants.APP_APPLY_SUCCESS),
            ]
            # First call - should populate apps_to_update
            self.manager._get_apps_update_order()
            first_result = self.manager.apps_to_update[constants.APP_UPDATE_OP]

            # Second call - should not accumulate
            self.manager._get_apps_update_order()
            second_result = self.manager.apps_to_update[constants.APP_UPDATE_OP]

            # Results should be identical, not accumulated
            self.assertEqual(len(first_result), 1)
            self.assertEqual(len(second_result), 1)  # Should be same length, not accumulated
            self.assertEqual(first_result, second_result)

    def test_get_apps_update_order_mixed_valid_invalid_statuses(self):
        # Test when some apps have valid statuses and others have invalid ones
        mock_metadata = {
            'class': {
                'critical': ['app_valid', 'app_invalid'],
                'storage': ['app_valid2'],
            },
            'independent_apps': ['app_invalid2'],
            'dependent_apps': []
        }
        with mock.patch('sysinv.common.app_metadata.get_reorder_apps', return_value=mock_metadata):
            self.mock_db_handler.kube_app_get_all.return_value = [
                SimpleNamespace(name='app_valid', status=constants.APP_APPLY_SUCCESS),
                SimpleNamespace(name='app_invalid', status=constants.APP_REMOVE_IN_PROGRESS),
                SimpleNamespace(name='app_valid2', status=constants.APP_UPLOAD_SUCCESS),
                SimpleNamespace(name='app_invalid2', status=constants.APP_UPDATE_IN_PROGRESS),
            ]
            self.manager._get_apps_update_order()

            # Only apps with valid statuses should be classified
            update_ops = self.manager.apps_to_update[constants.APP_UPDATE_OP]
            upload_ops = self.manager.apps_to_update[constants.APP_UPLOAD_OP]

            self.assertIn({'class_type': 'critical', 'apps': ['app_valid']}, update_ops)
            self.assertIn('app_valid2', upload_ops)

            # Apps with invalid statuses should not appear anywhere
            all_classified_apps = set()
            for entry in update_ops:
                all_classified_apps.update(entry['apps'])
            all_classified_apps.update(upload_ops)
            all_classified_apps.update(
                self.manager.apps_to_update[constants.APP_RECOVER_UPDATE_OP]
            )

            self.assertNotIn('app_invalid', all_classified_apps)
            self.assertNotIn('app_invalid2', all_classified_apps)

    # Tests for _update_a_list_of_apps
    def test_update_a_list_of_apps_all_success(self):
        # All apps succeed, no retry
        self.manager.apps_to_retry = []
        self.mock_update_strategy_fn.return_value = (None, [])
        result = self.manager._update_a_list_of_apps(
            self.context, ['app1', 'app2'], constants.APP_UPDATE_OP
        )
        self.assertTrue(result)
        self.assertIn('app1', self.manager.successfully_updated)
        self.assertIn('app2', self.manager.successfully_updated)
        self.assertEqual(self.manager.failed_apps, [])

    def test_update_a_list_of_apps_fail_on_retry_raises_retryerror(self):
        # First call: some apps fail, triggers retry
        # Second call: still fails, should raise RetryError due to retry decorator
        self.manager.apps_to_retry = []
        self.mock_update_strategy_fn.side_effect = [
            (None, ['app2']),
            (None, ['app2'])
        ]
        with mock.patch('sysinv.common.app_update_manager.LOG') as mock_log:
            with self.assertRaises(RetryError):
                self.manager._update_a_list_of_apps(
                    self.context, ['app1', 'app2'], constants.APP_UPDATE_OP
                )
            # After failure, app2 should be in failed_apps
            self.assertEqual(self.manager.failed_apps, ['app2'])
            mock_log.warning.assert_called_with(
                "The following apps did not update successfully: app2."
            )

    def test_update_a_list_of_apps_partial_success_on_retry(self):
        # First call: app2 fails, triggers retry
        # Second call: app2 succeeds
        self.manager.apps_to_retry = []
        self.mock_update_strategy_fn.side_effect = [
            (None, ['app2']),
            (None, [])
        ]
        with mock.patch('sysinv.common.app_update_manager.LOG') as mock_log:
            result = self.manager._update_a_list_of_apps(
                self.context, ['app1', 'app2'], constants.APP_UPDATE_OP
            )
            self.assertTrue(result)
            self.assertIn('app1', self.manager.successfully_updated)
            self.assertIn('app2', self.manager.successfully_updated)
            self.assertEqual(self.manager.failed_apps, [])
            mock_log.warning.assert_called_with(
                "The following apps did not update successfully: app2. "
                "The system will try to update these apps one more time."
            )

    def test_update_a_list_of_apps_no_apps_to_update(self):
        # No apps to update, should succeed
        self.manager.apps_to_retry = []
        self.mock_update_strategy_fn.return_value = (None, [])
        result = self.manager._update_a_list_of_apps(
            self.context, [], constants.APP_UPDATE_OP
        )
        self.assertTrue(result)
        self.assertEqual(self.manager.successfully_updated, [])
        self.assertEqual(self.manager.failed_apps, [])

    def test_update_a_list_of_apps_all_fail(self):
        # All apps fail, should retry and then fail
        self.manager.apps_to_retry = []
        self.mock_update_strategy_fn.side_effect = [
            (None, ['app1', 'app2']),
            (None, ['app1', 'app2'])
        ]
        with mock.patch('sysinv.common.app_update_manager.LOG') as mock_log:
            with self.assertRaises(RetryError):
                self.manager._update_a_list_of_apps(
                    self.context, ['app1', 'app2'], constants.APP_UPDATE_OP
                )
            self.assertEqual(self.manager.failed_apps, ['app1', 'app2'])
            mock_log.warning.assert_called_with(
                "The following apps did not update successfully: app1, app2."
            )

    def test_update_a_list_of_apps_with_empty_list(self):
        self.manager.apps_to_retry = []
        self.mock_update_strategy_fn.return_value = (None, [])
        result = self.manager._update_a_list_of_apps(
            self.context, [], constants.APP_UPDATE_OP
        )
        self.assertTrue(result)
        self.assertEqual(self.manager.successfully_updated, [])
        self.assertEqual(self.manager.failed_apps, [])

    # Tests for update_apps method
    def test_update_apps_successful_flow(self):
        with (
            mock.patch.object(self.manager, "_get_apps_update_order") as mock_get_order,
            mock.patch.object(
                self.manager, "_update_a_list_of_apps", return_value=True
            ) as mock_update_list,
        ):

            self.manager.apps_to_update = {
                constants.APP_UPLOAD_OP: ['app_upload'],
                constants.APP_RECOVER_UPDATE_OP: ['app_recover'],
                constants.APP_UPDATE_OP: [{'class_type': 'critical', 'apps': ['app_update']}]
            }

            self.manager.update_apps(self.context)

            mock_get_order.assert_called_once()
            expected_calls = [
                mock.call(
                    self.context,
                    ['app_upload'],
                    constants.APP_UPLOAD_OP,
                    async_upload=False,
                    skip_validations=True
                ),
                mock.call(
                    self.context,
                    ['app_recover'],
                    constants.APP_RECOVER_UPDATE_OP
                ),
                mock.call(
                    self.context,
                    ['app_update'],
                    constants.APP_UPDATE_OP,
                    async_update=False,
                    skip_validations=True,
                    ignore_locks=True
                )
            ]
            mock_update_list.assert_has_calls(expected_calls, any_order=False)
            self.assertEqual(self.manager._status.value, 'completed')

    def test_update_apps_sets_failed_status_on_exception(self):
        with (
            mock.patch.object(
                self.manager, "_get_apps_update_order", side_effect=Exception("fail")
            ),
            mock.patch("sysinv.common.app_update_manager.LOG") as mock_log,
        ):
            self.manager.update_apps(self.context)
            self.assertEqual(self.manager._status.value, "failed")
            mock_log.error.assert_called()
