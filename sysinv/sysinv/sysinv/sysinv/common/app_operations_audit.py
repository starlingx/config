#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# All Rights Reserved.
#

from oslo_log import log

from sysinv.common import constants
from sysinv.common import exception

LOG = log.getLogger(__name__)


class AppOperationsAudit():  # noqa: H238
    def __init__(
        self,
        dbapi,
        context,
        app_operator,
        apps_metadata,
        perform_automatic_operation_in_parallel_fn,
        execute_automatic_operation_sync,
    ):
        self._dbapi = dbapi
        self._context = context
        self._app_operator = app_operator
        self._apps_metadata = apps_metadata
        self._managed_apps = list(apps_metadata.get(
            constants.APP_METADATA_PLATFORM_MANAGED_APPS, {}).keys())
        self._ordered_class_apps = apps_metadata[constants.APP_METADATA_ORDERED_APPS].get(
            constants.APP_METADATA_CLASS, {})
        self._ordered_independent_apps = apps_metadata[constants.APP_METADATA_ORDERED_APPS].get(
            constants.APP_METADATA_INDEPENDENT_APPS, {})
        self._ordered_dependent_apps = apps_metadata[constants.APP_METADATA_ORDERED_APPS].get(
            constants.APP_METADATA_DEPENDENT_APPS, {})
        self._perform_automatic_operation_in_parallel_fn = \
            perform_automatic_operation_in_parallel_fn
        self._execute_automatic_operation_sync = execute_automatic_operation_sync
        self._app_statuses = {}

    def _load_app_status(self):
        """
        Load the status of all managed applications.

        Iterates through the list of managed applications, retrieves their current status from the
        database, and returns a dictionary mapping each application name to its status. If an
        application is not found in the database, its status is set to APP_NOT_PRESENT.

        Returns:
            dict: A dictionary where keys are application names and values are their statuses.
        """

        app_statuses = {}
        for app_name in self._managed_apps:
            try:
                app = self._dbapi.kube_app_get(app_name)
                app_statuses[app_name] = app.status
            except exception.KubeAppNotFound:
                app_statuses[app_name] = constants.APP_NOT_PRESENT
        return app_statuses

    def upload_missing_apps(self):
        """
        Automatically uploads platform-managed applications that are missing or failed to upload,
        but are desired to be present or applied according to the application's metadata.
        """
        app_to_upload_list = []

        for app_name in self._managed_apps:
            # Handle initial loading states
            if self._app_statuses[app_name] in [
                constants.APP_NOT_PRESENT,
                constants.APP_UPLOAD_FAILURE,
            ]:
                if app_name in self._apps_metadata[
                    constants.APP_METADATA_DESIRED_STATES
                ].keys() and self._apps_metadata[
                    constants.APP_METADATA_DESIRED_STATES
                ].get(app_name, None) in [
                    constants.APP_UPLOAD_SUCCESS,
                    constants.APP_APPLY_SUCCESS,
                ]:
                    app_to_upload_list.append(app_name)

        if not app_to_upload_list:
            return

        LOG.info(f"Starting auto uploading missing platform managed apps: {app_to_upload_list}")
        self._perform_automatic_operation_in_parallel_fn(
            self._context,
            app_to_upload_list,
            constants.APP_UPLOAD_OP,
        )

    def _execute_apply_reapply_recover_update(self, apps_list, op, op_strategy_fn):
        """
        Executes the apply, reapply, or recover operation for a list of
        platform-managed applications.

        This method filters the provided list of application names based on their management status
        and current state, then applies the specified operation (apply, reapply, recover or update)
        using the provided strategy function.

        Args:
            apps_list (list): List of application names to process.
            op (str): The operation to perform. Expected values are constants.APP_APPLY_OP,
                      constants.APP_REAPPLY_OP, or constants.APP_RECOVER_OP.
            op_strategy_fn (callable): A function to execute the operation strategy.
        """
        apps_to_operation_list = []

        for app_name in apps_list:
            if app_name not in self._managed_apps:
                continue

            status = self._app_statuses[app_name]
            LOG.debug("Platform managed application %s: %s" % (app_name, status))

            if op == constants.APP_APPLY_OP:
                if status == constants.APP_UPLOAD_SUCCESS:
                    if (
                        app_name in self._managed_apps
                        and self._apps_metadata[
                            constants.APP_METADATA_DESIRED_STATES
                        ].get(app_name, None) == constants.APP_APPLY_SUCCESS
                    ):
                        apps_to_operation_list.append(app_name)
            elif op == constants.APP_REAPPLY_OP:
                if status == constants.APP_APPLY_SUCCESS and \
                        self._app_operator.needs_reapply(app_name):
                    apps_to_operation_list.append(app_name)
            elif op == constants.APP_RECOVER_OP:
                if status in constants.APP_APPLY_FAILURE:
                    apps_to_operation_list.append(app_name)
            elif op == constants.APP_UPDATE_OP and status in constants.APP_APPLY_SUCCESS:
                apps_to_operation_list.append(app_name)

        if not apps_to_operation_list:
            return

        LOG.info(f"Starting auto {op} for platform managed apps: {apps_to_operation_list}")
        result = None

        if op == constants.APP_UPDATE_OP:
            result, _, _ = op_strategy_fn(
                self._context,
                apps_to_operation_list,
                op,
                async_update=False
            )
        elif op == constants.APP_RECOVER_OP:
            result, _, _ = op_strategy_fn(
                self._context,
                apps_to_operation_list,
                op,
                async_recover=False
            )
        else:
            result, _, _ = op_strategy_fn(
                self._context,
                apps_to_operation_list,
                op,
                async_apply=False
            )
        if result is None:
            LOG.warning(
                f"Auto-{op} skipped for one or more apps"
            )
        elif result is False:
            LOG.error(f"Error while auto {op}ing one or more apps")

    def apply_missing_apps(self):
        """
        Applies missing applications in the system by category.
        This method performs the following operations:
            1. Applies missing class applications in parallel (waiting for each class to complete).
            2. Applies missing independent applications in parallel (waiting for all to complete).
            3. Applies missing dependent applications sequentially.
        The method uses internal helper functions to execute the apply, reapply, or recover
        operations for each category of applications, ensuring that class and independent
        applications are handled concurrently, while dependent applications are processed
        in sequence to respect their dependencies.
        """
        # Apply in parallel missing class apps
        for class_apps in self._ordered_class_apps.values():
            if class_apps:
                self._execute_apply_reapply_recover_update(
                    class_apps,
                    constants.APP_APPLY_OP,
                    self._perform_automatic_operation_in_parallel_fn,
                )

        # Apply in parallel missing independent apps
        self._execute_apply_reapply_recover_update(
            self._ordered_independent_apps,
            constants.APP_APPLY_OP,
            self._perform_automatic_operation_in_parallel_fn,
        )

        # Apply sequentially missing dependent apps
        self._execute_apply_reapply_recover_update(
            self._ordered_dependent_apps,
            constants.APP_APPLY_OP,
            self._execute_automatic_operation_sync,
        )

    def reapply_apps(self):
        """
        Re-applies applications in the system according to their dependency order.

        This method performs the following steps:
        1. Re-applies applications grouped by class in parallel (waiting for each class to complete)
        2. Re-applies independent applications in parallel (waiting for all to complete).
        3. Re-applies dependent applications sequentially.
        """
        # Re-apply in parallel class apps
        for class_apps in self._ordered_class_apps.values():
            if class_apps:
                self._execute_apply_reapply_recover_update(
                    class_apps,
                    constants.APP_REAPPLY_OP,
                    self._perform_automatic_operation_in_parallel_fn,
                )

        # Re-apply in parallel dependent apps
        self._execute_apply_reapply_recover_update(
            self._ordered_independent_apps,
            constants.APP_REAPPLY_OP,
            self._perform_automatic_operation_in_parallel_fn,
        )

        # Re-apply sequentially dependent apps
        self._execute_apply_reapply_recover_update(
            self._ordered_dependent_apps,
            constants.APP_REAPPLY_OP,
            self._execute_automatic_operation_sync,
        )

    def recover_failed_apps(self):
        """
        Attempt to recover all failed applications by executing the recovery operation
        for each category of apps in a specific order:

        1. Recover class-based applications in parallel (waiting for each class to complete).
        2. Recover independent applications in parallel (waiting for all to complete).
        3. Recover dependent applications synchronously.
        """
        # Recover class apps
        for class_apps in self._ordered_class_apps.values():
            if class_apps:
                self._execute_apply_reapply_recover_update(
                    class_apps,
                    constants.APP_RECOVER_OP,
                    self._perform_automatic_operation_in_parallel_fn,
                )

        # Recover independent apps
        self._execute_apply_reapply_recover_update(
            self._ordered_independent_apps,
            constants.APP_RECOVER_OP,
            self._perform_automatic_operation_in_parallel_fn,
        )

        # Recover dependent apps
        self._execute_apply_reapply_recover_update(
            self._ordered_dependent_apps,
            constants.APP_RECOVER_OP,
            self._execute_automatic_operation_sync,
        )

    def update_apps(self):
        """
        Attempt to update all applications by executing the update operation
        for each category of apps in a specific order:

        1. Update class-based applications in parallel (waiting for each class to complete).
        2. Update independent applications in parallel (waiting for all to complete).
        3. Update dependent applications synchronously.
        """

        # Update in parallel missing class apps
        for class_apps in self._ordered_class_apps.values():
            if class_apps:
                self._execute_apply_reapply_recover_update(
                    class_apps,
                    constants.APP_UPDATE_OP,
                    self._perform_automatic_operation_in_parallel_fn,
                )

        # Update in parallel missing independent apps
        self._execute_apply_reapply_recover_update(
            self._ordered_independent_apps,
            constants.APP_UPDATE_OP,
            self._perform_automatic_operation_in_parallel_fn,
        )

        # Update sequentially missing dependent apps
        self._execute_apply_reapply_recover_update(
            self._ordered_dependent_apps,
            constants.APP_UPDATE_OP,
            self._execute_automatic_operation_sync,
        )

    def trigger_automatic_operations(self):
        """
        Performs a sequence of automatic operations related to platform application management.
        This method initiates an audit of automatic operations by:
            - Updade cache of application statuses.
            - Uploading any missing applications.
            - Applying applications with desire state "applied" that have not yet been applied.
            - Reapplying applications as needed.
            - Recovering applications that have failed to apply.
            - Performing updates on all applications if have tarballs with a superior version
              available that are compatible with the k8s version of the platform.
        """
        # Populate the app statuses
        self._app_statuses = self._load_app_status()
        # Perform all automatic operations
        self.upload_missing_apps()
        self.apply_missing_apps()
        self.reapply_apps()
        self.recover_failed_apps()
        self.update_apps()
