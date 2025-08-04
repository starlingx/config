from collections import defaultdict
from enum import Enum

from oslo_log import log

from sysinv.common import app_metadata
from sysinv.common import constants
from sysinv.common.retrying import retry


LOG = log.getLogger(__name__)


class AppsUpdateStatus(Enum):
    IN_PROGRESS = 'in_progress'
    COMPLETED = 'completed'
    FAILED = 'failed'


class AppUpdateManager:  # noqa: H238
    def __init__(self, db_handler, update_strategy_fn):
        self._db_handler = db_handler
        self._update_strategy_fn = update_strategy_fn
        self._status: AppsUpdateStatus = AppsUpdateStatus.IN_PROGRESS
        self._cyclic_dependencies: list = []
        self.failed_apps: list = []
        self.apps_to_retry: list = []
        self.successfully_updated: list = []
        self.apps_to_update: dict = {
            constants.APP_UPDATE_OP: [],
            constants.APP_UPLOAD_OP: [],
            constants.APP_RECOVER_UPDATE_OP: [],
        }

    @property
    def status(self):
        return {
            'status': self._status.value,
            'updated_apps': self.successfully_updated,
            'failed_apps': self.failed_apps
        }

    def _get_apps_update_order(self):
        """
            Builds the list of applications to be updated, uploaded, or recovered, organized by
            update priority and current status. The update order is determined based on metadata
            defined in the application manifest, which categorizes applications into the following
            groups (in order of update priority):
                - critical
                - storage + independent_apps
                - discovery
                - optional
                - reporting
                - dependent_apps
            Each application is matched against its current status in the system (successfully
            applied, failed, or uploaded) to determine whether it should be updated, uploaded, or
            recovered. Populates self.apps_to_update as a dictionary with the structure:
                {
                    APP_UPDATE_OP: [ {'class_type': str, 'apps': List[str]}, ... ],
                    APP_UPLOAD_OP: List[str],
                    APP_RECOVER_UPDATE_OP: List[str]
                }.
        """
        # Clear previous state for apps to update
        self.apps_to_update = {
            constants.APP_UPDATE_OP: [],
            constants.APP_UPLOAD_OP: [],
            constants.APP_RECOVER_UPDATE_OP: [],
        }

        apps_metadata = app_metadata.get_reorder_apps()

        if apps_metadata.get(constants.APP_METADATA_CYCLIC_DEPENDENCIES):
            self._cyclic_dependencies = apps_metadata.get(
                constants.APP_METADATA_CYCLIC_DEPENDENCIES
            )

        class_apps = apps_metadata.get('class', {})

        ordered_apps_metadata = {
            'critical': class_apps.get('critical', []),
            'storage_and_independent_apps': (
                class_apps.get('storage', []) + apps_metadata.get('independent_apps', [])
            ),
            'discovery': class_apps.get('discovery', []),
            'optional': class_apps.get('optional', []),
            'reporting': class_apps.get('reporting', []),
            'dependent_apps': apps_metadata.get('dependent_apps', []),
            'unmanaged_apps': apps_metadata.get('unmanaged_apps', set()),
        }

        status_to_category = {
            constants.APP_APPLY_SUCCESS: 'apps_to_update',
            constants.APP_APPLY_FAILURE: 'apps_to_recover',
            constants.APP_UPLOAD_SUCCESS: 'apps_to_upload',
            constants.APP_UPLOAD_FAILURE: 'apps_to_upload',
        }

        app_status_map = defaultdict(set)

        for app in self._db_handler.kube_app_get_all():
            category = status_to_category.get(app.status)
            if category:
                app_status_map[category].add(app.name)

        for class_type, apps in ordered_apps_metadata.items():
            update_apps = [
                app for app in apps if app in app_status_map['apps_to_update']
            ]
            if update_apps:
                self.apps_to_update[constants.APP_UPDATE_OP].append(
                    {'class_type': class_type, 'apps': update_apps}
                )

            upload_apps = [
                app for app in apps if app in app_status_map['apps_to_upload']
            ]
            if upload_apps:
                self.apps_to_update[constants.APP_UPLOAD_OP] += upload_apps

            recover_apps = [
                app for app in apps if app in app_status_map['apps_to_recover']
            ]
            if recover_apps:
                self.apps_to_update[constants.APP_RECOVER_UPDATE_OP] += recover_apps

    @retry(retry_on_result=lambda x: x is False, stop_max_attempt_number=2, wait_fixed=15 * 1000)
    def _update_a_list_of_apps(self, context, apps_list, operation, **kwargs):
        """
            Attempts to perform a specified operation on a list of applications in parallel,
            retrying once if any updates fail.
            Uses `self._update_strategy_fn` to execute the operation asynchronously.
            If some apps fail to update, retries updating only those failed apps once more after a
            fixed wait period.
            :param context: request context.
            :param apps_list (list): list of app names to update.
            :param operation (str): operation to perform on the apps.
            :param **kwargs: additional arguments passed to the operation.
            :return (bool): True if all apps updated successfully, False if any failed after
                            retries.
        """
        apps_to_update = apps_list
        if self.apps_to_retry:
            apps_to_update = self.apps_to_retry

        _, failed_updated_apps = self._update_strategy_fn(
            context,
            apps_to_update,
            operation,
            **kwargs
        )

        if failed_updated_apps and self.apps_to_retry:
            LOG.warning(
                f"The following apps did not update successfully: {', '.join(failed_updated_apps)}."
            )
            self.successfully_updated += list(set(self.apps_to_retry) - set(failed_updated_apps))
            self.failed_apps = failed_updated_apps
            return False
        elif failed_updated_apps:
            LOG.warning(
                f"The following apps did not update successfully: {', '.join(failed_updated_apps)}."
                " The system will try to update these apps one more time."
            )
            self.successfully_updated += list(set(apps_to_update) - set(failed_updated_apps))
            self.apps_to_retry = failed_updated_apps
            return False

        self.successfully_updated += apps_to_update
        return True

    def update_apps(self, context):
        """
            Executes the full application update process based on their current status:
                - Uploading apps that are marked as uploaded
                - Retrying apps that previously failed to apply
                - Updating apps that are already applied
            The update order is determined by `_get_apps_update_order`, and each group is updated
            using `_update_a_list_of_apps`.
            The overall update status is stored in `self._status`.
            :param context: Context of the request.
        """
        try:
            self._get_apps_update_order()

            if self._cyclic_dependencies:
                LOG.error(
                    f"The following apps won't be updated due to cyclic dependencies: \
                    {', '.join(self._cyclic_dependencies)}."
                )

            LOG.info("Starting the update of apps with uploaded status.")
            self._update_a_list_of_apps(
                context,
                self.apps_to_update[constants.APP_UPLOAD_OP],
                constants.APP_UPLOAD_OP,
                async_upload=False,
                skip_validations=True
            )

            LOG.info("Starting the attempt to update apps with apply-failed status.")
            self._update_a_list_of_apps(
                context,
                self.apps_to_update[constants.APP_RECOVER_UPDATE_OP],
                constants.APP_RECOVER_UPDATE_OP
            )

            LOG.info("Starting the update of apps with applied status.")
            for class_type in self.apps_to_update[constants.APP_UPDATE_OP]:
                if class_type == 'unmanaged_apps':
                    LOG.info("Starting the update of unmanaged apps with applied status.")
                self._update_a_list_of_apps(
                    context,
                    class_type['apps'],
                    constants.APP_UPDATE_OP,
                    async_update=False,
                    skip_validations=True,
                    ignore_locks=True
                )
            self._status = AppsUpdateStatus.COMPLETED
        except Exception as e:
            self._status = AppsUpdateStatus.FAILED
            LOG.error(e)

    def rollback_apps(self, context):
        """
            Executes the rollback process for applications based on their current statuses:
                - Rolling back apps with 'uploaded' status
                - Attempting rollback on apps with 'apply-failed' status
                - Rolling back apps with 'applied' status
            The rollback order is determined by `_get_apps_update_order_to_rollback_op`,
            and each group is processed using `_update_a_list_of_apps`.
            The overall rollback status is stored in `self._status`.
        :param context: The request context.
        """

        try:
            self._get_apps_update_order_to_rollback_op()

            if self._cyclic_dependencies:
                LOG.error(
                    f"The following apps won't be reverted due to cyclic dependencies: \
                    {', '.join(self._cyclic_dependencies)}."
                )

            LOG.info("Starting to rollback apps in uploaded status.")
            self._update_a_list_of_apps(
                context,
                self.apps_to_update[constants.APP_UPLOAD_OP],
                constants.APP_UPLOAD_OP,
                async_upload=False,
                skip_validations=True
            )

            LOG.info("Attempting to rollback apps in apply-failed status.")
            self._update_a_list_of_apps(
                context,
                self.apps_to_update[constants.APP_RECOVER_UPDATE_OP],
                constants.APP_RECOVER_UPDATE_OP
            )

            LOG.info("Starting to rollback apps in applied status.")
            self._update_a_list_of_apps(
                context,
                self.apps_to_update[constants.APP_UPDATE_OP],
                constants.APP_UPDATE_OP,
                async_update=False,
                skip_validations=True,
            )
            self._status = AppsUpdateStatus.COMPLETED
        except Exception as e:
            self._status = AppsUpdateStatus.FAILED
            LOG.error(e)

    def _get_apps_update_order_to_rollback_op(self):
        """
            Determines the rollback operation order for applications based on their current status.
            Maps application statuses to corresponding rollback operations:
                - Successful apply maps to update operation
                - Failed apply maps to recover update operation
                - Successful upload maps to upload operation
                - Failed upload maps to upload operation
            Populates `self.apps_to_update` with app names grouped by their rollback operation.
            This method retrieves all apps from the database and categorizes them accordingly.
        """
        # TODO(edias): This function will no longer be necessary in future releases and should be
        # deleted. Future releases will use the new inter-app dependency feature, which will allow
        # rollback operations to use the _get_apps_update_order method instead.

        # Clear previous state for apps to update
        self.apps_to_update = {
            constants.APP_UPDATE_OP: [],
            constants.APP_UPLOAD_OP: [],
            constants.APP_RECOVER_UPDATE_OP: [],
        }

        # Get the ordered list of apps for rollback
        ordered_apps = app_metadata.get_reorder_apps(is_platform_rollback=True)
        # Get all apps from the database
        db_apps = self._db_handler.kube_app_get_all()

        # Create a list to hold ordered database apps
        ordered_db_apps = []
        # Add db apps in the order specified by ordered_apps
        for app_name in ordered_apps:
            for db_app in db_apps:
                if db_app.name == app_name:
                    ordered_db_apps.append(db_app)
                    break
        # Add unmanaged apps (not in ordered_apps) at the end
        for db_app in db_apps:
            if db_app.name not in ordered_apps:
                ordered_db_apps.append(db_app)

        # Map statuses to operations
        status_to_operation = {
            constants.APP_APPLY_SUCCESS: constants.APP_UPDATE_OP,
            constants.APP_APPLY_FAILURE: constants.APP_RECOVER_UPDATE_OP,
            constants.APP_UPLOAD_SUCCESS: constants.APP_UPLOAD_OP,
            constants.APP_UPLOAD_FAILURE: constants.APP_UPLOAD_OP,
        }

        # Populate apps_to_update with ordered apps and their corresponding operations
        for db_app in ordered_db_apps:
            operation = status_to_operation.get(db_app.status)
            if operation:
                self.apps_to_update[operation].append(db_app.name)
