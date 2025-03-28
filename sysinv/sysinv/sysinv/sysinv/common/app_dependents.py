#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# All Rights Reserved.
#
""" Application interdependency support code. """

import logging

from sysinv.common import constants

LOG = logging.getLogger(__name__)


def get_dependent_apps_missing(app_metadata, dbapi, include_apps_action_ignore=False):
    """
    Determine the list of dependent applications that are missing based
    on the provided app metadata.
    Args:
        app_metadata (dict): Metadata of the application which includes
            information about dependent apps.
        include_apps_action_ignore (bool): Flag to include dependent apps
            with action set to ignore. Default is False.
    Returns:
        list: A list of dictionaries representing the dependent
        applications that are missing.
    """

    dependent_apps_list = []
    # Get the list of apps that are already applied
    applied_apps = dbapi.kube_app_get_all_by_status(constants.APP_APPLY_SUCCESS)
    # Mount the list of applied apps in the format (name, version)
    applied_apps_name_version = [(app.name, app.app_version) for app in applied_apps]

    # Get the list of dependent apps from the app metadata
    dependent_apps_metadata_list = app_metadata.get(constants.APP_METADATA_DEPENDENT_APPS, None)

    if dependent_apps_metadata_list:
        for dependent_app in dependent_apps_metadata_list:
            action = dependent_app.get('action', None)
            app_tuple = (dependent_app.get('name', None), dependent_app.get('version', None))
            # If the action is not ignore, include_apps_action_ignore is False and the
            # dependent app is not already applied, add the dependent app to the list
            if (action != constants.APP_METADATA_DEPENDENT_APPS_ACTION_IGNORE or
                    include_apps_action_ignore) and app_tuple not in applied_apps_name_version:
                dependent_apps_list.append(dependent_app)

    return dependent_apps_list


def get_dependent_apps_by_action(dependent_apps_metadata_list, action_type):
    """
    Get the list of dependent apps based on the action type.

    Args:
        dependent_apps_metadata_list (list): List of dependent apps metadata.
        action_type (str): Action type of the dependent apps.

    Returns:
        list: A list of dictionaries with 'name' and 'version' keys,
        representing the dependent applications that match the action type.
    """

    dependent_apps_list = []

    for dependent_app in dependent_apps_metadata_list:
        action = dependent_app.get('action', None)
        # If the action matches the action type, add the dependent app to the list and
        if action == action_type or (
            # If the action type is warn and the action is None, add the dependent
            # app to the list. The default action for dependent apps is warn.
            action_type == constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN and action is None
        ):
            dependent_apps_list.append({
                'name': dependent_app['name'],
                'version': dependent_app['version']
            })

    return dependent_apps_list
