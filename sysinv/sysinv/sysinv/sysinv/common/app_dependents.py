#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# All Rights Reserved.
#
""" Application interdependency support code. """

import re

from sysinv.common import constants


def match_dependency(app_list, app_tuple):
    """ Check if a given app matches any apps in a list

    Args:
        app_list (list): List of tuples containing apps with their names and versions.
        app_tuple (tuple): Tuple with the dependency name and its version regular
            expression.

    Returns:
        boolean: True if any apps in the list match the app name and the version regular
            expression from the given app tuple.
    """

    app_name, app_version_regex = app_tuple
    for applied_app_name, applied_app_version in app_list:
        if (applied_app_name == app_name and
                re.fullmatch(app_version_regex, applied_app_version) is not None):
            return True

    return False


def get_dependent_apps_missing(app_metadata, dbapi, include_apps_action_ignore=False):
    """
    Determine the list of dependent applications that are missing based
    on the provided app metadata.

    Args:
        app_metadata (dict): Metadata of the application which includes
            information about dependent apps.
        dbapi: Database API object used to query applied applications.
        include_apps_action_ignore (bool): Flag to include dependent apps
            with action set to ignore. Default is False.

    Returns:
        list: A list containing dictionaries (for individual missing dependencies)
        and lists of dictionaries (for mutually exclusive missing dependencies).
        Each dictionary represents a dependent application that is missing.
        Each list represents a group of mutually exclusive dependencies, where
        at least one must be satisfied.
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
            if isinstance(dependent_app, dict):
                action = dependent_app.get('action', None)
                app_tuple = (dependent_app.get('name', None), dependent_app.get('version', None))
                # If the action is not ignore, include_apps_action_ignore is False and the
                # dependent app is not already applied, add the dependent app to the list
                if ((action != constants.APP_METADATA_DEPENDENT_APPS_ACTION_IGNORE or
                        include_apps_action_ignore) and
                        not match_dependency(applied_apps_name_version, app_tuple)):
                    dependent_apps_list.append(dependent_app)
            elif isinstance(dependent_app, list):
                mutually_exclusive_apps = []
                for mutually_exclusive_app in dependent_app:
                    action = mutually_exclusive_app.get('action', None)
                    app_tuple = (mutually_exclusive_app.get('name', None),
                                 mutually_exclusive_app.get('version', None))
                    # If the action is not ignore, include_apps_action_ignore is False and the
                    # dependent app is not already applied, add the dependent app to the list
                    if ((action != constants.APP_METADATA_DEPENDENT_APPS_ACTION_IGNORE or
                            include_apps_action_ignore) and
                            not match_dependency(applied_apps_name_version, app_tuple)):
                        mutually_exclusive_apps.append(mutually_exclusive_app)
                if len(mutually_exclusive_apps) == len(dependent_app):
                    dependent_apps_list.append(mutually_exclusive_apps)
    return dependent_apps_list


def format_missing_apps_output(app_list):
    """
    Format a list of missing applications (including mutually exclusive groups)
    into a human-readable string.

    Args:
        app_list (list): List of dicts or lists of dicts representing missing apps.

    Returns:
        str: Formatted string describing the missing apps.
    """
    def format_single_app(app):
        return f"{app['name']} (compatible version(s): {app['version']})"

    formatted = []
    for app in app_list:
        if isinstance(app, dict):
            formatted.append(format_single_app(app))
        elif isinstance(app, list):
            formatted.append(" or ".join(
                format_single_app(mutually_exclusive_app) for mutually_exclusive_app in app))
    return ", ".join(formatted)


def is_action_match(action, action_type):
    """
    Determine if the given action matches the specified action type.

    Args:
        action (str or None): The action to check. Can be a string representing the action or None.
        action_type (str): The action type to match against.

    Returns:
        bool: True if the action matches the action type, or if the action type is
        'warn' and the action is None.
    """

    # If the action type is warn and the action is None, add the dependent
    # app to the list. The default action for dependent apps is warn.
    return (
        action == action_type or
        (action_type == constants.APP_METADATA_DEPENDENT_APPS_ACTION_WARN and action is None)
    )


def get_dependent_apps_by_action(dependent_apps_metadata_list, action_type):
    """
    Get the list of dependent apps based on the action type.

    Args:
        dependent_apps_metadata_list (list): List of dependent apps metadata.
        action_type (str): Action type of the dependent apps.

    Returns:
        list: A list containing dictionaries (for individual dependencies)
        and lists of dictionaries (for mutually exclusive dependencies),
        representing the dependent applications that match the action type.
    """

    dependent_apps_list = []

    for dependent_app in dependent_apps_metadata_list:
        if isinstance(dependent_app, dict):
            action = dependent_app.get('action', None)
            if is_action_match(action, action_type):
                dependent_apps_list.append({
                    'name': dependent_app['name'],
                    'version': dependent_app['version']
                })
        elif isinstance(dependent_app, list):
            mutually_exclusive_apps = []
            for dep in dependent_app:
                action = dep.get('action', None)
                if is_action_match(action, action_type):
                    mutually_exclusive_apps.append({
                        'name': dep['name'],
                        'version': dep['version']
                    })
            if mutually_exclusive_apps:
                dependent_apps_list.append(mutually_exclusive_apps)

    return dependent_apps_list


def has_circular_dependency(rpc_app, upload_apps_succeeded_list, dbapi):
    """
    Check for circular dependencies in the application metadata.

    Args:
        rpc_app: The application object being checked for circular dependencies.
        upload_apps_succeeded_list (list): List of successfully uploaded applications.
        dbapi: Database API object.

    Returns:
        bool: True if circular dependencies are found, False otherwise.
    """
    app_target = {
        'name': rpc_app.name,
        'version': rpc_app.app_version
    }

    # Initialize the variable
    dependent_apps_apply_type = []

    for dependent_app in upload_apps_succeeded_list:
        db_app = dbapi.kube_app_get(dependent_app['name'])
        app_metadata = db_app.app_metadata
        if not app_metadata.get(constants.APP_METADATA_DEPENDENT_APPS, None):
            continue

        dependent_apps_missing_list = get_dependent_apps_missing(
            db_app.app_metadata, dbapi)
        if not dependent_apps_missing_list:
            continue

        dependent_apps_apply_type = get_dependent_apps_by_action(
            dependent_apps_missing_list,
            constants.APP_METADATA_DEPENDENT_APPS_ACTION_APPLY)

    for dep in dependent_apps_apply_type:
        if (app_target['name'] == dep['name'] and
                re.fullmatch(dep['version'], app_target['version'])):
            return True

    return False


def is_blocking_dependency(dep, app_name, current_app_version, update_candidate_app_version):
    """
    Check if a dependency blocks the update candidate version.

    Args:
        dep (dict): Dependency dictionary with 'name' and 'version'.
        app_name (str): Name of the application.
        current_app_version (str): Currently applied version.
        update_candidate_app_version (str): Update candidate version.

    Returns:
        bool: True if the dependency blocks the update candidate version.
    """
    if re.fullmatch(dep.get('version'), update_candidate_app_version) is None:
        name_matches = dep.get('name') == app_name
        version_matches = re.fullmatch(dep.get('version'), current_app_version) is not None
        return name_matches and version_matches
    return False


def get_blocking_parent_dependencies(app_name,
                                     current_app_version,
                                     update_candidate_app_version,
                                     dbapi):
    """
    Retrieve a list of parent applied applications that do not comply with an update candidate
    version and declare a dependency on the current applied version.

    Args:
        app_name (str): The name of the application to check for as a dependency.
        current_app_version (str): The applied version of the application to check
                                   for dependent apps.
        update_candidate_app_version (str): The update candidate version of the application.
        dbapi: Database API object used to query applied applications.

    Returns:
        list of dict: A list of dictionaries, each containing the 'name' and 'version'
        of an applied parent application that lists the specified application and
        version as a dependency.
    """

    # Get the list of apps that are already applied
    applied_apps = dbapi.kube_app_get_all_by_status(constants.APP_APPLY_SUCCESS)

    dependent_parent_list = []

    for app in applied_apps:
        app_metadata = app.app_metadata
        dependent_apps_metadata_list = app_metadata.get(constants.APP_METADATA_DEPENDENT_APPS, [])
        for dependent_app in dependent_apps_metadata_list:
            # Handle mutually exclusive dependencies (list of dicts)
            if isinstance(dependent_app, list):
                for mutually_exclusive_app in dependent_app:
                    if is_blocking_dependency(mutually_exclusive_app,
                                              app_name,
                                              current_app_version,
                                              update_candidate_app_version):
                        dependent_parent_list.append({
                            'name': app.name,
                            'version': app.app_version
                        })
            # Handle single dependency (dict)
            elif isinstance(dependent_app, dict):
                if is_blocking_dependency(dependent_app,
                                          app_name,
                                          current_app_version,
                                          update_candidate_app_version):
                    dependent_parent_list.append({
                        'name': app.name,
                        'version': app.app_version
                    })

    return dependent_parent_list


def validate_parent_exceptions(blocking_parent_list, dependent_parent_exceptions):
    """ Check if all blocking apps have a corresponding exception

    Args:
        blocking_parent_list (list of dict): apps blocking an operation.
        dependent_parent_exceptions (list of dict): parent exceptions to be compared.

    Returns:
        True if all blocking apps have a corresponding exception. False otherwise.

    """

    for blocking_parent in blocking_parent_list:
        # Look for exceptions
        for parent_exception in dependent_parent_exceptions:
            if (blocking_parent['name'] == parent_exception['name'] and
                    re.fullmatch(parent_exception['version'],
                                 blocking_parent['version']) is not None):
                break
        else:
            return False

    return True
