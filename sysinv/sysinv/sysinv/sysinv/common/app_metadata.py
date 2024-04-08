#
# Copyright (c) 2023-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# All Rights Reserved.
#

import io
import glob
import os
import ruamel.yaml
import shutil
import six
import tarfile
import tempfile
import yaml

from oslo_config import cfg
from oslo_log import log as logging
from sysinv._i18n import _
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils

CONF = cfg.CONF

LOG = logging.getLogger(__name__)


def _locate_metadata_file(directory):

    return glob.glob(directory + '/**/metadata.yaml', recursive=True)


def validate_metadata_file(path, metadata_file, upgrade_from_release=None):
    """ Find and validate the metadata file in a given directory.

    Valid keys for metadata file are defined in the following format:

    app_name: <name>
    app_version: <version>
    upgrades:
      auto_update: <true/false/yes/no>
      update_failure_no_rollback: <true/false/yes/no>
      from_versions:
      - <version.1>
      - <version.2>
    supported_k8s_version:
      minimum: <version>
      maximum: <version>
    k8s_upgrades:
      auto_update: <true/false/yes/no>
      timing: <pre/post>
    supported_releases:
      <release>:
      - <patch.1>
      - <patch.2>
      ...
    repo: <helm repo> - optional: defaults to HELM_REPO_FOR_APPS
    disabled_charts: - optional: charts default to enabled
    - <chart name>
    - <chart name>
    ...

    maintain_attributes: <true|false>
      - optional: defaults to false. Over an app update any system overrides
        are preserved for the new version of the application. This can be
        renamed to 'maintain_system_overrides', but will require more effort
        to keep the naming of 'helm-chart-attribute-modify' command in sync
        with this.
    maintain_user_overrides: <true|false>
      - optional: defaults to false. Over an app update any user overrides are
        preserved for the new version of the application

    behavior: - optional: describes the app behavior
        platform_managed_app: <true/false/yes/no> - optional: when absent
        behaves as false
        desired_state: <uploaded/applied> - optional: state the app should
        reach
        evaluate_reapply: - optional: describe the reapply evaluation behaviour
            after: - optional: list of apps that should be evaluated before
            the current one
              - <app_name.1>
              - <app_name.2>
            triggers: - optional: list of what triggers the reapply evaluation
              - type: <key in APP_EVALUATE_REAPPLY_TRIGGER_TO_METADATA_MAP>
                filters: - optional: list of field:value, that aid filtering
                    of the trigger events. All pairs in this list must be
                    present in trigger dictionary that is passed in
                    the calls (eg. trigger[field_name1]==value_name1 and
                    trigger[field_name2]==value_name2).
                    Function evaluate_apps_reapply takes a dictionary called
                    'trigger' as parameter. Depending on trigger type this
                    may contain custom information used by apps, for example
                    a field 'personality' corresponding to node personality.
                    It is the duty of the app developer to enhance existing
                    triggers with the required information.
                    Hard to obtain information should be passed in the trigger.
                    To use existing information it is as simple as defining
                    the metadata.
                  - <field_name.1>: <value_name.1>
                  - <field_name.2>: <value_name.2>
                filter_field: <field_name> - optional: field name in trigger
                              dictionary. If specified the filters are applied
                              to trigger[filter_field] sub-dictionary instead
                              of the root trigger dictionary.
    """

    # Type-level validations:
    def validate_string(value, error_message=None):
        """Validate string types"""

        if not isinstance(value, six.string_types):
            if not error_message:
                error_message = _("Invalid string: {}.".format(value))

            raise exception.SysinvException(error_message)

    def validate_boolstr(value, error_message=None):
        """Validate boolean string types"""

        if not utils.is_valid_boolstr(value):
            if not error_message:
                error_message = _("Invalid boolean value: {}"
                                  .format(value))
            raise exception.SysinvException(error_message)

    def validate_dict(value, error_message=None):
        """Validate dictionary types"""

        if not isinstance(value, dict):
            if not error_message:
                error_message = _("Invalid dictionary: {}"
                                  .format(value))
            raise exception.SysinvException(error_message)

    def validate_list(value, error_message=None):
        "Validate list types"

        if not isinstance(value, list):
            if not error_message:
                error_message = _("Invalid list: {}".format(value))
            raise exception.SysinvException(error_message)

    # Field-level validations:
    def validate_string_field(parent, key):
        """ Validate a metadata string field

        :param parent: parent section that contains the string field
                       to be verified
        :param key: field name to be validated
        """
        value = None

        try:
            value = parent[key]
            error_message = _("Invalid {}: {} should be {}.".format(
                metadata_file,
                key,
                six.string_types))
            validate_string(value, error_message)
        except KeyError:
            pass

        return value

    def validate_boolstr_field(parent, key):
        """ Validate metadata boolean string fields

        :param parent: parent section that contains the boolean string field
                       to be verified
        :param key: field name to be validated
        """
        value = None

        try:
            value = parent[key]
            error_message = _("Invalid {}: {} expected values: 'true', 'false', "
                              "'yes', 'no', 'y', 'n', '1' or '0'"
                              .format(metadata_file, key))
            validate_boolstr(value, error_message)
        except KeyError:
            pass

        return value

    def validate_dict_field(parent, key):
        """ Validate metadata dictionary fields

        :param parent: parent section that contains the dictionary field
                       to be verified
        :param key: field name to be validated
        """
        value = None

        try:
            value = parent[key]
            error_message = _("Invalid {}: {} should be a dict."
                              .format(metadata_file, key))
            validate_dict(value, error_message)
        except KeyError:
            pass

        return value

    def validate_list_field(parent, key):
        """ Validate metadata list fields

        :param parent: parent section that contains the list field
                       to be verified
        :param key: field name to be validated
        """
        value = None

        try:
            value = parent[key]
            error_message = _("Invalid {}: {} should be a list."
                              .format(metadata_file,
                                      constants.APP_METADATA_AFTER))
            validate_list(value, error_message)
        except KeyError:
            pass

        return value

    # Specific validations
    def validate_timing(parent):
        """ Validate the timing field of a given parent section

        :param parent: parent section that contains the timing field
                       to be verified
        """

        value = None

        try:
            value = \
                parent[constants.APP_METADATA_TIMING]
            if value != "pre" and value != "post":
                raise exception.SysinvException(_(
                    "Invalid {}: {} expected value is either 'pre' or 'post'."
                    "".format(metadata_file,
                              constants.APP_METADATA_TIMING)))
        except KeyError:
            pass

        return value

    def validate_k8s_version(parent):
        """ Validate the Kubernetes version section of a given
            parent section

        :param parent: parent section that contains the Kubernetes
                       version section to be verified
        """

        value = \
            validate_dict_field(parent,
                                constants.APP_METADATA_SUPPORTED_K8S_VERSION)

        if value is None:
            raise exception.SysinvException(_(
                "Kubernetes supported versions not specified on application "
                "metadata file. Please add a 'supported_k8s_version' section "
                "containing at least a 'minimum' field ('maximum' field is "
                "optional)."))

        return value

    def validate_k8s_minimum_version(parent):
        """ Validate the Kubernetes minimum version field of a given
            parent section

        :param parent: parent section that contains the Kubernetes
                       minimum version field to be verified
        """
        validate_string_field(parent, constants.APP_METADATA_MINIMUM)

        value = validate_string_field(parent, constants.APP_METADATA_MINIMUM)
        if value is None:
            raise exception.SysinvException(_(
                "Minimum supported Kubernetes version not specified "
                "on application metadata file. Please add a 'minimum' "
                "field to the 'supported_k8s_version' section."))

    def validate_k8s_upgrades_section(k8s_upgrades_auto_update,
                                      k8s_upgrades_timing):
        """ Validate the k8s_upgrade section

        :param k8s_app_auto_update: k8s_upgrade:auto_update field value
        :param k8s_app_timing: k8s_upgrade:timing field value
        """

        if (k8s_upgrades_auto_update and k8s_upgrades_timing is None):
            raise exception.SysinvException(_(
                "Metadata file has 'k8s_upgrade:auto_update' set but no "
                "corresponding k8s_upgrade:timing field was found. Please add "
                "a 'timing' field to the 'k8s_upgrade' section."))

        if (k8s_upgrades_timing and k8s_upgrades_auto_update is None):
            raise exception.SysinvException(_(
                "Metadata file has 'k8s_upgrade:timing' set but no "
                "corresponding k8s_upgrade:auto_update field was found. Please "
                "add an 'auto_update' field to the 'k8s_upgrade' section."))

    app_name = ''
    app_version = ''
    patches = []
    metadata_path = os.path.join(path, metadata_file)

    if os.path.isfile(metadata_path):
        with io.open(metadata_path, 'r', encoding='utf-8') as f:
            try:
                doc = yaml.safe_load(f)
                app_name = doc['app_name']
                app_version = doc['app_version']
            except KeyError:
                # metadata file does not have the key(s)
                pass

            # Have to check for empty string instead of None.
            if app_name == '' or app_name is None:
                raise exception.SysinvException(_(
                    "Invalid %s: app_name is empty or None." % metadata_file)
                )
            if app_version == '' or app_version is None:
                raise exception.SysinvException(_(
                    "Invalid %s: app_version is empty or None." % metadata_file)
                )

            behavior = validate_dict_field(doc,
                                           constants.APP_METADATA_BEHAVIOR)
            if behavior:
                validate_boolstr_field(
                    behavior,
                    constants.APP_METADATA_PLATFORM_MANAGED_APP)
                validate_string_field(
                    behavior,
                    constants.APP_METADATA_DESIRED_STATE)
                evaluate_reapply = \
                    validate_dict_field(
                        behavior,
                        constants.APP_METADATA_EVALUATE_REAPPLY)

                if evaluate_reapply:
                    validate_list_field(
                        evaluate_reapply,
                        constants.APP_METADATA_AFTER)
                    triggers = validate_list_field(
                        evaluate_reapply,
                        constants.APP_METADATA_TRIGGERS)

                    if triggers:
                        for trigger in triggers:
                            validate_dict(trigger)
                            validate_string_field(
                                trigger,
                                constants.APP_METADATA_TYPE)
                            validate_string_field(
                                trigger,
                                constants.APP_METADATA_FILTER_FIELD)
                            validate_list_field(
                                trigger,
                                constants.APP_METADATA_FILTERS)

        upgrades = validate_dict_field(doc, constants.APP_METADATA_UPGRADES)
        if upgrades:
            validate_boolstr_field(
                upgrades,
                constants.APP_METADATA_UPDATE_FAILURE_SKIP_RECOVERY)
            validate_boolstr_field(
                upgrades,
                constants.APP_METADATA_AUTO_UPDATE)
            from_versions = validate_list_field(
                upgrades,
                constants.APP_METADATA_FROM_VERSIONS)

            if from_versions:
                for version in from_versions:
                    validate_string(version)

        # Kubernetes version section validation
        k8s_version = validate_k8s_version(doc)
        if k8s_version:
            validate_k8s_minimum_version(k8s_version)
            validate_string_field(k8s_version, constants.APP_METADATA_MAXIMUM)

        # Kubernetes upgrades section validation
        k8s_upgrades = \
            validate_dict_field(doc,
                                constants.APP_METADATA_K8S_UPGRADES)
        if k8s_upgrades:
            k8s_upgrades_auto_update = \
                validate_boolstr_field(k8s_upgrades,
                                       constants.APP_METADATA_AUTO_UPDATE)
            k8s_upgrades_timing = validate_timing(k8s_upgrades)
            validate_k8s_upgrades_section(k8s_upgrades_auto_update,
                                          k8s_upgrades_timing)

        supported_releases = \
            validate_dict_field(doc, constants.APP_METADATA_SUPPORTED_RELEASES)

        if upgrade_from_release is None:
            check_release = utils.get_sw_version()
        else:
            check_release = upgrade_from_release

        if supported_releases:
            release_error_message = _(
                        "Invalid {}: {} release key should be {}."
                        .format(metadata_file,
                                constants.APP_METADATA_SUPPORTED_RELEASES,
                                six.string_types))
            release_patches_error_message = _(
                        "Invalid {}: {} <release>: [<patch>, ...] "
                        "patches should be a list."
                        .format(metadata_file,
                                constants.APP_METADATA_SUPPORTED_RELEASES))
            patch_error_message = _(
                        "Invalid {}: {} <release>: [<patch>, ...] "
                        "each patch should be {}."
                        .format(metadata_file,
                                constants.APP_METADATA_SUPPORTED_RELEASES,
                                six.string_types))
            for release, release_patches in supported_releases.items():
                validate_string(release, release_error_message)
                validate_list(release_patches,
                              release_patches_error_message)

                for patch in release_patches:
                    validate_string(patch, patch_error_message)
                if release == check_release:
                    patches.extend(release_patches)
                    LOG.info("{}, application {} ({}), "
                             "check_release {}, requires patches {}"
                             .format(metadata_file, app_name, app_version,
                                     check_release, release_patches))

    return app_name, app_version, patches


def verify_application_tarball(path: str) -> None:
    """Verify metadata withing an application tarball directly.

    Args:
        path: str: An absolute path to application tarball.
    """
    with tempfile.TemporaryDirectory() as temp_dirname:

        # Copy tarball
        shutil.copy(path, temp_dirname)

        if not utils.extract_tarfile(temp_dirname, path):
            raise Exception("Unable to extract tarball")

        # If checksum file is included in the tarball, verify its contents.
        if not utils.verify_checksum(temp_dirname):
            raise Exception("Unable to verify app tarball checksum")

        try:
            name, version, _ = validate_metadata_file(
                temp_dirname, constants.APP_METADATA_FILE)

            if name == '' and version == '':
                message = "Application Metadata file not found! Failure!"
                LOG.error(message)
                raise Exception(message)
            else:
                LOG.info(
                    f"Application Metadata for App: {name}, "
                    f"Ver: {version} succeeded!"
                )
        except exception.SysinvException as e:
            LOG.info("Application Metadata Verification Failed!")
            raise exception.SysinvException(_(
                "metadata verification failed. {}".format(e)))


def verify_application_metadata_file(path: str) -> bool:
    """Verify metadata withing an that is in a repository or not in tarball.

    Args:
        path: str: An absolute path to application metadata.yaml or an absolute
                   path to the folder it resides in.
    """
    is_verified = False

    with tempfile.TemporaryDirectory() as temp_dirname:

        # The input may be either a file, or a directory.  Depending on which
        # use the appropriate shutil copy function.

        final_dir_name = temp_dirname

        if os.path.isfile(path):
            shutil.copy(path, temp_dirname)
        else:
            shutil.copytree(path, temp_dirname, dirs_exist_ok=True)

            metadata_path_hits = _locate_metadata_file(temp_dirname)

            if len(metadata_path_hits) == 0:
                message = \
                    f"Error: Metadata file not found in directory: {path}"
                LOG.error(message)
                raise Exception(message)
            elif len(metadata_path_hits) > 1:
                message = \
                    "Error: Found More than One Application Metadata File! " \
                    "There should only be one!"
                LOG.error(message)
                raise Exception(message)
            else:
                final_dir_name = os.path.dirname(metadata_path_hits[-1])

        try:
            name, version, _ = validate_metadata_file(
                final_dir_name, constants.APP_METADATA_FILE)

            if name == '' and version == '':
                message = "Application Metadata file not found! Failure!"
                LOG.error(message)
                is_verified = False
                raise Exception(message)
            else:
                LOG.info(
                    f"Application Metadata for App: {name}, "
                    f"Ver: {version} succeeded!"
                )
                is_verified = True
        except exception.SysinvException as e:
            LOG.info("Application Metadata Verification Failed!")
            raise exception.SysinvException(_(
                "metadata verification failed. {}".format(e)))

    return is_verified


def verify_application(path: str) -> bool:
    """Wrapper for all possible tests or checks. This is what Tox will use.

    Whenever a new check is needed, that should be added here as another
    condition.

    Args:
    path: str: An absolute path to application metadata.yaml or an absolute
                path to the folder it resides in.
    """
    is_verified = False

    # For each check, add a try except so there is granularity.
    # This test will exit on the first failure detected.
    try:
        verify_application_metadata_file(path)
        is_verified = True
    except exception.SysinvException as e:
        LOG.info("Application Metadata Verification Failed!")
        raise exception.SysinvException(_(
            "metadata verification failed. {}".format(e)))

    return is_verified


def extract_bundle_metadata(file_path):
    """Extract metadata from a given tarball

    :param file_path: Application bundle file path
    """

    try:
        tarball = tarfile.open(file_path)
        metadata_yaml_path = "./{}".format(constants.APP_METADATA_FILE)
        tarball.getmember(metadata_yaml_path)

        with tarball.extractfile(metadata_yaml_path) as metadata_file:
            metadata = ruamel.yaml.load(metadata_file,
                                        Loader=ruamel.yaml.RoundTripLoader,
                                        preserve_quotes=True)

        minimum_supported_k8s_version = metadata.get(
            constants.APP_METADATA_SUPPORTED_K8S_VERSION, {}).get(
                constants.APP_METADATA_MINIMUM, None)

        if minimum_supported_k8s_version is None:
            LOG.error("Minimum supported Kubernetes version missing from {}"
                      .format(file_path))
            return None

        minimum_supported_k8s_version = minimum_supported_k8s_version.strip().lstrip('v')

        maximum_supported_k8s_version = metadata.get(
            constants.APP_METADATA_SUPPORTED_K8S_VERSION, {}).get(
                constants.APP_METADATA_MAXIMUM, None)

        if maximum_supported_k8s_version is not None:
            maximum_supported_k8s_version = maximum_supported_k8s_version.strip().lstrip('v')

        k8s_upgrades = metadata.get(constants.APP_METADATA_K8S_UPGRADES, None)
        if k8s_upgrades is None:
            k8s_auto_update = constants.APP_METADATA_K8S_AUTO_UPDATE_DEFAULT_VALUE
            k8s_update_timing = constants.APP_METADATA_TIMING_DEFAULT_VALUE
            LOG.warning("k8s_upgrades section missing from {} metadata"
                        .format(file_path))
        else:
            k8s_auto_update = metadata.get(
                constants.APP_METADATA_K8S_UPGRADES).get(
                constants.APP_METADATA_AUTO_UPDATE,
                constants.APP_METADATA_K8S_AUTO_UPDATE_DEFAULT_VALUE)
            k8s_update_timing = metadata.get(
                constants.APP_METADATA_K8S_UPGRADES).get(
                constants.APP_METADATA_TIMING,
                constants.APP_METADATA_TIMING_DEFAULT_VALUE)

        bundle_data = {
            'name': metadata.get(constants.APP_METADATA_NAME),
            'version': metadata.get(constants.APP_METADATA_VERSION),
            'file_path': file_path,
            'auto_update':
                metadata.get(constants.APP_METADATA_UPGRADES, {}).get(
                    constants.APP_METADATA_AUTO_UPDATE,
                    CONF.app_framework.missing_auto_update),
            'k8s_auto_update': k8s_auto_update,
            'k8s_timing': k8s_update_timing,
            'k8s_minimum_version': minimum_supported_k8s_version,
            'k8s_maximum_version': maximum_supported_k8s_version
        }

        return bundle_data
    except KeyError:
        LOG.warning("Application bundle {} does not contain a metadata file.".format(file_path))
    except Exception as e:
        LOG.exception(e)
