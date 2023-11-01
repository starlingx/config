#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# All Rights Reserved.
#

import io
import os
import six
import yaml

from oslo_log import log as logging

from sysinv._i18n import _
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils

LOG = logging.getLogger(__name__)


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

        # TODO: uncomment when supported_k8s_version is included on
        # the metadata file of at least all default apps
        #
        # if value is None:
        #    raise exception.SysinvException(_(
        #        "Kubernetes supported versions not specified on application "
        #        "metadata file. Please add a 'supported_k8s_version' section "
        #        "containing at least a 'minimum' field ('maximum' field is "
        #        "optional)."))
        #
        return value

    def validate_k8s_minimum_version(parent):
        """ Validate the Kubernetes minimum version field of a given
            parent section

        :param parent: parent section that contains the Kubernetes
                       minimum version field to be verified
        """
        validate_string_field(parent, constants.APP_METADATA_MINIMUM)

        # TODO: uncomment when k8s_minimum_version is included on
        # the metadata file of at least all default apps
        #
        # value = validate_string_field(parent, constants.APP_METADATA_MINIMUM)
        # if value is None:
        #    raise exception.SysinvException(_(
        #        "Minimum supported Kubernetes version not specified "
        #        "on application metadata file. Please add a 'minimum' "
        #        "field to the 'supported_k8s_version' section."))

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

            if (app_name is None or
                    app_version is None):
                raise exception.SysinvException(_(
                    "Invalid %s: app_name or/and app_version "
                    "is/are None." % metadata_file))

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
                validate_list_field(release_patches,
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
