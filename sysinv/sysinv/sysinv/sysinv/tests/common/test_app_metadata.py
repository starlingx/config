#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for app_metadata.py
"""

import io
import mock
import os.path
import testtools
import yaml

from sysinv.common import app_metadata
from sysinv.common import constants
from sysinv.common import exception


# these unit tests do not need to subclass base.TestCase
class Validate_metadata_file(testtools.TestCase):

    def get_metadata_yaml_sample(self, yaml_file_name):
        """Help Funcition to import example yaml

        :param yaml_file_name: path to yaml
        """
        path = os.path.join(os.path.dirname(__file__),
                            "data", yaml_file_name)

        with open(path, 'r', encoding='utf-8') as f:
            yaml_content = f.read()

        return yaml_content

    def test_nofile(self):
        """Verify results of validate_metadata_file

        when if no file is found, returns:
        app_name =  "", app_version = "", patches = []
        """
        app_name, app_version, patches = \
            app_metadata.validate_metadata_file("invalid_path",
                                                "invalid_file",
                                                upgrade_from_release=None)
        # if the file is not loaded or has invalid contents
        # validate_metadata_file returns two empty strings and
        # an empty list  ie:  "","",[]
        self.assertEqual(app_name, "")
        self.assertEqual(app_version, "")
        self.assertEqual(patches, [])

    @mock.patch.object(io, 'open')
    @mock.patch.object(os.path, 'isfile')
    def test_file_validation(self, _mock_isfile, _mock_open):
        """This test mocks file operations

        Returns static file contents to allow unit
        testing the validation code
        """

        _mock_isfile.return_value = "True"
        yaml_content = self.get_metadata_yaml_sample('sample_metadata.yaml')
        _mock_open.return_value = io.StringIO(yaml_content)

        app_name, app_version, patches = \
            app_metadata.validate_metadata_file("valid_path",
                                                "valid_file",
                                                upgrade_from_release=None)
        self.assertEqual(app_name, "sample-app")
        self.assertEqual(app_version, "1.2-3")

    @mock.patch.object(io, 'open')
    @mock.patch.object(os.path, 'isfile')
    def test_file_validate_with_bad_contents(self,
                                             _mock_isfile,
                                             _mock_open):
        """This test mocks file operations with bad values

         This test mocks file operations and verifies
         failure handling in how the yaml is validated
        """
        _mock_isfile.return_value = "True"

        # bad_replacements is a list of atomic changes that
        # will trigger a SysinvException in the validator
        bad_replacements = [
                # app_name cannot be None
                {constants.APP_METADATA_NAME: None},
                # app_version cannot be None
                {constants.APP_METADATA_VERSION: None},
                # minimum or maximum cannot be a boolean
                {constants.APP_METADATA_SUPPORTED_K8S_VERSION: {
                    constants.APP_METADATA_MINIMUM: True}},
                # minimum or maximum cannot be a number
                {constants.APP_METADATA_SUPPORTED_K8S_VERSION: {
                    constants.APP_METADATA_MINIMUM: 2}},
        ]

        # start each loop with valid contents and replace
        # a certain section with bad contents so that the
        # validator will raise a SysinvException
        for bad_dict in bad_replacements:
            contents = self.get_metadata_yaml_sample('sample_metadata.yaml')
            contents = yaml.safe_load(contents)

            for key, value in bad_dict.items():
                contents[key] = value

            bad_contents = yaml.dump(contents)
            _mock_open.return_value = io.StringIO(bad_contents)

            self.assertRaises(exception.SysinvException,
                              app_metadata.validate_metadata_file,
                              "valid_path",
                              "valid_file")

    @mock.patch.object(io, 'open')
    @mock.patch.object(os.path, 'isfile')
    def test_file_validation_supported_k8s_version(self,
                                                   _mock_isfile,
                                                   _mock_open):
        """Validate supported_k8s_version

        This test mocks file operations with supported_k8s_version key
        and returns static file contents to allow unit
        testing the validation code
        """
        _mock_isfile.return_value = "True"

        yaml_content = self.get_metadata_yaml_sample(
            'sample_metadata_k8s_versions.yaml')
        _mock_open.return_value = io.StringIO(yaml_content)

        app_name, app_version, patches = \
            app_metadata.validate_metadata_file("valid_path",
                                                "valid_file",
                                                upgrade_from_release=None)

        self.assertEqual(app_name, "sample-app")
        self.assertEqual(app_version, "1.2-3")

    @mock.patch.object(io, 'open')
    @mock.patch.object(os.path, 'isfile')
    def test_file_validation_supported_k8s_version_bad_contents(self,
                                                                _mock_isfile,
                                                                _mock_open):
        """Validate supported_k8s_version with bad values

        This test mocks file operations to supported_k8s_version key
        and verifies failure handling in how the yaml is validated
        """

        _mock_isfile.return_value = "True"

        # bad_replacements is a list of atomic changes that
        # will trigger a SysinvException in the validator
        bad_replacements = [
            # supported_k8s_version must be a dict
            {constants.APP_METADATA_SUPPORTED_K8S_VERSION: None},
            # minimum must be a string
            {constants.APP_METADATA_SUPPORTED_K8S_VERSION: {
                constants.APP_METADATA_MINIMUM: True}},
            # minimum must be a string
            {constants.APP_METADATA_SUPPORTED_K8S_VERSION: {
                constants.APP_METADATA_MAXIMUM: 1}}
        ]

        # start each loop with valid contents and replace
        # a certain section with bad contents so that the
        # validator will raise a SysinvException
        for bad_dict in bad_replacements:
            contents = self.get_metadata_yaml_sample(
                'sample_metadata_k8s_versions.yaml')
            contents = yaml.safe_load(contents)

            for key, value in bad_dict.items():
                contents[key] = value

            bad_contents = yaml.dump(contents)
            _mock_open.return_value = io.StringIO(bad_contents)

            self.assertRaises(exception.SysinvException,
                              app_metadata.validate_metadata_file,
                              "valid_path",
                              "valid_file")

    @mock.patch.object(io, 'open')
    @mock.patch.object(os.path, 'isfile')
    def test_file_validation_without_min_k8s_version(self,
                                                     _mock_isfile,
                                                     _mock_open):
        """Validate supported_k8s_version without supported_k8s_version

         This test mocks file operations without supported_k8s_version
         key and returns static file contents to allow unit testing the
         validation code
        """

        _mock_isfile.return_value = "True"

        yaml_content = self.get_metadata_yaml_sample(
            'sample_metadata_without_k8s_minimum_version.yaml')
        _mock_open.return_value = io.StringIO(yaml_content)

        self.assertRaises(exception.SysinvException,
                          app_metadata.validate_metadata_file,
                          "valid_path",
                          "valid_file")

    @mock.patch.object(io, 'open')
    @mock.patch.object(os.path, 'isfile')
    def test_file_validation_with_upgrade_key(self,
                                             _mock_isfile,
                                             _mock_open):
        """Validate upgrades key

        This test mocks file operations with upgrades key
        and returns static file contents to allow unit testing
        the validation code
        """

        _mock_isfile.return_value = "True"
        yaml_content = self.get_metadata_yaml_sample('sample_metadata_upgrades.yaml')
        _mock_open.return_value = io.StringIO(yaml_content)

        app_name, app_version, patches = \
            app_metadata.validate_metadata_file("valid_path",
                                                "valid_file",
                                                upgrade_from_release=None)
        self.assertEqual(app_name, "sample-app")
        self.assertEqual(app_version, "1.2-3")

    @mock.patch.object(io, 'open')
    @mock.patch.object(os.path, 'isfile')
    def test_file_validation_with_upgrade_key_bad_contents(self,
                                                         _mock_isfile,
                                                         _mock_open):
        """Validate upgrades key with bad values

        This test mocks file operations to upgrades key and
        verifies failure handling in how the yaml is validated
        """

        _mock_isfile.return_value = "True"

        # bad_replacements is a list of atomic changes that
        # will trigger a SysinvException in the validator
        bad_replacements = [
            # upgrades must be a dict
            {constants.APP_METADATA_UPGRADES: None},
            # update_failure_no_rollback must be a boolean string like: <true/false/yes/no>
            {constants.APP_METADATA_UPGRADES: {
                constants.APP_METADATA_UPDATE_FAILURE_SKIP_RECOVERY: 123}},
            # auto_update must be a boolean string like: <true/false/yes/no>
            {constants.APP_METADATA_UPGRADES: {constants.APP_METADATA_AUTO_UPDATE: 123}},
            # auto_update must be a list
            {constants.APP_METADATA_UPGRADES: {constants.APP_METADATA_FROM_VERSIONS: {}}}
        ]

        # start each loop with valid contents and replace
        # a certain section with bad contents so that the
        # validator will raise a SysinvException
        for bad_dict in bad_replacements:
            contents = self.get_metadata_yaml_sample('sample_metadata_upgrades.yaml')
            contents = yaml.safe_load(contents)

            for key, value in bad_dict.items():
                contents[key] = value

            bad_contents = yaml.dump(contents)
            _mock_open.return_value = io.StringIO(bad_contents)

            self.assertRaises(exception.SysinvException,
                              app_metadata.validate_metadata_file,
                              "valid_path",
                              "valid_file")

    @mock.patch.object(io, 'open')
    @mock.patch.object(os.path, 'isfile')
    def test_file_validation_repo_key(self,
                                      _mock_isfile,
                                      _mock_open):
        """Validate repo key

        This test mocks file operations with repo key and
        returns static file contents to allow unit testing
        the validation code
        """

        _mock_isfile.return_value = "True"
        yaml_content = self.get_metadata_yaml_sample('sample_metadata_repo.yaml')
        _mock_open.return_value = io.StringIO(yaml_content)

        app_name, app_version, patches = \
            app_metadata.validate_metadata_file("valid_path",
                                                "valid_file",
                                                upgrade_from_release=None)
        self.assertEqual(app_name, "sample-app")
        self.assertEqual(app_version, "1.2-3")

    @mock.patch.object(io, 'open')
    @mock.patch.object(os.path, 'isfile')
    def test_file_validation_behavior_key(self,
                                      _mock_isfile,
                                      _mock_open):
        """Validate behavior key

        This test mocks file operations with behavior key and
        returns static file contents to allow unit testing
        the validation code
        """

        _mock_isfile.return_value = "True"
        yaml_content = self.get_metadata_yaml_sample('sample_metadata_behavior.yaml')
        _mock_open.return_value = io.StringIO(yaml_content)

        app_name, app_version, patches = \
            app_metadata.validate_metadata_file("valid_path",
                                                "valid_file",
                                                upgrade_from_release=None)
        self.assertEqual(app_name, "sample-app")
        self.assertEqual(app_version, "1.2-3")

    @mock.patch.object(io, 'open')
    @mock.patch.object(os.path, 'isfile')
    def test_file_validate_behavior_key_with_bad_contents(self,
                                             _mock_isfile,
                                             _mock_open):
        """Validate behavior key with bad values

        This test mocks file operations to behavior key and
        verifies failure handling in how the yaml is validated
        """

        _mock_isfile.return_value = "True"

        # bad_replacements is a list of atomic changes that
        # will trigger a SysinvException in the validator
        bad_replacements = [
            # behavior must be a dict
            {constants.APP_METADATA_BEHAVIOR: []},
            # platform_managed_app must be a boolean string like: <true/false/yes/no>
            {constants.APP_METADATA_BEHAVIOR: {
                constants.APP_METADATA_PLATFORM_MANAGED_APP: "something"}},
            # desired_state must be a dict
            {constants.APP_METADATA_BEHAVIOR: {
                constants.APP_METADATA_DESIRED_STATE: 2}},
            # evaluate_reapply must be a dict
            {constants.APP_METADATA_BEHAVIOR: {constants.APP_METADATA_EVALUATE_REAPPLY: []}},
            # after must be a list
            {constants.APP_METADATA_BEHAVIOR: {constants.APP_METADATA_EVALUATE_REAPPLY: {
                constants.APP_METADATA_AFTER: {}}}},
            # triggers must be a list
            {constants.APP_METADATA_BEHAVIOR: {constants.APP_METADATA_EVALUATE_REAPPLY: {
                constants.APP_METADATA_TRIGGERS: {}}}},
            # type must be a string
            {constants.APP_METADATA_BEHAVIOR: {
                constants.APP_METADATA_EVALUATE_REAPPLY: {
                    constants.APP_METADATA_TRIGGERS: [{constants.APP_METADATA_TYPE: 1}]
                }
            }},
            # filter_field must be a string
            {constants.APP_METADATA_BEHAVIOR: {
                constants.APP_METADATA_EVALUATE_REAPPLY: {
                    constants.APP_METADATA_TRIGGERS: [{constants.APP_METADATA_FILTER_FIELD: 1}]
                }
            }},
            # filters must be a list
            {constants.APP_METADATA_BEHAVIOR: {
                constants.APP_METADATA_EVALUATE_REAPPLY: {
                    constants.APP_METADATA_TRIGGERS: [{constants.APP_METADATA_FILTERS: {}}]
                }
            }}
        ]

        # start each loop with valid contents and replace
        # a certain section with bad contents so that the
        # validator will raise a SysinvException
        for bad_dict in bad_replacements:
            contents = self.get_metadata_yaml_sample('sample_metadata_behavior.yaml')
            contents = yaml.safe_load(contents)

            for key, value in bad_dict.items():
                contents[key] = value

            bad_contents = yaml.dump(contents)
            _mock_open.return_value = io.StringIO(bad_contents)

            self.assertRaises(exception.SysinvException,
                              app_metadata.validate_metadata_file,
                              "valid_path",
                              "valid_file")

    @mock.patch.object(io, 'open')
    @mock.patch.object(os.path, 'isfile')
    def test_file_validation_supported_releases(self,
                                                _mock_isfile,
                                                _mock_open):
        """Validate supported_releases key

        This test mocks file operations with supported_releases
        key and returns static file contents to allow unit testing
        the validation code
        """
        _mock_isfile.return_value = "True"

        yaml_content = self.get_metadata_yaml_sample(
            'sample_metadata_supported_releases.yaml')
        _mock_open.return_value = io.StringIO(yaml_content)

        app_name, app_version, patches = \
            app_metadata.validate_metadata_file("valid_path",
                                                "valid_file",
                                                upgrade_from_release=None)

        self.assertEqual(app_name, "sample-app")
        self.assertEqual(app_version, "1.2-3")
        self.assertEqual(patches, ["patch_0001", "patch_0002"])

    @mock.patch.object(io, 'open')
    @mock.patch.object(os.path, 'isfile')
    def test_file_validation_supported_releases_bad_contents(self,
                                                _mock_isfile,
                                                _mock_open):
        """Validate supported_releases key with bad values

        This test mocks file operations to supported_releases key
        and verifies failure handling in how the yaml is validated
        """
        _mock_isfile.return_value = "True"

        # bad_replacements is a list of atomic changes that
        # will trigger a SysinvException in the validator
        bad_replacements = [
            # supported_releases must be a dict
            {constants.APP_METADATA_SUPPORTED_RELEASES: []},
            # releases group must be a list
            {constants.APP_METADATA_SUPPORTED_RELEASES: {"TEST.SW.VERSION": {}}},
            # releases item must be a string
            {constants.APP_METADATA_SUPPORTED_RELEASES: {"TEST.SW.VERSION": [1, True]}},
        ]

        # start each loop with valid contents and replace
        # a certain section with bad contents so that the
        # validator will raise a SysinvException
        for bad_dict in bad_replacements:
            contents = self.get_metadata_yaml_sample(
                'sample_metadata_supported_releases.yaml')
            contents = yaml.safe_load(contents)

            for key, value in bad_dict.items():
                contents[key] = value

            bad_contents = yaml.dump(contents)
            _mock_open.return_value = io.StringIO(bad_contents)

            self.assertRaises(exception.SysinvException,
                              app_metadata.validate_metadata_file,
                              "valid_path",
                              "valid_file")

    @mock.patch.object(io, 'open')
    @mock.patch.object(os.path, 'isfile')
    def test_file_validation_k8s_upgrades(self,
                                          _mock_isfile,
                                          _mock_open):
        """Validate k8s_upgrades key

        This test mocks file operations with k8s_upgrades
        key and returns static file contents to allow unit testing
        the validation code
        """
        _mock_isfile.return_value = "True"

        yaml_content = self.get_metadata_yaml_sample(
            'sample_metadata_k8s_upgrades.yaml')
        _mock_open.return_value = io.StringIO(yaml_content)

        app_name, app_version, patches = \
            app_metadata.validate_metadata_file("valid_path",
                                                "valid_file",
                                                upgrade_from_release=None)

        self.assertEqual(app_name, "sample-app")
        self.assertEqual(app_version, "1.2-3")

    @mock.patch.object(io, 'open')
    @mock.patch.object(os.path, 'isfile')
    def test_file_validation_k8s_upgrades_bad_contents(self,
                                                       _mock_isfile,
                                                       _mock_open):
        """Validate k8s_upgrades key with bad values

        This test mocks file operations to k8s_upgrades key
        and verifies failure handling in how the yaml is validated
        """
        _mock_isfile.return_value = "True"

        # bad_replacements is a list of atomic changes that
        # will trigger a SysinvException in the validator
        bad_replacements = [
            # k8s_upgrades must be a dict
            {constants.APP_METADATA_K8S_UPGRADES: []},
            # auto_update key must be a boolean string
            # like: <true/false/yes/no>
            {constants.APP_METADATA_K8S_UPGRADES: {
                constants.APP_METADATA_AUTO_UPDATE: None,
            }},
            {constants.APP_METADATA_K8S_UPGRADES: {
                constants.APP_METADATA_AUTO_UPDATE: True,
                # if auto_update key exist timing key must exist and be a string
                constants.APP_METADATA_TIMING: None
            }},
        ]

        # start each loop with valid contents and replace
        # a certain section with bad contents so that the
        # validator will raise a SysinvException
        for bad_dict in bad_replacements:
            contents = self.get_metadata_yaml_sample(
                'sample_metadata_k8s_upgrades.yaml')
            contents = yaml.safe_load(contents)

            for key, value in bad_dict.items():
                contents[key] = value

            bad_contents = yaml.dump(contents)
            _mock_open.return_value = io.StringIO(bad_contents)

            self.assertRaises(exception.SysinvException,
                              app_metadata.validate_metadata_file,
                              "valid_path",
                              "valid_file")
