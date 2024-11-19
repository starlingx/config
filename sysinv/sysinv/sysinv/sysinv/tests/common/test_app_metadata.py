#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for app_metadata.py
"""

from dataclasses import dataclass
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


@dataclass
class FakeDbApp(object):
    name: str


class FakeDbapi(object):
    def __init__(self):
        self.fake_db_apps = [
            FakeDbApp('cert-manager'),
            FakeDbApp('istio'),
            FakeDbApp('metrics-server')
        ]

    def kube_app_get_all(self):
        if not self.fake_db_apps:
            raise exception.KubeAppNotFound("exception raised")
        return self.fake_db_apps


class FakeHelper(object):
    def __init__(self, dbapi):
        self.dbapi = dbapi
        self.raise_exception_once = False
        self.success_count = 0
        self.fake_metadata_values = iter(
            (
                ('metrics-server', '1.1.1', 'ds1a'),
                ('cert-manager', '1.3.1', 'ds1a'),
                ('istio', '2.1.1', 'ds1a')
            )
        )

    def _verify_metadata_file(self, path, name, version):
        if self.raise_exception_once:
            self.raise_exception_once = False
            raise exception.SysinvException("fake exception.")
        fake_value = next(self.fake_metadata_values)
        self.success_count += 1
        return fake_value


class FakeYaml(object):
    def __init__(self):
        self.content = iter((
            ('metrics-server', '1.1.1'),
            ('cert-manager', '1.3.1'),
            ('istio', '2.1.1')
        ))

    def get_fake_content(self):
        name, version = next(self.content)
        return io.StringIO(f"""
            maintain_user_overrides: true
            app_name: {name}
            app_version: {version}
            helm_repo: stx-platform
        """)


FAKE_PATH = '/temp/path'


class TestLoadMetadata(testtools.TestCase):
    '''
        TODO: A previous attempt of implemeting this testcase, trying to start the mocks in the
              setUp method resulted in a fail check at zuul, point out to a bug where mock.patch
              looses its references. In the future, its necessary to remove the mock decorator and
              add mocks in the setUp method to eliminate duplicated code in the tests.
    '''

    @mock.patch('sysinv.db.api.get_instance')
    @mock.patch('sysinv.api.controllers.v1.kube_app.KubeAppHelper')
    @mock.patch.object(os, 'listdir')
    @mock.patch('sysinv.common.utils.TempDirectory')
    @mock.patch('sysinv.common.utils.extract_tarfile')
    @mock.patch('sysinv.common.utils.verify_checksum')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(io, 'open')
    @mock.patch('sysinv.conductor.kube_app.AppOperator.update_and_process_app_metadata')
    def test_load_metadata_raises_exception_when_there_are_no_apps(
        self,
        mock_operator,
        mock_io,
        mock_path_exists,
        mock_checksum,
        mock_extract,
        mock_directory,
        mock_app_bundle,
        mock_helper,
        mock_dbapi
    ):
        fake_metadata = {
            'apps': {},
            'platform_managed_apps_list': {},
            'desired_states': {},
            'ordered_apps': []
        }
        mock_helper.return_value = FakeHelper(mock_dbapi)
        mock_app_bundle.return_value = [
            'oidc-auth-apps-22.12-6.tgz',
            'metrics-server-22.12-2.tgz',
            'cert-manager-22.12-8.tgz',
            'platform-integ-apps-22.12-71.tgz',
            'istio-22.12-1.tgz'
        ]
        mock_directory.return_value.__enter__.return_value = FAKE_PATH
        mock_path_exists.return_value = True
        fake_yml = FakeYaml()
        mock_io.return_value.__enter__.side_effect = [
            fake_yml.get_fake_content(),
            fake_yml.get_fake_content(),
            fake_yml.get_fake_content()
        ]
        fake_db = FakeDbapi()
        fake_db.fake_db_apps = []
        mock_dbapi.return_value = fake_db
        self.assertRaises(exception.KubeAppNotFound, app_metadata.load_metadata_of_apps, fake_metadata)

    @mock.patch('sysinv.db.api.get_instance')
    @mock.patch('sysinv.api.controllers.v1.kube_app.KubeAppHelper')
    @mock.patch.object(os, 'listdir')
    @mock.patch('sysinv.common.utils.TempDirectory')
    @mock.patch('sysinv.common.utils.extract_tarfile')
    @mock.patch('sysinv.common.utils.verify_checksum')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(io, 'open')
    @mock.patch('sysinv.conductor.kube_app.AppOperator.update_and_process_app_metadata')
    def test_if_only_loaded_applications_have_the_tarballs_extracted(
        self,
        mock_operator,
        mock_io,
        mock_path_exists,
        mock_checksum,
        mock_extract,
        mock_directory,
        mock_app_bundle,
        mock_helper,
        mock_dbapi
    ):
        fake_metadata = {
            'apps': {},
            'platform_managed_apps_list': {},
            'desired_states': {},
            'ordered_apps': []
        }
        mock_dbapi.return_value = FakeDbapi()
        mock_helper.return_value = FakeHelper(mock_dbapi)
        mock_app_bundle.return_value = [
            'oidc-auth-apps-22.12-6.tgz',
            'metrics-server-22.12-2.tgz',
            'cert-manager-22.12-8.tgz',
            'platform-integ-apps-22.12-71.tgz',
            'istio-22.12-1.tgz'
        ]
        mock_directory.return_value.__enter__.return_value = FAKE_PATH
        mock_path_exists.return_value = True
        fake_yml = FakeYaml()
        mock_io.return_value.__enter__.side_effect = [
            fake_yml.get_fake_content(),
            fake_yml.get_fake_content(),
            fake_yml.get_fake_content()
        ]
        app_metadata.load_metadata_of_apps(fake_metadata)
        mock_extract.assert_has_calls(
            [
                mock.call('/temp/path', f'{constants.HELM_APP_ISO_INSTALL_PATH}/cert-manager-22.12-8.tgz'),
                mock.call('/temp/path', f'{constants.HELM_APP_ISO_INSTALL_PATH}/istio-22.12-1.tgz'),
                mock.call('/temp/path', f'{constants.HELM_APP_ISO_INSTALL_PATH}/metrics-server-22.12-2.tgz'),
            ], any_order=True
        )
        self.assertEqual(mock_extract.call_count, 3)

    @mock.patch('sysinv.db.api.get_instance')
    @mock.patch('sysinv.api.controllers.v1.kube_app.KubeAppHelper')
    @mock.patch.object(os, 'listdir')
    @mock.patch('sysinv.common.utils.TempDirectory')
    @mock.patch('sysinv.common.utils.extract_tarfile')
    @mock.patch('sysinv.common.utils.verify_checksum')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(io, 'open')
    @mock.patch('sysinv.conductor.kube_app.AppOperator.update_and_process_app_metadata')
    def test_if_only_loaded_applications_have_the_checksum_verified(
        self,
        mock_operator,
        mock_io,
        mock_path_exists,
        mock_checksum,
        mock_extract,
        mock_directory,
        mock_app_bundle,
        mock_helper,
        mock_dbapi
    ):
        fake_metadata = {
            'apps': {},
            'platform_managed_apps_list': {},
            'desired_states': {},
            'ordered_apps': []
        }
        mock_dbapi.return_value = FakeDbapi()
        mock_helper.return_value = FakeHelper(mock_dbapi)
        mock_app_bundle.return_value = [
            'oidc-auth-apps-22.12-6.tgz',
            'metrics-server-22.12-2.tgz',
            'cert-manager-22.12-8.tgz',
            'platform-integ-apps-22.12-71.tgz',
            'istio-22.12-1.tgz'
        ]
        mock_directory.return_value.__enter__.return_value = FAKE_PATH
        mock_path_exists.return_value = True
        fake_yml = FakeYaml()
        mock_io.return_value.__enter__.side_effect = [
            fake_yml.get_fake_content(),
            fake_yml.get_fake_content(),
            fake_yml.get_fake_content()
        ]
        app_metadata.load_metadata_of_apps(fake_metadata)
        self.assertEqual(mock_checksum.call_count, 3)

    @mock.patch('sysinv.db.api.get_instance')
    @mock.patch('sysinv.api.controllers.v1.kube_app.KubeAppHelper')
    @mock.patch.object(os, 'listdir')
    @mock.patch('sysinv.common.utils.TempDirectory')
    @mock.patch('sysinv.common.utils.extract_tarfile')
    @mock.patch('sysinv.common.utils.verify_checksum')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(io, 'open')
    @mock.patch('sysinv.conductor.kube_app.AppOperator.update_and_process_app_metadata')
    def test_if_load_metadata_skip_app_if_tarball_extraction_fails(
        self,
        mock_operator,
        mock_io,
        mock_path_exists,
        mock_checksum,
        mock_extract,
        mock_directory,
        mock_app_bundle,
        mock_helper,
        mock_dbapi
    ):
        fake_metadata = {
            'apps': {},
            'platform_managed_apps_list': {},
            'desired_states': {},
            'ordered_apps': []
        }
        mock_dbapi.return_value = FakeDbapi()
        mock_app_bundle.return_value = [
            'oidc-auth-apps-22.12-6.tgz',
            'metrics-server-22.12-2.tgz',
            'cert-manager-22.12-8.tgz',
            'platform-integ-apps-22.12-71.tgz',
            'istio-22.12-1.tgz'
        ]
        mock_directory.return_value.__enter__.return_value = FAKE_PATH
        mock_path_exists.return_value = True
        fake_yml = FakeYaml()
        mock_io.return_value.__enter__.side_effect = [
            fake_yml.get_fake_content(),
            fake_yml.get_fake_content(),
            fake_yml.get_fake_content()
        ]
        fake_helper = FakeHelper(mock_dbapi)
        fake_helper.raise_exception_once = True
        mock_helper.return_value = fake_helper
        app_metadata.load_metadata_of_apps(fake_metadata)
        self.assertEqual(fake_helper.success_count, 2)

    @mock.patch('sysinv.db.api.get_instance')
    @mock.patch('sysinv.api.controllers.v1.kube_app.KubeAppHelper')
    @mock.patch.object(os, 'listdir')
    @mock.patch('sysinv.common.utils.TempDirectory')
    @mock.patch('sysinv.common.utils.extract_tarfile')
    @mock.patch('sysinv.common.utils.verify_checksum')
    @mock.patch.object(os.path, 'exists')
    @mock.patch.object(io, 'open')
    @mock.patch('sysinv.conductor.kube_app.AppOperator.update_and_process_app_metadata')
    def test_update_and_process_app_metadata_is_called_with_right_parameters(
        self,
        mock_operator,
        mock_io,
        mock_path_exists,
        mock_checksum,
        mock_extract,
        mock_directory,
        mock_app_bundle,
        mock_helper,
        mock_dbapi
    ):
        fake_metadata = {
            'apps': {},
            'platform_managed_apps_list': {},
            'desired_states': {},
            'ordered_apps': []
        }
        mock_dbapi.return_value = FakeDbapi()
        mock_helper.return_value = FakeHelper(mock_dbapi)
        mock_app_bundle.return_value = [
            'oidc-auth-apps-22.12-6.tgz',
            'metrics-server-22.12-2.tgz',
            'cert-manager-22.12-8.tgz',
            'platform-integ-apps-22.12-71.tgz',
            'istio-22.12-1.tgz'
        ]
        mock_directory.return_value.__enter__.return_value = FAKE_PATH
        mock_path_exists.return_value = True
        fake_yml = FakeYaml()
        mock_io.return_value.__enter__.side_effect = [
            fake_yml.get_fake_content(),
            fake_yml.get_fake_content(),
            fake_yml.get_fake_content()
        ]
        app_metadata.load_metadata_of_apps(fake_metadata)
        expected_metric_metadata = {
            'maintain_user_overrides': True,
            'app_name': 'metrics-server',
            'app_version': '1.1.1',
            'helm_repo': 'stx-platform'
        }
        expected_cert_metadata = {
            'maintain_user_overrides': True,
            'app_name': 'cert-manager',
            'app_version': '1.3.1',
            'helm_repo': 'stx-platform'
        }
        expected_istio_metadata = {
            'maintain_user_overrides': True,
            'app_name': 'istio',
            'app_version': '2.1.1',
            'helm_repo': 'stx-platform'
        }
        mock_operator.assert_has_calls(
            [
                mock.call(fake_metadata, 'metrics-server', expected_metric_metadata),
                mock.call(fake_metadata, 'cert-manager', expected_cert_metadata),
                mock.call(fake_metadata, 'istio', expected_istio_metadata)
            ], any_order=True
        )
        self.assertEqual(mock_operator.call_count, 3)
