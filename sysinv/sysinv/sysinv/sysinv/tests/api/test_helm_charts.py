#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the helm chart methods.
"""

import mock
from six.moves import http_client
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class FakeConductorAPI(object):

    def __init__(self):
        self.app_has_system_plugins = mock.MagicMock()
        self.get_helm_application_namespaces = mock.MagicMock()
        self.get_active_helm_applications = mock.MagicMock()
        self.get_helm_chart_overrides = mock.MagicMock()
        self.merge_overrides = mock.MagicMock()


class FakeException(Exception):
        pass


class ApiHelmChartTestCaseMixin(base.FunctionalTest,
                                dbbase.ControllerHostTestCase):

    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/helm_charts'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'charts'

    # expected_api_fields are attributes that should be populated by
    # an API query
    expected_api_fields = ['name',
                           'namespace',
                           'user_overrides',
                           'system_overrides',
                           'app_id']

    # hidden_api_fields are attributes that should not be populated by
    # an API query
    hidden_api_fields = ['app_id']

    def setUp(self):
        super(ApiHelmChartTestCaseMixin, self).setUp()
        self.fake_conductor_api = FakeConductorAPI()
        p = mock.patch('sysinv.conductor.rpcapiproxy.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)
        self.helm_app = self._create_db_app()
        self.helm_override_obj_one = self._create_db_overrides(
                                appid=self.helm_app.id,
                                chart_name='ceph-pools-audit',
                                chart_namespace='kube-system',
                                system_override_attr={"enabled": True},
                                user_override="global:\n  replicas: \"2\"\n")
        self.helm_override_obj_two = self._create_db_overrides(
                                appid=self.helm_app.id,
                                chart_name='rbd-provisioner',
                                chart_namespace='kube-system',
                                system_override_attr={"enabled": False},
                                user_override="global:\n  replicas: \"3\"\n")
        self.fake_helm_apps = self.fake_conductor_api.get_active_helm_applications
        self.fake_ns = self.fake_conductor_api.get_helm_application_namespaces
        self.fake_override = self.fake_conductor_api.get_helm_chart_overrides
        self.fake_merge_overrides = self.fake_conductor_api.merge_overrides
        self.fake_system_app = self.fake_conductor_api.app_has_system_plugins

    def exception_helm_override(self):
        print('Raised a fake exception')
        raise FakeException

    def get_single_url_helm_override_list(self, app_name):
        return '%s/?app_name=%s' % (self.API_PREFIX, app_name)

    def get_single_url_helm_override(self, app_name, chart_name, namespace):
        return '%s/%s?name=%s&namespace=%s' % (self.API_PREFIX, app_name,
                                               chart_name, namespace)

    def _create_db_app(self, obj_id=None):
        return dbutils.create_test_app(id=obj_id, name='platform-integ-apps',
                                app_version='1.0-8',
                                manifest_name='platform-integration-manifest',
                                manifest_file='manifest.yaml',
                                status='applied',
                                active=True)

    def _create_db_overrides(self, appid, chart_name, chart_namespace,
                             system_override_attr, user_override, obj_id=None):
        return dbutils.create_test_helm_overrides(id=obj_id,
                                      app_id=appid,
                                      name=chart_name,
                                      namespace=chart_namespace,
                                      system_overrides=system_override_attr,
                                      user_overrides=user_override)


class ApiHelmChartListTestSuiteMixin(ApiHelmChartTestCaseMixin):
    """ Helm Override List GET operations
    """
    def setUp(self):
        super(ApiHelmChartListTestSuiteMixin, self).setUp()

    def test_fetch_success_helm_override_list(self):
        # Return a namespace dictionary
        self.fake_ns.return_value = {'ceph-pools-audit': ['kube-system'],
                                     'rbd-provisioner': ['kube-system']}
        url = self.get_single_url_helm_override_list('platform-integ-apps')
        response = self.get_json(url)

        # Verify the values of the response with the object values in database
        self.assertEqual(len(response[self.RESULT_KEY]), 2)

        # py36 preserves insertion order, whereas py27 does not
        result_one = response[self.RESULT_KEY][0]
        result_two = response[self.RESULT_KEY][1]
        self.assertTrue(result_one['name'] == self.helm_override_obj_one.name or
                        result_two['name'] == self.helm_override_obj_one.name)
        self.assertTrue(result_one['name'] == self.helm_override_obj_two.name or
                        result_two['name'] == self.helm_override_obj_two.name)
        if(result_one['name'] == self.helm_override_obj_one.name):
            self.assertTrue(result_one['enabled'] == [True])
            self.assertTrue(result_two['enabled'] == [False])
        else:
            self.assertTrue(result_two['enabled'] == [True])
            self.assertTrue(result_one['enabled'] == [False])

    def test_fetch_helm_override_list_exception(self):
        # Raise an exception while finding helm charts for an application
        self.fake_ns.side_effect = self.exception_helm_override
        url = self.get_single_url_helm_override_list('platform-integ-apps')
        response = self.get_json(url, expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Unable to get the helm charts for application "
                      "platform-integ-apps",
                      response.json['error_message'])

    def test_fetch_helm_override_list_invalid_value(self):
        self.fake_ns.return_value = {'ceph-pools-audit': ['kube-system']}
        url = self.get_single_url_helm_override_list('invalid_app_name')
        # Pass an invalid value for app name
        response = self.get_json(url, expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Application invalid_app_name not found.",
                      response.json['error_message'])


class ApiHelmChartShowTestSuiteMixin(ApiHelmChartTestCaseMixin):
    """ Helm Override Show GET operations
    """
    def setUp(self):
        super(ApiHelmChartShowTestSuiteMixin, self).setUp()

    def test_no_system_override(self):
        self.fake_system_app.return_value = False
        self.fake_merge_overrides.return_value = {}

        url = self.get_single_url_helm_override('platform-integ-apps',
                                    'ceph-pools-audit', 'kube-system')
        response = self.get_json(url)

        # Verify the values of the response with the values stored in database
        self.assertEqual(response['name'], self.helm_override_obj_one.name)
        self.assertIn(self.helm_override_obj_one.namespace,
                      response['namespace'])

    def test_fetch_helm_override_show_invalid_application(self):
        url = self.get_single_url_helm_override('invalid_value',
                        'ceph-pools-audit', 'kube-system')
        response = self.get_json(url, expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Application invalid_value not found.",
                      response.json['error_message'])

    def test_fetch_helm_override_show_invalid_helm_chart(self):
        self.fake_system_app.return_value = False

        url = self.get_single_url_helm_override('platform-integ-apps',
                        'invalid_value', 'kube-system')
        response = self.get_json(url, expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Unable to get the helm chart attributes for chart "
                      "invalid_value under Namespace kube-system",
                      response.json['error_message'])

    def test_fetch_helm_override_show_invalid_namespace(self):
        self.fake_system_app.return_value = False
        url = self.get_single_url_helm_override('platform-integ-apps',
                                                'ceph-pools-audit',
                                                'invalid_value')
        response = self.get_json(url, expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Unable to get the helm chart attributes for chart "
                      "ceph-pools-audit under Namespace invalid_value",
                      response.json['error_message'])

    def test_fetch_helm_override_show_empty_name(self):
        url = self.get_single_url_helm_override('platform-integ-apps',
                                                '',
                                                'kube-system')
        response = self.get_json(url, expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Name must be specified.",
                      response.json['error_message'])

    def test_fetch_helm_override_show_empty_namespace(self):
        url = self.get_single_url_helm_override('platform-integ-apps',
                                                'ceph-pools-audit',
                                                '')
        response = self.get_json(url, expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Namespace must be specified.",
                      response.json['error_message'])

    def test_fetch_helm_override_no_system_overrides_fetched(self):
        # Return system apps
        self.fake_helm_apps.return_value = ['platform-integ-apps']

        url = self.get_single_url_helm_override('platform-integ-apps',
                        'ceph-pools-audit', 'kube-system')
        response = self.get_json(url, expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Unable to get the helm chart overrides for chart "
                      "ceph-pools-audit under Namespace kube-system",
                      response.json['error_message'])

    def test_fetch_success_helm_override_show(self):
        # Return system apps
        self.fake_helm_apps.return_value = ['platform-integ-apps']
        # Return helm chart overrides
        self.fake_override.return_value = {"enabled": True}
        self.fake_merge_overrides.return_value = {}

        url = self.get_single_url_helm_override('platform-integ-apps',
                        'ceph-pools-audit', 'kube-system')
        response = self.get_json(url, expect_errors=True)
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.content_type, 'application/json')

        # Verify the values of the response with the values in database
        self.assertEqual(response.json['name'],
                         self.helm_override_obj_one.name)
        self.assertEqual(response.json['namespace'],
                         self.helm_override_obj_one.namespace)
        self.assertEqual(response.json['attributes'],
                         "enabled: true\n")
        self.assertEqual(response.json['system_overrides'],
                         "{enabled: true}\n")
        self.assertEqual(response.json['user_overrides'],
                         "global:\n  replicas: \"2\"\n")
        self.assertEqual(response.json['combined_overrides'], {})


class ApiHelmChartDeleteTestSuiteMixin(ApiHelmChartTestCaseMixin):
    """ Helm Override delete operations
    """
    def setUp(self):
        super(ApiHelmChartDeleteTestSuiteMixin, self).setUp()

    # Test that a valid DELETE operation is successful
    def test_delete_helm_override_success(self):
        self.fake_system_app.return_value = False
        self.fake_merge_overrides.return_value = {}

        # Verify that user override exists initially
        url = self.get_single_url_helm_override('platform-integ-apps',
                                 'rbd-provisioner', 'kube-system')
        response = self.get_json(url, expect_errors=True)
        self.assertEqual(response.json['user_overrides'],
                         'global:\n  replicas: \"3\"\n')

        # Perform delete operation
        response = self.delete(url, expect_errors=True)

        # Verify the expected API response for the delete
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify that the user override is deleted
        response = self.get_json(url, expect_errors=True)
        self.assertEqual(response.json['user_overrides'], None)

    def test_delete_helm_override_empty_name(self):
        url = self.get_single_url_helm_override('platform-integ-apps',
                                                '',
                                                'kube-system')
        response = self.delete(url, expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Name must be specified.", response.json['error_message'])

    def test_delete_helm_override_empty_namespace(self):
        url = self.get_single_url_helm_override('platform-integ-apps',
                                                'ceph-pools-audit',
                                                '')
        response = self.delete(url, expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Namespace must be specified.",
                      response.json['error_message'])

    def test_delete_helm_override_invalid_application(self):
        url = self.get_single_url_helm_override('invalid_application',
                        'ceph-pools-audit', 'kube-system')
        response = self.delete(url, expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Application invalid_application not found.",
                      response.json['error_message'])

    def test_delete_helm_override_invalid_helm_override(self):
        url = self.get_single_url_helm_override('platform-integ-apps',
                        'invalid_name', 'invalid_namespace')
        response = self.delete(url, expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.NO_CONTENT)


class ApiHelmChartPatchTestSuiteMixin(ApiHelmChartTestCaseMixin):
    """ Helm Override patch operations
    """

    def setUp(self):
        super(ApiHelmChartPatchTestSuiteMixin, self).setUp()

    def test_success_helm_override_patch(self):
        # Return system apps
        self.fake_helm_apps.return_value = ['platform-integ-apps']
        # Return helm chart overrides
        self.fake_override.return_value = {"enabled": True}
        self.fake_merge_overrides.return_value = "global:\n  replicas: \"2\"\n"

        # Pass a non existant field to be patched by the API
        response = self.patch_json(self.get_single_url_helm_override(
                                    'platform-integ-apps',
                                    'rbd-provisioner', 'kube-system'),
                                    {'attributes': {},
                                    'flag': 'reuse',
                                    'values': {'files': [],
                                    'set': ['global.replicas=2']}},
                                    headers=self.API_HEADERS,
                                    expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the helm override was updated
        url = self.get_single_url_helm_override('platform-integ-apps',
                                 'rbd-provisioner', 'kube-system')
        response = self.get_json(url, expect_errors=True)
        self.assertEqual(response.json['user_overrides'],
                         'global:\n  replicas: \"2\"\n')

    def test_helm_override_patch_attribute(self):
        # Return system apps
        self.fake_helm_apps.return_value = ['platform-integ-apps']
        # Return helm chart overrides
        self.fake_override.return_value = {"enabled": False}
        self.fake_merge_overrides.return_value = "global:\n  replicas: \"2\"\n"

        # Pass a non existant field to be patched by the API
        url = self.get_single_url_helm_override('platform-integ-apps',
                                    'rbd-provisioner', 'kube-system')
        response = self.patch_json(url,
                                   {'attributes': {"enabled": "false"},
                                   'flag': '',
                                   'values': {}},
                                   headers=self.API_HEADERS,
                                   expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the helm chart attribute was updated
        response = self.get_json(url, expect_errors=True)
        self.assertEqual(response.json['attributes'], 'enabled: false\n')

    def test_patch_invalid_application(self):
        url = self.get_single_url_helm_override('invalid_app_name',
                                   'rbd-provisioner', 'kube-system')
        response = self.patch_json(url,
                                   {'attributes': {},
                                   'flag': 'reuse',
                                   'values': {'files': [],
                                   'set': ['global.replicas=2']}},
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Application invalid_app_name not found.",
                      response.json['error_message'])

    def test_patch_empty_name(self):
        url = self.get_single_url_helm_override('platform-integ-apps',
                                                '',
                                                'kube-system')
        response = self.patch_json(url,
                                   {'attributes': {},
                                    'flag': 'reuse',
                                    'values': {'files': [],
                                    'set': ['global.replicas=2']}},
                                    headers=self.API_HEADERS,
                                    expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Name must be specified.", response.json['error_message'])

    def test_patch_empty_namespace(self):
        url = self.get_single_url_helm_override('platform-integ-apps',
                                                'rbd-provisioner',
                                                '')
        response = self.patch_json(url,
                                   {'attributes': {},
                                   'flag': 'reuse',
                                   'values': {'files': [],
                                   'set': ['global.replicas=2']}},
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Namespace must be specified.",
                      response.json['error_message'])

    def test_patch_invalid_attribute(self):
        url = self.get_single_url_helm_override('platform-integ-apps',
                                   'rbd-provisioner', 'kube-system')
        response = self.patch_json(url,
                                   {'attributes': {"invalid_attr": "false"},
                                   'flag': '',
                                   'values': {}},
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Invalid chart attribute: invalid_attr must "
                      "be one of [enabled]",
                      response.json['error_message'])

    def test_patch_invalid_flag(self):
        url = self.get_single_url_helm_override('platform-integ-apps',
                                    'rbd-provisioner', 'kube-system')
        response = self.patch_json(url,
                                   {'attributes': {},
                                    'flag': 'invalid_flag',
                                    'values': {'files': [],
                                    'set': ['global.replicas=2']}},
                                    headers=self.API_HEADERS,
                                    expect_errors=True)

        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Invalid flag: invalid_flag must be either 'reuse' "
                      "or 'reset'.",
                       response.json['error_message'])

    def test_patch_invalid_helm_override(self):
        url = self.get_single_url_helm_override('platform-integ-apps',
                                   'invalid_name', 'invalid_namespace')
        response = self.patch_json(url,
                                   {'attributes': {},
                                    'flag': 'reuse',
                                    'values': {'files': [],
                                    'set': ['global.replicas=2']}},
                                    headers=self.API_HEADERS,
                                    expect_errors=True)
        self.fake_system_app.return_value = False
        self.fake_merge_overrides.return_value = {}

        response = self.get_json(url, expect_errors=True)
        self.assertEqual(response.status_code, http_client.OK)
        # Verify the values of the response with the values in database
        self.assertEqual(response.json['name'], 'invalid_name')
        self.assertIn('invalid_namespace', response.json['namespace'])

    def test_patch_multiple_values(self):
        url = self.get_single_url_helm_override('platform-integ-apps',
                                    'rbd-provisioner', 'kube-system')
        response = self.patch_json(url,
                                    {'attributes': {},
                                    'flag': 'reuse',
                                    'values': {'files': [],
                                    'set': ['global.replicas=2,'
                                    'global.defaultStorageClass=generic']}},
                                    headers=self.API_HEADERS,
                                    expect_errors=True)
        # Verify appropriate exception is raised
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Invalid input: One (or more) set overrides contains "
                      "multiple values. Consider using --values "
                      "option instead.", response.json['error_message'])

    def test_success_helm_override_patch_reset_flag(self):
        # Return system apps
        self.fake_helm_apps.return_value = ['platform-integ-apps']
        # Return helm chart overrides
        self.fake_override.return_value = {"enabled": True}
        self.fake_merge_overrides.return_value = "global:\n  replicas: \"2\"\n"
        url = self.get_single_url_helm_override('platform-integ-apps',
                                                'rbd-provisioner',
                                                'kube-system')
        # Pass a non existant field to be patched by the API
        response = self.patch_json(url,
                                   {'attributes': {},
                                    'flag': 'reset',
                                    'values': {}},
                                    headers=self.API_HEADERS,
                                    expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Verify that the helm override was updated
        response = self.get_json(url, expect_errors=True)
        self.assertEqual(response.json['user_overrides'], None)
