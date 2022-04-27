#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API / service_parameter / methods.
"""

from six.moves import http_client

from oslo_utils import uuidutils
from sysinv.common import constants

from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class ApiServiceParameterTestCaseMixin(object):
    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test',
                   'Content-Type': 'application/json',
                   'Accept': 'application/json'}

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/service_parameter'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'parameters'

    # expected_api_fields are attributes that should be populated by
    # an API query
    expected_api_fields = ['uuid',
                           'service',
                           'section',
                           'name',
                           'value',
                           'resource',
                           'personality'
                           ]

    required_post_fields = [
        'service',
        'section',
        'parameters'
        'resource',
        'personality'
    ]

    # hidden_api_fields are attributes that should not be populated by
    # an API query
    hidden_api_fields = []

    service_parameter_data = [
        {
            'service': constants.SERVICE_TYPE_HTTP,
            'section': constants.SERVICE_PARAM_SECTION_HTTP_CONFIG,
            'name': constants.SERVICE_PARAM_HTTP_PORT_HTTP,
            'value': str(constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT)
        },
        {
            'service': constants.SERVICE_TYPE_HTTP,
            'section': constants.SERVICE_PARAM_SECTION_HTTP_CONFIG,
            'name': constants.SERVICE_PARAM_HTTP_PORT_HTTPS,
            'value': str(constants.SERVICE_PARAM_HTTP_PORT_HTTPS_DEFAULT)
        },
        {
            'service': constants.SERVICE_TYPE_KUBERNETES,
            'section': constants.SERVICE_PARAM_SECTION_KUBERNETES_CERTIFICATES,
            'name': constants.SERVICE_PARAM_NAME_KUBERNETES_API_SAN_LIST,
            'value': 'localurl'
        },
        {
            'service': constants.SERVICE_TYPE_KUBERNETES,
            'section': constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER,
            'name': constants.SERVICE_PARAM_NAME_OIDC_USERNAME_CLAIM,
            'value': 'wad'
        },
        {
            'service': constants.SERVICE_TYPE_KUBERNETES,
            'section': constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER,
            'name': constants.SERVICE_PARAM_NAME_OIDC_ISSUER_URL,
            'value': 'https://10.10.10.3:30556/dex'
        },
        {
            'service': constants.SERVICE_TYPE_KUBERNETES,
            'section': constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER,
            'name': constants.SERVICE_PARAM_NAME_OIDC_CLIENT_ID,
            'value': 'wad'
        },
        {
            'service': constants.SERVICE_TYPE_KUBERNETES,
            'section': constants.SERVICE_PARAM_SECTION_KUBERNETES_APISERVER,
            'name': constants.SERVICE_PARAM_NAME_OIDC_GROUPS_CLAIM,
            'value': 'wad'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_PROCESS_SIZE_MAX,
            'value': '2G'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_EXTERNAL_SIZE_MAX,
            'value': '0'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_MAX_USE,
            'value': '0.02T'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_KEEP_FREE,
            'value': '1G'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_PROCESS_SIZE_MAX,
            'value': '4MB'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_PROCESS_SIZE_MAX,
            'value': '4.0MB'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_EXTERNAL_SIZE_MAX,
            'value': '4'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_MAX_USE,
            'value': '4g'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_MAX_USE,
            'value': '-4'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_KEEP_FREE,
            'value': '4,0G'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_PROCESS_SIZE_MAX,
            'value': ''
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_EXTERNAL_SIZE_MAX,
            'value': ''
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_MAX_USE,
            'value': ''
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_KEEP_FREE,
            'value': ''
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_PROCESS_SIZE_MAX,
            'value': '-1G'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_EXTERNAL_SIZE_MAX,
            'value': '-1G'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_MAX_USE,
            'value': '-1G'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_KEEP_FREE,
            'value': '-1G'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_KEEP_FREE,
            'value': '1M'
        },
        {
            'service': constants.SERVICE_TYPE_PLATFORM,
            'section': constants.SERVICE_PARAM_SECTION_PLATFORM_COREDUMP,
            'name': constants.SERVICE_PARAM_NAME_PLATFORM_KEEP_FREE,
            'value': '0'
        }
    ]

    service_parameter_wildcard = {
        'service': constants.SERVICE_TYPE_PTP,
        'section': constants.SERVICE_PARAM_SECTION_PTP_GLOBAL,
        'name': 'network_transport',
        'value': 'L2'
    }

    def setUp(self):
        super(ApiServiceParameterTestCaseMixin, self).setUp()

    def get_single_url(self, uuid):
        return '%s/%s' % (self.API_PREFIX, uuid)

    # These methods have generic names and are overridden here
    # Future activity: Redo the subclasses to use mixins
    def assert_fields(self, api_object):
        # check the uuid is a uuid
        assert(uuidutils.is_uuid_like(api_object['uuid']))

        # Verify that expected attributes are returned
        for field in self.expected_api_fields:
            self.assertIn(field, api_object)

        # Verify that hidden attributes are not returned
        for field in self.hidden_api_fields:
            self.assertNotIn(field, api_object)

    def _create_db_object(self, parameter_data=None):
        if not parameter_data:
            parameter_data = self.service_parameter_data[0]
        return dbutils.create_test_service_parameter(**parameter_data)

    def _create_db_objects(self, data_set=None):
        if not data_set:
            data_set = self.service_parameter_data
        data = []
        for parameter_data in data_set:
            data.append(self._create_db_object(parameter_data))

        return data

    def get_one(self, uuid, expect_errors=False, error_message=None):
        response = self.get_json(self.get_single_url(uuid), headers=self.API_HEADERS)
        self.validate_response(response, expect_errors, error_message, json_response=True)
        return response

    def get_list(self):
        response = self.get_json(self.API_PREFIX, headers=self.API_HEADERS)
        return response[self.RESULT_KEY]

    def patch(self, uuid, data, expect_errors=False, error_message=None):
        response = self.patch_dict(self.get_single_url(uuid),
                                   data=data,
                                   expect_errors=expect_errors,
                                   headers=self.API_HEADERS)
        self.validate_response(response, expect_errors, error_message)
        if expect_errors:
            return response
        else:
            return response.json

    def post(self, data, expect_errors=False, error_message=None):
        formatted_data = self.format_data(data)
        response = self.post_json(self.API_PREFIX,
                                  params=formatted_data,
                                  expect_errors=expect_errors,
                                  headers=self.API_HEADERS)

        self.validate_response(response, expect_errors, error_message)
        if expect_errors:
            return response
        else:
            return response.json[self.RESULT_KEY][0]

    def apply(self, service, expect_errors=False):
        data = {}
        data['service'] = service
        response = self.post_json(self.API_PREFIX + "/apply",
                                  params=data,
                                  expect_errors=expect_errors,
                                  headers=self.API_HEADERS)
        return response

    def validate_response(self, response, expect_errors, error_message, json_response=False):
        if expect_errors:
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            if error_message:
                self.assertIn(error_message, response.json['error_message'])
        elif not json_response:
            self.assertEqual(http_client.OK, response.status_int)

    def validate_data(self, input_data, response_data):
        self.assert_fields(response_data)
        for key, value in input_data.items():
            if key in self.expected_api_fields:
                self.assertEqual(value, response_data[key])

    def format_data(self, data):
        formatted_data = dict(data)
        formatted_data.update({'parameters': {data['name']: data['value']}})
        for field in self.required_post_fields:
            if field not in formatted_data:
                formatted_data[field] = None

        return formatted_data


class ApiServiceParameterPostTestSuiteMixin(ApiServiceParameterTestCaseMixin):

    def setUp(self):
        super(ApiServiceParameterPostTestSuiteMixin, self).setUp()

    def test_create_success(self):
        # Test creation of object
        post_object = self.service_parameter_data[0]
        response = self.post(post_object)
        self.validate_data(post_object, response)

    def test_create_invalid_service(self):
        # Test creation with an invalid service name
        post_object = dict(self.service_parameter_data[0])
        post_object.update({'service': 'not_valid'})
        self.post(post_object, expect_errors=True, error_message="Invalid service name")

    def test_create_wildcard_deprecated(self):
        # Test creation of a section that allows wildcard parameter names
        post_object = self.service_parameter_wildcard
        self.post(post_object,
                  expect_errors=True,
                  error_message="ptp service is deprecated")

    def test_apply_kubernetes_apiserver_oidc_parameters_semantic(self):
        # applying kubernetes service parameters with no OIDC parameters
        # this is a valid configuration
        response = self.apply('kubernetes')
        self.assertEqual(http_client.NO_CONTENT, response.status_int)

        # set SERVICE_PARAM_NAME_OIDC_USERNAME_CLAIM. this is an invalid config
        # valid configs are (none)
        # (oidc_issuer_url, oidc_client_id, oidc_username_claim)
        # (the previous 3 plus oidc_groups_claim)
        post_object = self.service_parameter_data[3]
        response = self.post(post_object)
        self.validate_data(post_object, response)
        response = self.apply('kubernetes', expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)

        # the other 2 valid configs
        post_object = self.service_parameter_data[4]
        response = self.post(post_object)
        self.validate_data(post_object, response)
        post_object = self.service_parameter_data[5]
        response = self.post(post_object)
        self.validate_data(post_object, response)
        response = self.apply('kubernetes')
        self.assertEqual(http_client.NO_CONTENT, response.status_int)

        post_object = self.service_parameter_data[6]
        response = self.post(post_object)
        self.validate_data(post_object, response)
        response = self.apply('kubernetes')
        self.assertEqual(http_client.NO_CONTENT, response.status_int)

    def test_coredump_values_and_formats(self):
        # test invalid value format
        for param in range(11, 17):
            post_object = self.service_parameter_data[param]
            self.post(post_object, expect_errors=True, error_message="Parameter '" +
                self.service_parameter_data[param]['name'] + "' has invalid value format.")

        # test empty value
        for param in range(17, 21):
            post_object = self.service_parameter_data[param]
            self.post(post_object, expect_errors=True,
                error_message="The service parameter value is mandatory")

        # test minimum value greater than or equal to 0
        for param in range(21, 24):
            post_object = self.service_parameter_data[param]
            self.post(post_object, expect_errors=True, error_message="Parameter '" +
                self.service_parameter_data[param]['name'] +
                "' must be greater than or equal to 0.")

        # test minimum value greater than or equal to 1G
        for param in range(24, 27):
            post_object = self.service_parameter_data[param]
            self.post(post_object, expect_errors=True, error_message="Parameter '" +
                self.service_parameter_data[param]['name'] +
                "' must be greater than or equal to 1G.")

        # test valid values
        for param in range(7, 11):
            post_object = self.service_parameter_data[param]
            response = self.post(post_object)
            self.validate_data(post_object, response)


class ApiServiceParameterDeleteTestSuiteMixin(ApiServiceParameterTestCaseMixin):
    """ Tests deletion.
        Typically delete APIs return NO CONTENT.
        python2 and python3 libraries may return different
        content_type (None, or empty json) when NO_CONTENT returned.
    """

    def setUp(self):
        super(ApiServiceParameterDeleteTestSuiteMixin, self).setUp()
        self.delete_object = self._create_db_object()

    # Delete an object and ensure it is removed
    def test_delete(self):
        # Delete the API object
        uuid = self.delete_object.uuid
        response = self.delete(self.get_single_url(uuid),
                               headers=self.API_HEADERS)

        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Verify the object is no longer returned
        results = self.get_list()
        returned_uuids = (result.uuid for result in results)
        self.assertNotIn(uuid, returned_uuids)


class ApiServiceParameterListTestSuiteMixin(ApiServiceParameterTestCaseMixin):
    """ list operations """

    def test_empty_list(self):
        results = self.get_list()
        self.assertEqual([], results)

    def test_single_entry(self):
        # create a single object
        single_object = self._create_db_object()
        uuid = single_object.uuid
        response = self.get_json(self.get_single_url(uuid))
        self.validate_data(single_object, response)

    def test_many_entries_in_list(self):
        db_obj_list = self._create_db_objects()

        response = self.get_list()
        # Verify that the input data is found in the result
        response_map = {}
        for api_object in response:
            response_map[api_object['uuid']] = api_object
        for db_oject in db_obj_list:
            self.validate_data(db_oject, response_map[db_oject.uuid])


class ApiServiceParameterPatchTestSuiteMixin(ApiServiceParameterTestCaseMixin):

    def setUp(self):
        super(ApiServiceParameterPatchTestSuiteMixin, self).setUp()
        self.patch_object = self._create_db_object()

    def test_patch_valid(self):
        # Update value of patchable field
        new_data = {'value': '8077'}
        response = self.patch(self.patch_object.uuid, new_data)
        # Verify that the attribute was updated
        self.patch_object.update(new_data)
        self.validate_data(self.patch_object, response)

    def test_patch_invalid_value(self):
        # Pass a value that fails a semantic check when patched by the API
        new_data = {'value': 'a_string'}
        self.patch(self.patch_object.uuid, new_data, expect_errors=True,
                   error_message="must be an integer value")


class PlatformIPv4ControllerApiServiceParameterDeleteTestCase(ApiServiceParameterDeleteTestSuiteMixin,
                                                              base.FunctionalTest,
                                                              dbbase.ProvisionedControllerHostTestCase):
    pass


class PlatformIPv4ControllerApiServiceParameterListTestCase(ApiServiceParameterListTestSuiteMixin,
                                                            base.FunctionalTest,
                                                            dbbase.ProvisionedControllerHostTestCase):
    pass


class PlatformIPv4ControllerApiServiceParameterPostTestCase(ApiServiceParameterPostTestSuiteMixin,
                                                            base.FunctionalTest,
                                                            dbbase.ProvisionedControllerHostTestCase):
    pass


class PlatformIPv4ControllerApiServiceParameterPatchTestCase(ApiServiceParameterPatchTestSuiteMixin,
                                                             base.FunctionalTest,
                                                             dbbase.ProvisionedControllerHostTestCase):
    pass
