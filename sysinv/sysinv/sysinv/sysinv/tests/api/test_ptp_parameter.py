# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from six.moves import http_client
from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class BasePtpParameterTestCase(base.FunctionalTest, dbbase.BaseHostTestCase):
    # Generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # Prefix for the URL
    API_PREFIX = '/ptp_parameters'

    # Python table key for the list of results
    RESULT_KEY = 'ptp_parameters'

    # Field that is known to exist for inputs and outputs
    COMMON_FIELD = 'name'

    # Can perform API operations on this object at a sublevel of PTP instances
    PTP_INSTANCE_PREFIX = '/ptp_instances'

    # Can perform API operations on this object at a sublevel of PTP interfaces
    PTP_INTERFACE_PREFIX = '/ptp_interfaces'

    def setUp(self):
        super(BasePtpParameterTestCase, self).setUp()
        self.controller = self._create_test_host(constants.CONTROLLER)
        self.ptp_instances = self._create_test_ptp_instance()
        self.ptp_interfaces = self._create_test_ptp_interface(
            self.ptp_instances)

    def get_single_url(self, ptp_parameter_uuid):
        return '%s/%s' % (self.API_PREFIX, ptp_parameter_uuid)

    def get_instance_scoped_url(self, ptp_instance_uuid):
        return '%s/%s%s' % (self.PTP_INSTANCE_PREFIX, ptp_instance_uuid,
                            self.API_PREFIX)

    def get_interface_scoped_url(self, ptp_interface_uuid):
        return '%s/%s%s' % (self.PTP_INTERFACE_PREFIX, ptp_interface_uuid,
                            self.API_PREFIX)

    def get_instance_url(self, ptp_instance_uuid):
        return '%s/%s' % (self.PTP_INSTANCE_PREFIX, ptp_instance_uuid)

    def get_interface_url(self, ptp_interface_uuid):
        return '%s/%s' % (self.PTP_INTERFACE_PREFIX, ptp_interface_uuid)

    def get_post_object(self, name='test_parameter', value='test_value'):
        return dbutils.get_test_ptp_parameter(name=name, value=value)


class TestCreatePtpParameter(BasePtpParameterTestCase):
    name = 'test-param'
    value = 'test-value'

    def setUp(self):
        super(TestCreatePtpParameter, self).setUp()
        dbutils.create_test_ptp_parameter(name=self.name, value=self.value)

    def _create_ptp_parameter_success(self, name, value):
        ptp_parameter_db = self.get_post_object(name=name, value=value)
        response = self.post_json(self.API_PREFIX, ptp_parameter_db,
                                  headers=self.API_HEADERS)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json[self.COMMON_FIELD],
                         ptp_parameter_db[self.COMMON_FIELD])

    def _create_ptp_parameter_failed(self, name, value, status_code,
                                     error_message):
        ptp_parameter_db = self.get_post_object(name=name, value=value)
        response = self.post_json(self.API_PREFIX, ptp_parameter_db,
                                  headers=self.API_HEADERS, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, status_code)
        self.assertIn(error_message, response.json['error_message'])

    def test_create_ptp_parameter_ok(self):
        self._create_ptp_parameter_success(
            name='some-param', value='some-value')

    def test_create_ptp_parameter_synonymous_ok(self):
        self._create_ptp_parameter_success(
            name=self.name, value='another-value')


class TestGetPtpParameter(BasePtpParameterTestCase):
    name = 'test-param'
    value = 'test-value'
    type = constants.PTP_PARAMETER_OWNER_INSTANCE
    parameter_uuid = None
    owner_uuid = None

    def setUp(self):
        super(TestGetPtpParameter, self).setUp()

    def test_get_ptp_parameter_found(self):
        ptp_parameter = dbutils.create_test_ptp_parameter(
            name='fake-param', value='fake-value')
        uuid = ptp_parameter['uuid']
        response = self.get_json(self.get_single_url(uuid))
        self.assertIn(self.COMMON_FIELD, response)

    def test_get_ptp_parameter_not_found(self):
        fake_uuid = 'f4c56ddf-aef3-46ed-b9aa-126a1faafd40'
        error_message = 'No PTP parameter with id %s found' % fake_uuid

        response = self.get_json(self.get_single_url(fake_uuid),
                                 expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
        self.assertIn(error_message, response.json['error_message'])


class TestListPtpParameter(BasePtpParameterTestCase):
    def setUp(self):
        super(TestListPtpParameter, self).setUp()
        self._create_test_ptp_parameters()

    def _create_test_ptp_parameters(self, prefix='test'):
        response = self.patch_json(
            self.get_instance_url(self.ptp_instances[0].uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'value': 'param1=value1',
              'op': constants.PTP_PATCH_OPERATION_ADD},
             {'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'value': 'param2=value2',
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        response = self.patch_json(
            self.get_interface_url(self.ptp_interfaces[0].uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'value': 'param3=value3',
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_list_ptp_parameter_all(self):
        response = self.get_json(self.API_PREFIX)
        for result in response[self.RESULT_KEY]:
            self.assertIn(self.COMMON_FIELD, result)

    def test_list_ptp_parameter_empty(self):
        response = self.get_json(
            self.get_instance_scoped_url(self.ptp_instances[1].uuid))
        self.assertEqual([], response[self.RESULT_KEY])

    def test_list_ptp_parameter_by_instance(self):
        response = self.get_json(
            self.get_instance_scoped_url(self.ptp_instances[0].uuid))
        for result in response[self.RESULT_KEY]:
            self.assertIn(self.ptp_instances[0].uuid, str(result['owners']))
            self.assertNotIn(self.ptp_interfaces[0].uuid,
                             str(result['owners']))

    def test_list_ptp_parameter_by_interface(self):
        response = self.get_json(
            self.get_interface_scoped_url(self.ptp_interfaces[0].uuid))
        for result in response[self.RESULT_KEY]:
            self.assertIn(self.ptp_interfaces[0].uuid, str(result['owners']))
            self.assertNotIn(self.ptp_instances[0].uuid, str(result['owners']))


class TestUpdatePtpParameter(BasePtpParameterTestCase):
    def setUp(self):
        super(TestUpdatePtpParameter, self).setUp()

    def test_update_ptp_parameter(self):
        ptp_parameter = dbutils.create_test_ptp_parameter(
            name='fake-param', value='fake-value')
        uuid = ptp_parameter['uuid']

        response = self.patch_json(self.get_single_url(uuid),
                                   [{'path': '/value',
                                     'value': 'changed-value',
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Check the parameter was indeed updated
        response = self.get_json(self.get_single_url(uuid))
        self.assertEqual(response['value'], 'changed-value')


class TestDeletePtpParameter(BasePtpParameterTestCase):
    """ Tests deletion.
        Typically delete APIs return NO CONTENT.
        python2 and python3 libraries may return different
        content_type (None, or empty json) when NO_CONTENT returned.
    """
    ptp_parameter = None
    uuid = None
    name = 'test-param'
    value = 'test-value'

    def setUp(self):
        super(TestDeletePtpParameter, self).setUp()
        self.ptp_parameter = dbutils.create_test_ptp_parameter(
            name=self.name, value=self.value)
        self.uuid = self.ptp_parameter['uuid']

    def test_delete_ptp_parameter_ok(self):
        response = self.delete(self.get_single_url(self.uuid),
                               headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Check the parameter was indeed removed
        error_message = 'No PTP parameter with id %s found' % self.uuid
        response = self.get_json(self.get_single_url(self.uuid),
                                 expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
        self.assertIn(error_message, response.json['error_message'])

    def test_delete_ptp_parameter_with_owner_failed(self):
        value = '%s=%s' % (self.name, self.value)
        response = self.patch_json(
            self.get_interface_url(self.ptp_interfaces[0].uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'value': value,
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        error_message = 'PTP parameter %s still in use' % self.uuid
        response = self.delete(self.get_single_url(self.uuid),
                               headers=self.API_HEADERS, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(error_message, response.json['error_message'])
