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

    # Can perform API operations on this object at a sublevel of interfaces
    INTERFACE_PREFIX = '/iinterfaces'

    def setUp(self):
        super(BasePtpParameterTestCase, self).setUp()
        self.controller = self._create_test_host(constants.CONTROLLER)
        self.ptp_instances = self._create_test_ptp_instance(self.controller)
        self.platform_interfaces = \
            self._create_test_host_platform_interface(self.controller)
        self.ptp_interfaces = self._create_test_ptp_interface(
            self.ptp_instances, self.platform_interfaces)

    def get_single_url(self, ptp_parameter_uuid):
        return '%s/%s' % (self.API_PREFIX, ptp_parameter_uuid)

    def get_instance_scoped_url(self, ptp_instance_uuid):
        return '%s/%s%s' % (self.PTP_INSTANCE_PREFIX, ptp_instance_uuid,
                            self.API_PREFIX)

    def get_interface_scoped_url(self, interface_uuid):
        return '%s/%s%s' % (self.INTERFACE_PREFIX, interface_uuid,
                            self.API_PREFIX)

    def get_post_object(self, name='test_parameter', value='test_value',
                        type=None, foreign_uuid=None):
        return dbutils.get_test_ptp_parameter(name=name,
                                              value=value,
                                              type=type,
                                              foreign_uuid=foreign_uuid)


class TestCreatePtpParameter(BasePtpParameterTestCase):
    name = 'test-param'
    value = 'test-value'
    type = constants.PTP_PARAMETER_OWNER_INSTANCE
    foreign_uuid = None

    def setUp(self):
        super(TestCreatePtpParameter, self).setUp()
        self.foreign_uuid = self.ptp_instances[0].uuid
        dbutils.create_test_ptp_parameter(name=self.name,
                                          value=self.value,
                                          type=self.type,
                                          foreign_uuid=self.foreign_uuid)

    def _create_ptp_parameter_success(self, name, value, type, foreign_uuid):
        ptp_parameter_db = self.get_post_object(name=name,
                                                value=value,
                                                type=type,
                                                foreign_uuid=foreign_uuid)
        response = self.post_json(self.API_PREFIX, ptp_parameter_db,
                                  headers=self.API_HEADERS)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json[self.COMMON_FIELD],
                         ptp_parameter_db[self.COMMON_FIELD])

    def _create_ptp_parameter_failed(self, name, value, type, foreign_uuid,
                                     status_code, error_message):
        ptp_parameter_db = self.get_post_object(name=name,
                                                value=value,
                                                type=type,
                                                foreign_uuid=foreign_uuid)
        response = self.post_json(self.API_PREFIX, ptp_parameter_db,
                                  headers=self.API_HEADERS, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, status_code)
        self.assertIn(error_message, response.json['error_message'])

    def test_create_ptp_parameter_instance_ok(self):
        self._create_ptp_parameter_success(
            name='instance-param', value='instance-value',
            type=constants.PTP_PARAMETER_OWNER_INSTANCE,
            foreign_uuid=self.ptp_instances[0].uuid)

    def test_create_ptp_parameter_interface_ok(self):
        self._create_ptp_parameter_success(
            name='interface-param', value='interface-value',
            type=constants.PTP_PARAMETER_OWNER_INTERFACE,
            foreign_uuid=self.ptp_interfaces[0].uuid)

    def test_create_ptp_parameter_invalid_type(self):
        self._create_ptp_parameter_failed(
            name='fake-param', value='fake-value',
            type='invalid',
            foreign_uuid=self.ptp_instances[0].uuid,
            status_code=http_client.BAD_REQUEST,
            error_message='Invalid input for field/attribute type')

    def test_create_ptp_parameter_invalid_uuid(self):
        bad_uuid = 'f4c56ddf-aef3-46ed-b9aa-126a1faafd40'
        error_message = 'No foreign object found with id %s' % bad_uuid
        self._create_ptp_parameter_failed(
            name='fake-param', value='fake-value',
            type=constants.PTP_PARAMETER_OWNER_INSTANCE,
            foreign_uuid=bad_uuid,
            status_code=http_client.BAD_REQUEST,
            error_message=error_message)

    def test_create_ptp_parameter_duplicate(self):
        self._create_ptp_parameter_failed(
            name=self.name,
            value='another-value',
            type=constants.PTP_PARAMETER_OWNER_INSTANCE,
            foreign_uuid=self.foreign_uuid,
            status_code=http_client.CONFLICT,
            error_message='already exists')


class TestGetPtpParameter(BasePtpParameterTestCase):
    def setUp(self):
        super(TestGetPtpParameter, self).setUp()

    def test_get_ptp_parameter_found(self):
        ptp_parameter = dbutils.create_test_ptp_parameter(
            name='fake-param', value='fake-value',
            type=constants.PTP_PARAMETER_OWNER_INSTANCE,
            foreign_uuid=self.ptp_instances[0].uuid)
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
        self._create_test_ptp_parameters(
            type=constants.PTP_PARAMETER_OWNER_INSTANCE,
            prefix='ptp')
        self._create_test_ptp_parameters(
            type=constants.PTP_PARAMETER_OWNER_INTERFACE,
            prefix='iface')

    def _create_test_ptp_parameters(self, type, prefix='test',
                                    foreign_uuid=None):
        parameters = []

        if not foreign_uuid:
            if type == constants.PTP_PARAMETER_OWNER_INSTANCE:
                foreign_uuid = self.ptp_instances[0].uuid
            elif type == constants.PTP_PARAMETER_OWNER_INTERFACE:
                foreign_uuid = self.ptp_interfaces[0].uuid
            else:
                return parameters

        for i in range(2):
            name = '%s-name%s' % (prefix, i)
            value = '%s-value%s' % (prefix, i)
            parameter = dbutils.create_test_ptp_parameter(
                name=name, value=value, type=type, foreign_uuid=foreign_uuid)
            parameters.append(parameter)
        return parameters

    def test_list_ptp_parameter_all(self):
        response = self.get_json(self.API_PREFIX)
        for result in response[self.RESULT_KEY]:
            self.assertIn(self.COMMON_FIELD, result)

    def test_list_ptp_parameter_empty(self):
        fake_uuid = 'f4c56ddf-aef3-46ed-b9aa-126a1faafd40'
        response = self.get_json(self.get_instance_scoped_url(fake_uuid))
        self.assertEqual([], response[self.RESULT_KEY])

    def test_list_ptp_parameter_by_type(self):
        self._create_test_ptp_parameters(
            constants.PTP_PARAMETER_OWNER_INSTANCE,
            foreign_uuid=self.ptp_instances[1].uuid)
        """
        TODO: needs investigation of the reason to get this:
        webtest.app.AppError: Bad response: 400 Bad Request (not 200 OK or 3xx
        redirect for http://
        localhost/v1/ptp_parameters?q.field=type&q.value=ptp-instance&q.op=eq)
        '{"error_message": "{\\"debuginfo\\": null, \\"faultcode\\":
        \\"Client\\", \\"faultstring\\": \\"Unknown argument: \\\\\\"q.field,
        q.value, q.op\\\\\\"\\"}"}'
        query = [{
            'field': 'type',
            'value': constants.PTP_PARAMETER_OWNER_INSTANCE,
            'op': 'eq'
        }]
        response = self.get_json(self.API_PREFIX, q=query)
        for result in response[self.RESULT_KEY]:
            self.assertEqual(constants.PTP_PARAMETER_OWNER_INSTANCE,
                             result['type'])
        """

    def test_list_ptp_parameter_by_instance(self):
        self._create_test_ptp_parameters(
            constants.PTP_PARAMETER_OWNER_INSTANCE,
            foreign_uuid=self.ptp_instances[1].uuid)
        response = self.get_json(self.get_instance_scoped_url(
            self.ptp_instances[1].uuid))
        for result in response[self.RESULT_KEY]:
            self.assertEqual(self.ptp_instances[1].uuid,
                             result['foreign_uuid'])

    def test_list_ptp_parameter_by_interface(self):
        self._create_test_ptp_parameters(
            constants.PTP_PARAMETER_OWNER_INTERFACE,
            foreign_uuid=self.ptp_interfaces[1].uuid)
        response = self.get_json(self.get_interface_scoped_url(
            self.ptp_interfaces[1].uuid))
        for result in response[self.RESULT_KEY]:
            self.assertEqual(self.ptp_interfaces[1].uuid,
                             result['foreign_uuid'])


class TestUpdatePtpParameter(BasePtpParameterTestCase):
    def setUp(self):
        super(TestUpdatePtpParameter, self).setUp()

    def test_update_ptp_parameter(self):
        ptp_parameter = dbutils.create_test_ptp_parameter(
            name='fake-param', value='fake-value',
            type=constants.PTP_PARAMETER_OWNER_INSTANCE,
            foreign_uuid=self.ptp_instances[0].uuid)
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

    def setUp(self):
        super(TestDeletePtpParameter, self).setUp()

    def test_delete_ptp_parameter(self):
        ptp_parameter = dbutils.create_test_ptp_parameter(
            name='fake-param', value='fake-value',
            type=constants.PTP_PARAMETER_OWNER_INSTANCE,
            foreign_uuid=self.ptp_instances[0].uuid)
        uuid = ptp_parameter['uuid']

        response = self.delete(self.get_single_url(uuid),
                               headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Check the instance was indeed removed
        error_message = 'No PTP parameter with id %s found' % uuid
        response = self.get_json(self.get_single_url(uuid),
                                 expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
        self.assertIn(error_message, response.json['error_message'])
