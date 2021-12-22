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
    PARAMETER_PREFIX = '/ptp_parameters'

    # Python table key for the list of results
    PARAMETER_KEY = 'ptp_parameters'

    # Field that is known to exist for inputs and outputs
    PARAMETER_FIELD = 'name'

    # Prefix for the URL
    OWNERSHIP_PREFIX = '/ptp_parameter_ownerships'

    # Python table key for the list of results
    OWNERSHIP_KEY = 'ptp_parameter_ownerships'

    # Field that is known to exist for inputs and outputs
    OWNERSHIP_FIELD = 'owner_uuid'

    # Can perform API operations on this object at a sublevel of PTP instances
    PTP_INSTANCE_PREFIX = '/ptp_instances'

    # Can perform API operations on this object at a sublevel of interfaces
    INTERFACE_PREFIX = '/iinterfaces'

    def setUp(self):
        super(BasePtpParameterTestCase, self).setUp()
        self.controller = self._create_test_host(constants.CONTROLLER)
        self.ptp_instances = self._create_test_ptp_instance()
        self.ptp_interfaces = self._create_test_ptp_interface(
            self.ptp_instances)

    def get_parameter_url(self, ptp_parameter_uuid):
        return '%s/%s' % (self.PARAMETER_PREFIX, ptp_parameter_uuid)

    def get_ownership_url(self, ptp_paramownership_uuid):
        return '%s/%s' % (self.OWNERSHIP_PREFIX, ptp_paramownership_uuid)

    def get_instance_scoped_url(self, ptp_instance_uuid):
        return '%s/%s%s' % (self.PTP_INSTANCE_PREFIX, ptp_instance_uuid,
                            self.PARAMETER_PREFIX)

    def get_interface_scoped_url(self, interface_uuid):
        return '%s/%s%s' % (self.INTERFACE_PREFIX, interface_uuid,
                            self.PARAMETER_PREFIX)

    def get_post_parameter(self, name='test_parameter', value='test_value'):
        return dbutils.get_test_ptp_parameter(name=name,
                                              value=value)

    def get_post_ownership(self, parameter_uuid=None, owner_uuid=None):
        return dbutils.get_test_ptp_ownership(parameter_uuid=parameter_uuid,
                                              owner_uuid=owner_uuid)


class TestCreatePtpParameter(BasePtpParameterTestCase):
    name = 'test-param'
    value = 'test-value'

    def setUp(self):
        super(TestCreatePtpParameter, self).setUp()
        ptp_parameter_db = dbutils.create_test_ptp_parameter(name=self.name,
                                                             value=self.value)
        uuid = ptp_parameter_db['uuid']
        response = self.get_json(self.get_parameter_url(uuid))
        self.assertIn(self.PARAMETER_FIELD, response)

    def _create_ptp_parameter_success(self, name, value):
        ptp_parameter_db = self.get_post_parameter(name=name,
                                                   value=value)
        response = self.post_json(self.PARAMETER_PREFIX, ptp_parameter_db,
                                  headers=self.API_HEADERS)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json[self.PARAMETER_FIELD],
                         ptp_parameter_db[self.PARAMETER_FIELD])

    def _create_ptp_parameter_failed(self, name, value, status_code,
                                     error_message):
        ptp_parameter_db = self.get_post_parameter(name=name,
                                                   value=value)
        response = self.post_json(self.PARAMETER_PREFIX, ptp_parameter_db,
                                  headers=self.API_HEADERS, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, status_code)
        self.assertIn(error_message, response.json['error_message'])

    def test_create_ptp_parameter_instance_ok(self):
        self._create_ptp_parameter_success(
            name='instance-param', value='instance-value')

    def test_create_ptp_parameter_interface_ok(self):
        self._create_ptp_parameter_success(
            name='interface-param', value='interface-value')

    def test_create_ptp_parameter_synonymous_ok(self):
        self._create_ptp_parameter_success(
            name=self.name, value='another-value')


class TestSetPtpParameter(BasePtpParameterTestCase):
    name = 'test-param'
    value = 'test-value'
    parameter_uuid = None
    owner_uuid = None

    def setUp(self):
        super(TestSetPtpParameter, self).setUp()
        self.owner_uuid = self.ptp_instances[0].uuid
        ptp_parameter_db = dbutils.create_test_ptp_parameter(name=self.name,
                                                             value=self.value)
        self.parameter_uuid = ptp_parameter_db['uuid']
        response = self.get_json(self.get_parameter_url(self.parameter_uuid))
        self.assertIn(self.PARAMETER_FIELD, response)

        ptp_ownership_db = dbutils.create_test_ptp_ownership(
            parameter_uuid=self.parameter_uuid,
            owner_uuid=self.owner_uuid)
        ownership_uuid = ptp_ownership_db['uuid']
        response = self.get_json(self.get_ownership_url(ownership_uuid))
        self.assertIn(self.OWNERSHIP_FIELD, response)

    def _set_ptp_parameter(self, name, value):
        ptp_parameter_db = dbutils.create_test_ptp_parameter(name=name,
                                                             value=value)
        return ptp_parameter_db['uuid']

    def _set_ptp_ownership_success(self, name, value, owner_uuid):
        parameter_uuid = self._set_ptp_parameter(name, value)

        ptp_ownership_db = self.get_post_ownership(
            parameter_uuid=parameter_uuid,
            owner_uuid=owner_uuid)
        response = self.post_json(self.OWNERSHIP_PREFIX, ptp_ownership_db,
                                  headers=self.API_HEADERS)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json[self.OWNERSHIP_FIELD],
                         ptp_ownership_db[self.OWNERSHIP_FIELD])

    def _set_ptp_ownership_failed(self, name, value, owner_uuid,
                                  status_code, error_message):
        parameter_uuid = self._set_ptp_parameter(name, value)

        ptp_ownership_db = self.get_post_ownership(
            parameter_uuid=parameter_uuid,
            owner_uuid=owner_uuid)
        response = self.post_json(self.OWNERSHIP_PREFIX, ptp_ownership_db,
                                  headers=self.API_HEADERS, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, status_code)
        self.assertIn(error_message, response.json['error_message'])

    def test_set_ptp_parameter_instance_ok(self):
        self._set_ptp_ownership_success(
            name='instance-param', value='instance-value',
            owner_uuid=self.ptp_instances[0].uuid)

    def test_set_ptp_parameter_interface_ok(self):
        self._set_ptp_ownership_success(
            name='interface-param', value='interface-value',
            owner_uuid=self.ptp_interfaces[0].uuid)

    def test_set_ptp_parameter_duplicate(self):
        ptp_ownership_db = self.get_post_ownership(
            parameter_uuid=self.parameter_uuid,
            owner_uuid=self.owner_uuid)
        response = self.post_json(self.OWNERSHIP_PREFIX, ptp_ownership_db,
                                  headers=self.API_HEADERS, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.CONFLICT)
        self.assertIn('already a PTP parameter',
                      response.json['error_message'])

    def test_set_ptp_parameter_invalid_param(self):
        bad_uuid = 'f4c56ddf-aef3-46ed-b9aa-126a1faafd40'
        error_message = 'No PTP parameter object found with id %s' % bad_uuid

        ptp_ownership_db = self.get_post_ownership(
            parameter_uuid=bad_uuid,
            owner_uuid=self.owner_uuid)
        response = self.post_json(self.OWNERSHIP_PREFIX, ptp_ownership_db,
                                  headers=self.API_HEADERS, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(error_message, response.json['error_message'])

    def test_set_ptp_parameter_invalid_owner_uuid(self):
        bad_uuid = 'f4c56ddf-aef3-46ed-b9aa-126a1faafd40'
        error_message = 'No PTP parameter owner found with id %s' % bad_uuid
        self._set_ptp_ownership_failed(
            name='fake-param', value='fake-value',
            owner_uuid=bad_uuid,
            status_code=http_client.BAD_REQUEST,
            error_message=error_message)


class TestUnsetPtpParameter(BasePtpParameterTestCase):
    def setUp(self):
        super(TestUnsetPtpParameter, self).setUp()

    def test_unset_ptp_parameter_instance(self):
        owner_uuid = self.ptp_instances[0].uuid
        ptp_parameter = dbutils.create_test_ptp_parameter(
            name='instance-param', value='instance-value')
        ptp_ownership = dbutils.create_test_ptp_ownership(
            parameter_uuid=ptp_parameter['uuid'],
            owner_uuid=owner_uuid)
        uuid = ptp_ownership['uuid']

        response = self.delete(self.get_ownership_url(uuid),
                               headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Double check the ownership was removed
        error_message = 'No PTP parameter ownership with id %s found' % uuid
        response = self.get_json(self.get_ownership_url(uuid),
                                 expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
        self.assertIn(error_message, response.json['error_message'])

        response = self.get_json(self.get_instance_scoped_url(owner_uuid))
        self.assertEqual([], response[self.PARAMETER_KEY])

    def test_unset_ptp_parameter_interface(self):
        owner_uuid = self.ptp_interfaces[0].uuid
        ptp_parameter = dbutils.create_test_ptp_parameter(
            name='interface-param', value='interface-value')
        ptp_ownership = dbutils.create_test_ptp_ownership(
            parameter_uuid=ptp_parameter['uuid'],
            owner_uuid=owner_uuid)
        uuid = ptp_ownership['uuid']

        response = self.delete(self.get_ownership_url(uuid),
                               headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Double check the ownership was removed
        error_message = 'No PTP parameter ownership with id %s found' % uuid
        response = self.get_json(self.get_ownership_url(uuid),
                                 expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
        self.assertIn(error_message, response.json['error_message'])

        response = self.get_json(self.get_interface_scoped_url(owner_uuid))
        self.assertEqual([], response[self.PARAMETER_KEY])


class TestGetPtpParameter(BasePtpParameterTestCase):
    name = 'test-param'
    value = 'test-value'
    type = constants.PTP_PARAMETER_OWNER_INSTANCE
    parameter_uuid = None
    owner_uuid = None

    def setUp(self):
        super(TestGetPtpParameter, self).setUp()
        self.owner_uuid = self.ptp_instances[0].uuid
        ptp_parameter_db = dbutils.create_test_ptp_parameter(name=self.name,
                                                             value=self.value)
        self.parameter_uuid = ptp_parameter_db['uuid']
        response = self.get_json(self.get_parameter_url(self.parameter_uuid))
        self.assertIn(self.PARAMETER_FIELD, response)

    def test_get_ptp_parameter_found(self):
        ptp_parameter = dbutils.create_test_ptp_parameter(
            name='fake-param', value='fake-value')
        uuid = ptp_parameter['uuid']
        response = self.get_json(self.get_parameter_url(uuid))
        self.assertIn(self.PARAMETER_FIELD, response)

    def test_get_ptp_parameter_not_found(self):
        fake_uuid = 'f4c56ddf-aef3-46ed-b9aa-126a1faafd40'
        error_message = 'No PTP parameter with id %s found' % fake_uuid

        response = self.get_json(self.get_parameter_url(fake_uuid),
                                 expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
        self.assertIn(error_message, response.json['error_message'])

    def test_get_ptp_parameter_owner_found(self):
        ptp_ownership = dbutils.create_test_ptp_ownership(
            parameter_uuid=self.parameter_uuid,
            owner_uuid=self.owner_uuid)
        uuid = ptp_ownership['uuid']
        response = self.get_json(self.get_ownership_url(uuid))
        self.assertIn(self.OWNERSHIP_FIELD, response)

    def test_get_ptp_parameter_owner_not_found(self):
        fake_uuid = 'f4c56ddf-aef3-46ed-b9aa-126a1faafd40'
        error_message = \
            'No PTP parameter ownership with id %s found' % fake_uuid

        response = self.get_json(self.get_ownership_url(fake_uuid),
                                 expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
        self.assertIn(error_message, response.json['error_message'])


class TestListPtpParameter(BasePtpParameterTestCase):
    def setUp(self):
        super(TestListPtpParameter, self).setUp()
        self._create_test_ptp_parameters(
            prefix='ptp',
            type=constants.PTP_PARAMETER_OWNER_INSTANCE)
        self._create_test_ptp_parameters(
            prefix='iface',
            type=constants.PTP_PARAMETER_OWNER_INTERFACE)

    def _create_test_ptp_parameters(self, prefix='test',
                                    owner_uuid=None, type=None):
        parameters = []
        ownerships = []

        if not owner_uuid:
            if type == constants.PTP_PARAMETER_OWNER_INSTANCE:
                owner_uuid = self.ptp_instances[0].uuid
            elif type == constants.PTP_PARAMETER_OWNER_INTERFACE:
                owner_uuid = self.ptp_interfaces[0].uuid
            else:
                return parameters, ownerships

        for i in range(2):
            name = '%s-name%s' % (prefix, i)
            value = '%s-value%s' % (prefix, i)
            parameter = dbutils.create_test_ptp_parameter(name=name,
                                                          value=value)
            parameters.append(parameter)

            ownership = dbutils.create_test_ptp_ownership(
                parameter_uuid=parameter['uuid'],
                owner_uuid=owner_uuid)
            ownerships.append(ownership)

        return parameters, ownerships

    def test_list_ptp_parameter_all(self):
        response = self.get_json(self.PARAMETER_PREFIX)
        for result in response[self.PARAMETER_KEY]:
            self.assertIn(self.PARAMETER_FIELD, result)

    def test_list_ptp_parameter_empty(self):
        fake_uuid = 'f4c56ddf-aef3-46ed-b9aa-126a1faafd40'
        response = self.get_json(self.get_instance_scoped_url(fake_uuid))
        self.assertEqual([], response[self.PARAMETER_KEY])

    def test_list_ptp_parameter_by_instance(self):
        uuid = self.ptp_instances[1].uuid
        self._create_test_ptp_parameters(owner_uuid=uuid)
        response = self.get_json(self.get_instance_scoped_url(uuid))
        for result in response[self.PARAMETER_KEY]:
            self.assertIn(uuid, str(result['owners']))

    def test_list_ptp_parameter_by_interface(self):
        uuid = self.ptp_interfaces[1].uuid
        self._create_test_ptp_parameters(owner_uuid=uuid)
        response = self.get_json(self.get_interface_scoped_url(uuid))
        for result in response[self.PARAMETER_KEY]:
            self.assertIn(uuid, str(result['owners']))


class TestUpdatePtpParameter(BasePtpParameterTestCase):
    def setUp(self):
        super(TestUpdatePtpParameter, self).setUp()

    def test_update_ptp_parameter(self):
        ptp_parameter = dbutils.create_test_ptp_parameter(
            name='fake-param', value='fake-value')
        uuid = ptp_parameter['uuid']

        response = self.patch_json(self.get_parameter_url(uuid),
                                   [{'path': '/value',
                                     'value': 'changed-value',
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Check the parameter was indeed updated
        response = self.get_json(self.get_parameter_url(uuid))
        self.assertEqual(response['value'], 'changed-value')


class TestDeletePtpParameter(BasePtpParameterTestCase):
    """ Tests deletion.
        Typically delete APIs return NO CONTENT.
        python2 and python3 libraries may return different
        content_type (None, or empty json) when NO_CONTENT returned.
    """

    def setUp(self):
        super(TestDeletePtpParameter, self).setUp()

    def test_delete_ptp_parameter_ok(self):
        ptp_parameter = dbutils.create_test_ptp_parameter(
            name='fake-param', value='fake-value')
        uuid = ptp_parameter['uuid']
        response = self.delete(self.get_parameter_url(uuid),
                               headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Check the parameter was indeed removed
        error_message = 'No PTP parameter with id %s found' % uuid
        response = self.get_json(self.get_parameter_url(uuid),
                                 expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
        self.assertIn(error_message, response.json['error_message'])

    def test_delete_ptp_parameter_with_owner_failed(self):
        ptp_parameter = dbutils.create_test_ptp_parameter(
            name='fake-param', value='fake-value')
        uuid = ptp_parameter['uuid']
        owner_uuid = self.ptp_instances[0].uuid
        dbutils.create_test_ptp_ownership(parameter_uuid=uuid,
                                          owner_uuid=owner_uuid)

        response = self.delete(self.get_parameter_url(uuid),
                               headers=self.API_HEADERS, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('still associated with ', response.json['error_message'])
