# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from six.moves import http_client
from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class BasePtpInstanceTestCase(base.FunctionalTest, dbbase.BaseHostTestCase):
    # Generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # Prefix for the URL
    API_PREFIX = '/ptp_instances'

    # Python table key for the list of results
    RESULT_KEY = 'ptp_instances'

    # Field that is known to exist for inputs and outputs
    COMMON_FIELD = 'name'

    # Can perform API operations on this object at a sublevel of host
    HOST_PREFIX = '/ihosts'

    def setUp(self):
        super(BasePtpInstanceTestCase, self).setUp()
        self.controller = self._create_test_host(constants.CONTROLLER)
        self.worker = self._create_test_host(constants.WORKER)

    def get_single_url(self, ptp_instance_uuid):
        return '%s/%s' % (self.API_PREFIX, ptp_instance_uuid)

    def get_host_scoped_url(self, host_uuid):
        return '%s/%s%s' % (self.HOST_PREFIX, host_uuid, self.API_PREFIX)

    def get_host_url(self, host_uuid):
        return '%s/%s' % (self.HOST_PREFIX, host_uuid)

    def get_post_object(self, name='test_instance',
                        service=constants.PTP_INSTANCE_TYPE_PTP4L):
        return dbutils.get_test_ptp_instance(name=name, service=service)


class TestCreatePtpInstance(BasePtpInstanceTestCase):
    name = constants.PTP_INSTANCE_DEFAULT_PTP4L
    service = constants.PTP_INSTANCE_TYPE_PTP4L

    def setUp(self):
        super(TestCreatePtpInstance, self).setUp()
        dbutils.create_test_ptp_instance(name=self.name, service=self.service)

    def _create_ptp_instance_success(self, name, service):
        ptp_instance_db = self.get_post_object(name=name, service=service)
        response = self.post_json(self.API_PREFIX, ptp_instance_db,
                                  headers=self.API_HEADERS)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json[self.COMMON_FIELD],
                         ptp_instance_db[self.COMMON_FIELD])

    def _create_ptp_instance_failed(self, name, service,
                                    status_code, error_message):
        ptp_instance_db = self.get_post_object(name=name, service=service)
        response = self.post_json(self.API_PREFIX, ptp_instance_db,
                                  headers=self.API_HEADERS, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, status_code)
        self.assertIn(error_message, response.json['error_message'])

    def test_create_ptp_instance_ok(self):
        self._create_ptp_instance_success('test-instance',
                                          constants.PTP_INSTANCE_TYPE_PTP4L)

    def test_create_ptp_instance_invalid_service(self):
        self._create_ptp_instance_failed(
            'test-invalid',
            'invalid',
            status_code=http_client.BAD_REQUEST,
            error_message='Invalid input for field/attribute service')

    def test_create_ptp_instance_duplicate_name(self):
        error_message = \
            "PTP instance with name '%s' already exists" % self.name
        self._create_ptp_instance_failed(
            name=self.name,
            service=self.service,
            status_code=http_client.CONFLICT,
            error_message=error_message)


class TestUpdatePtpInstance(BasePtpInstanceTestCase):
    uuid = None

    def setUp(self):
        super(TestUpdatePtpInstance, self).setUp()
        ptp_instance = dbutils.create_test_ptp_instance(
            name=constants.PTP_INSTANCE_DEFAULT_PTP4L,
            service=constants.PTP_INSTANCE_TYPE_PTP4L)
        self.uuid = ptp_instance['uuid']

    def test_update_ptp_instance_add_parameter_ok(self):
        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'value': 'param1=value1',
              'op': constants.PTP_PATCH_OPERATION_ADD},
             {'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'value': 'param2=value2',
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_update_ptp_instance_add_parameter_failed_no_instance(self):
        fake_uuid = 'f4c56ddf-aef3-46ed-b9aa-126a1faafd40'
        error_message = 'No PTP instance with id %s found.' % fake_uuid
        response = self.patch_json(
            self.get_single_url(fake_uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'value': 'param0=value0',
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS,
            expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
        self.assertIn(error_message, response.json['error_message'])

    def test_update_ptp_instance_delete_parameter_ok(self):
        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'value': 'param0=value0',
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'value': 'param0=value0',
              'op': constants.PTP_PATCH_OPERATION_DELETE}],
            headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)


class TestHostPtpInstance(BasePtpInstanceTestCase):
    def setUp(self):
        super(TestHostPtpInstance, self).setUp()

    def _assign_host_ptp_instance_success(self):
        ptp_instance = dbutils.create_test_ptp_instance(
            name=constants.PTP_INSTANCE_DEFAULT_PTP4L,
            service=constants.PTP_INSTANCE_TYPE_PTP4L)
        ptp_instance_id = ptp_instance['id']
        response = self.patch_json(
            self.get_host_url(self.controller.uuid),
            [{'path': constants.PTP_INSTANCE_ARRAY_PATH,
              'value': ptp_instance_id,
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        return ptp_instance_id

    def test_host_ptp_instance_assign_ok(self):
        self._assign_host_ptp_instance_success()

    def test_host_ptp_instance_assign_failed(self):
        fake_id = 101
        response = self.patch_json(
            self.get_host_url(self.controller.uuid),
            [{'path': constants.PTP_INSTANCE_ARRAY_PATH,
              'value': fake_id,
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS,
            expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('No PTP instance object', response.json['error_message'])

    def test_host_ptp_instance_remove_ok(self):
        ptp_instance_id = self._assign_host_ptp_instance_success()

        response = self.patch_json(
            self.get_host_url(self.controller.uuid),
            [{'path': constants.PTP_INSTANCE_ARRAY_PATH,
              'value': ptp_instance_id,
              'op': constants.PTP_PATCH_OPERATION_DELETE}],
            headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)


class TestGetPtpInstance(BasePtpInstanceTestCase):
    def setUp(self):
        super(TestGetPtpInstance, self).setUp()

    def test_get_ptp_instance_found(self):
        ptp_instance = dbutils.create_test_ptp_instance(
            name=constants.PTP_INSTANCE_DEFAULT_PTP4L,
            service=constants.PTP_INSTANCE_TYPE_PTP4L)
        response = self.get_json(self.get_single_url(ptp_instance['uuid']))
        self.assertIn(self.COMMON_FIELD, response)

    def test_get_ptp_instance_not_found(self):
        fake_uuid = 'f4c56ddf-aef3-46ed-b9aa-126a1faafd40'
        error_message = 'No PTP instance with id %s found' % fake_uuid

        response = self.get_json(self.get_single_url(fake_uuid),
                                 expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
        self.assertIn(error_message, response.json['error_message'])


class TestListPtpInstance(BasePtpInstanceTestCase):
    def setUp(self):
        super(TestListPtpInstance, self).setUp()
        self._create_test_ptp_instances()

    def _create_test_ptp_instances(self, name_prefix='test'):
        services = [constants.PTP_INSTANCE_TYPE_PTP4L,
                    constants.PTP_INSTANCE_TYPE_PHC2SYS,
                    constants.PTP_INSTANCE_TYPE_TS2PHC]
        for service in services:
            name = '%s-%s' % (name_prefix, service)
            instance = dbutils.create_test_ptp_instance(name=name,
                                                        service=service)
            response = self.patch_json(
                self.get_host_url(self.controller.uuid),
                [{'path': constants.PTP_INSTANCE_ARRAY_PATH,
                  'value': instance['id'],
                  'op': constants.PTP_PATCH_OPERATION_ADD}],
                headers=self.API_HEADERS)
            self.assertEqual(response.content_type, 'application/json')
            self.assertEqual(response.status_code, http_client.OK)

    def test_list_ptp_instance_all(self):
        response = self.get_json(self.API_PREFIX)
        for result in response[self.RESULT_KEY]:
            self.assertIn(self.COMMON_FIELD, result)

    def test_list_ptp_instance_empty(self):
        response = self.get_json(self.get_host_scoped_url(self.worker.uuid))
        self.assertEqual([], response[self.RESULT_KEY])

    def test_list_ptp_instance_host(self):
        response = self.get_json(
            self.get_host_scoped_url(self.controller.uuid))
        for result in response[self.RESULT_KEY]:
            self.assertIn(self.controller.hostname, result['hostnames'])


class TestDeletePtpInstance(BasePtpInstanceTestCase):
    """ Tests deletion.
        Typically delete APIs return NO CONTENT.
        python2 and python3 libraries may return different
        content_type (None, or empty json) when NO_CONTENT returned.
    """
    ptp_instance = None
    uuid = None

    def setUp(self):
        super(TestDeletePtpInstance, self).setUp()
        self.ptp_instance = dbutils.create_test_ptp_instance(
            name=constants.PTP_INSTANCE_DEFAULT_PTP4L,
            service=constants.PTP_INSTANCE_TYPE_PTP4L)
        self.uuid = self.ptp_instance['uuid']

    def test_delete_ptp_instance_ok(self):
        response = self.delete(self.get_single_url(self.uuid),
                               headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Check the instance was indeed removed
        error_message = 'No PTP instance with id %s found' % self.uuid
        response = self.get_json(self.get_single_url(self.uuid),
                                 expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
        self.assertIn(error_message, response.json['error_message'])

    def test_delete_ptp_instance_with_host_failed(self):
        response = self.patch_json(
            self.get_host_url(self.controller.uuid),
            [{'path': constants.PTP_INSTANCE_ARRAY_PATH,
              'value': self.ptp_instance['id'],
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        response = self.delete(self.get_single_url(self.uuid),
                               headers=self.API_HEADERS, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('still associated with host',
                      response.json['error_message'])

    def test_delete_ptp_instance_with_parameters_failed(self):
        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'value': 'param0=value0',
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        response = self.delete(self.get_single_url(self.uuid),
                               headers=self.API_HEADERS, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('still associated with PTP parameter',
                      response.json['error_message'])

    def test_delete_ptp_instance_with_interfaces_failed(self):
        ptp_interface = dbutils.create_test_ptp_interface(
            name='test',
            ptp_instance_id=self.ptp_instance['id'],
            ptp_instance_uuid=self.ptp_instance['uuid'])
        self.assertEqual(self.ptp_instance['id'],
                         ptp_interface['ptp_instance_id'])

        response = self.delete(self.get_single_url(self.uuid),
                               headers=self.API_HEADERS, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('still associated with PTP interface',
                      response.json['error_message'])
