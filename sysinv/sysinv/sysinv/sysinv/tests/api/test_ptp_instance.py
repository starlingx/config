# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from oslo_utils import uuidutils
from six.moves import http_client
from sysinv.common import constants
from sysinv.db import api as dbapi
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase


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

    # Attributes that should be populated by an API query
    expected_api_fields = ['uuid', 'name', 'service']

    # Attributes that should NOT be populated by an API query
    hidden_api_fields = ['host_id']

    def _get_ptp_instance(self, **kw):
        instance = {
            'id': kw.get('id'),
            'uuid': kw.get('uuid'),
            'name': kw.get('name', None),
            'service': kw.get('service', 'ptp4l'),
            'host_id': kw.get('host_id', None)
        }
        return instance

    def _create_ptp_instance(self, **kw):
        instance = self._get_ptp_instance(**kw)
        # Let DB generate ID if isn't specified
        if 'id' not in kw:
            del instance['id']
        if 'uuid' in kw:
            del instance['uuid']
        db_api = dbapi.get_instance()
        return db_api.ptp_instance_create(instance)

    def setUp(self):
        super(BasePtpInstanceTestCase, self).setUp()
        self.controller = self._create_test_host(constants.CONTROLLER)
        self.worker = self._create_test_host(constants.WORKER)

    def get_single_url(self, ptp_instance_uuid):
        return '%s/%s' % (self.API_PREFIX, ptp_instance_uuid)

    def get_host_scoped_url(self, host_uuid):
        return '%s/%s%s' % (self.HOST_PREFIX, host_uuid, self.API_PREFIX)

    def get_post_object(self, name='test_instance', service='ptp4l',
                        host_id=None, host_uuid=None):
        ptp_instance_db = self._get_ptp_instance(name=name,
                                                 service=service,
                                                 host_id=host_id)
        ptp_instance_db['host_uuid'] = host_uuid
        return ptp_instance_db

    def assert_fields(self, api_object):
        assert(uuidutils.is_uuid_like(api_object['uuid']))
        for field in self.expected_api_fields:
            self.assertIn(field, api_object)
        for field in self.hidden_api_fields:
            self.assertNotIn(field, api_object)


class TestCreatePtpInstance(BasePtpInstanceTestCase):
    name = 'ptp-name'
    service = 'ptp4l'
    host_id = None
    host_uuid = None

    def setUp(self):
        super(TestCreatePtpInstance, self).setUp()
        self.host_id = self.controller.id
        self.host_uuid = self.controller.uuid
        self._create_ptp_instance(name=self.name, service=self.service,
                                  host_id=self.host_id)

    def _create_ptp_instance_success(self, name, service, host_id, host_uuid):
        ptp_instance_db = self.get_post_object(name=name, service=service,
                                               host_id=host_id,
                                               host_uuid=host_uuid)
        response = self.post_json(self.API_PREFIX, ptp_instance_db,
                                  headers=self.API_HEADERS)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json[self.COMMON_FIELD],
                         ptp_instance_db[self.COMMON_FIELD])

    def _create_ptp_instance_failed(self, name, service, host_id, host_uuid,
                                    status_code, error_message):
        ptp_instance_db = self.get_post_object(name=name, service=service,
                                               host_id=host_id,
                                               host_uuid=host_uuid)
        response = self.post_json(self.API_PREFIX, ptp_instance_db,
                                  headers=self.API_HEADERS, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, status_code)
        self.assertIn(error_message, response.json['error_message'])

    def test_create_ptp_instance_ok(self):
        self._create_ptp_instance_success('test-instance', 'ptp4l',
                                          host_id=self.controller.id,
                                          host_uuid=self.controller.uuid)

    def test_create_ptp_instance_invalid_service(self):
        self._create_ptp_instance_failed(
            'test-invalid',
            'invalid',
            host_id=self.controller.id,
            host_uuid=self.controller.uuid,
            status_code=http_client.BAD_REQUEST,
            error_message='Invalid input for field/attribute service')

    def test_create_ptp_instance_duplicate_name(self):
        error_message = \
            "PTP instance with name '%s' already exists" % self.name
        self._create_ptp_instance_failed(
            name=self.name,
            service=self.service,
            host_id=self.host_id,
            host_uuid=self.host_uuid,
            status_code=http_client.CONFLICT,
            error_message=error_message)

    def test_create_ptp_instance_invalid_host(self):
        bad_uuid = 'f4c56ddf-aef3-46ed-b9aa-126a1faafd40'
        error_message = '%s could not be found' % bad_uuid
        self._create_ptp_instance_failed(
            'test-invalid',
            'phc2sys',
            host_id=99,
            host_uuid='f4c56ddf-aef3-46ed-b9aa-126a1faafd40',
            status_code=http_client.NOT_FOUND,
            error_message=error_message)


class TestGetPtpInstance(BasePtpInstanceTestCase):
    def setUp(self):
        super(TestGetPtpInstance, self).setUp()

    def test_get_ptp_instance_found(self):
        ptp_instance = self._create_ptp_instance(
            name='fake-ptp4l', service='ptp4l', host_id=self.controller.id)
        uuid = ptp_instance['uuid']
        response = self.get_json(self.get_single_url(uuid))
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

    def _create_test_ptp_instances(self, name_prefix='test', host_id=None):
        services = ['ptp4l', 'phc2sys', 'ts2phc']
        instances = []
        if not host_id:
            host_id = self.controller.id
        for service in services:
            name = '%s-%s' % (name_prefix, service)
            instance = self._create_ptp_instance(
                name=name, service=service, host_id=host_id)
            instances.append(instance)
        return instances

    def test_list_ptp_instance_all(self):
        response = self.get_json(self.API_PREFIX)
        for result in response[self.RESULT_KEY]:
            self.assertIn(self.COMMON_FIELD, result)

    def test_list_ptp_instance_empty(self):
        response = self.get_json(self.get_host_scoped_url(self.worker.uuid))
        self.assertEqual([], response[self.RESULT_KEY])

    def test_list_ptp_instance_host(self):
        self._create_test_ptp_instances(name_prefix='fake',
                                        host_id=self.worker.id)
        response = self.get_json(self.get_host_scoped_url(self.worker.uuid))
        for result in response[self.RESULT_KEY]:
            self.assertEqual(self.worker.uuid, result['host_uuid'])


class TestDeletePtpInstance(BasePtpInstanceTestCase):
    """ Tests deletion.
        Typically delete APIs return NO CONTENT.
        python2 and python3 libraries may return different
        content_type (None, or empty json) when NO_CONTENT returned.
    """

    def setUp(self):
        super(TestDeletePtpInstance, self).setUp()

    def test_delete_ptp_instance(self):
        ptp_instance = self._create_ptp_instance(
            name='fake-phc2sys', service='phc2sys', host_id=self.controller.id)
        uuid = ptp_instance['uuid']
        response = self.delete(self.get_single_url(uuid),
                               headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        # Check the instance was indeed removed
        error_message = 'No PTP instance with id %s found' % uuid
        response = self.get_json(self.get_single_url(uuid),
                                 expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
        self.assertIn(error_message, response.json['error_message'])

    def test_delete_ptp_instance_with_parameters_failed(self):
        # TODO: implement when PTP parameters API is available
        pass

    def test_delete_ptp_instance_with_interfaces_failed(self):
        # TODO: implement when PTP interfaces API is available
        pass
