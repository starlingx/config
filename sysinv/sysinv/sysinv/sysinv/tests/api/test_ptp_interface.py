########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from oslo_utils import uuidutils
from six.moves import http_client
from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class BasePtpInterfaceTestCase(base.FunctionalTest, dbbase.BaseHostTestCase):
    # Generic header passed in most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # Prefix for the URL
    API_PREFIX = '/ptp_interfaces'

    # Python table key for the list of results
    RESULT_KEY = 'ptp_interfaces'

    # Field that is known to exist for inputs and outputs
    COMMON_FIELD = 'interface_uuid'

    # Can perform API operations on thie object at a sublevel of host
    HOST_PREFIX = '/ihosts'

    # Attributes that should be populated by an API query
    expected_api_fields = ['uuid', 'interface_id', 'ptp_instance_id']

    # Attributes that should NOT be populated by an API query
    hidden_api_fields = ['host_id']

    def setUp(self):
        super(BasePtpInterfaceTestCase, self).setUp()
        self.controller = self._create_test_host(constants.CONTROLLER)
        self.worker = self._create_test_host(constants.WORKER)

    def get_single_url(self, ptp_interface_uuid):
        return '%s/%s' % (self.API_PREFIX, ptp_interface_uuid)

    def get_host_scoped_url(self, host_uuid):
        return '%s/%s%s' % (self.HOST_PREFIX, host_uuid, self.API_PREFIX)

    def get_host_scoped_url_interface(self, host_uuid, interface_uuid):
        return '%s/%s%s?interface_uuid=%s' % (self.HOST_PREFIX,
                                              host_uuid,
                                              self.API_PREFIX,
                                              interface_uuid)

    def get_post_object(self, interface_uuid=None, ptp_instance_uuid=None):
        ptp_interface_db = {
            'interface_uuid': interface_uuid,
            'ptp_instance_uuid': ptp_instance_uuid
        }
        return ptp_interface_db

    def assert_fields(self, api_object):
        assert(uuidutils.is_uuid_like(api_object['uuid']))
        for field in self.expected_api_fields:
            self.assertIn(field, api_object)
        for field in self.hidden_api_fields:
            self.assertNotIn(field, api_object)


class TestCreatePtpInterface(BasePtpInterfaceTestCase):

    def setUp(self):
        super(TestCreatePtpInterface, self).setUp()

        self.test_interface = dbutils.create_test_interface(
            ifname='ptp0',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid)

        self.test_instance = dbutils.create_test_ptp_instance(
            name='testInstance',
            service=constants.PTP_INSTANCE_TYPE_PTP4L,
            host_id=self.controller.id)

    def _create_ptp_interface_success(self, interface_uuid, ptp_instance_uuid):
        ptp_interface_db = self.get_post_object(interface_uuid,
                                                ptp_instance_uuid)
        response = self.post_json(self.API_PREFIX, ptp_interface_db,
                                  headers=self.API_HEADERS)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json[self.COMMON_FIELD],
                         ptp_interface_db[self.COMMON_FIELD])

    def _create_ptp_interface_failed(self, interface_uuid, ptp_instance_uuid,
                                     status_code, error_message):
        ptp_interface_db = self.get_post_object(interface_uuid,
                                                ptp_instance_uuid)
        response = self.post_json(self.API_PREFIX, ptp_interface_db,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, status_code)
        self.assertIn(error_message, response.json['error_message'])

    def test_create_ptp_interface_ok(self):
        self._create_ptp_interface_success(self.test_interface.uuid,
                                           self.test_instance.uuid)

    def test_create_ptp_interface_invalid_interface(self):
        self._create_ptp_interface_failed(
            '32dbb999-6c10-448d-aeca-964c50af6384',
            self.test_instance.uuid,
            status_code=http_client.BAD_REQUEST,
            error_message='No entry found for interface 32dbb999-6c10-448d-aeca-964c50af6384')

    def test_create_ptp_interface_invalid_instance(self):
        self._create_ptp_interface_failed(
            self.test_interface.uuid,
            '32dbb999-6c10-448d-aeca-964c50af6384',
            status_code=http_client.NOT_FOUND,
            error_message='No PTP instance with id 32dbb999-6c10-448d-aeca-964c50af6384 found.')

    def test_create_ptp_interface_duplicate(self):
        self._create_ptp_interface_success(self.test_interface.uuid,
                                           self.test_instance.uuid)

        self._create_ptp_interface_failed(
            interface_uuid=self.test_interface.uuid,
            ptp_instance_uuid=self.test_instance.uuid,
            status_code=http_client.INTERNAL_SERVER_ERROR,
            error_message='')


class TestGetPtpInterface(BasePtpInterfaceTestCase):
    def setUp(self):
        super(TestGetPtpInterface, self).setUp()
        self.test_interface = dbutils.create_test_interface(
            ifname='ptp0',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=self.controller.id,
            ihost_uuid=self.controller.uuid)

        self.test_instance = dbutils.create_test_ptp_instance(
            name='testInstance',
            service=constants.PTP_INSTANCE_TYPE_PTP4L,
            host_id=self.controller.id)

        self.test_ptp_interface = dbutils.create_test_ptp_interface(
            interface_id=self.test_interface.id,
            ptp_instance_id=self.test_instance.id)

    def test_get_ptp_interface_found(self):

        response = self.get_json(
            self.get_single_url(self.test_ptp_interface.uuid))
        self.assertIn(self.COMMON_FIELD, response)

    def test_get_ptp_interface_not_found(self):
        fake_uuid = 'f4c56ddf-aef3-46ed-b9aa-126a1faafd40'
        error_message = 'No PTP interface with id %s found' % fake_uuid

        response = self.get_json(self.get_single_url(fake_uuid),
                                 expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
        self.assertIn(error_message, response.json['error_message'])


class TestListPtpInterface(BasePtpInterfaceTestCase):
    def setUp(self):
        super(TestListPtpInterface, self).setUp()
        self.test_interface = dbutils.create_test_interface(
            ifname='ptp0',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=self.worker.id,
            ihost_uuid=self.worker.uuid)

        self.dummy_interface = dbutils.create_test_interface(
            ifname='ptp1',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=self.worker.id,
            ihost_uuid=self.worker.uuid)

        self.test_instance_ptp4l = dbutils.create_test_ptp_instance(
            name='ptp4lInstance',
            service=constants.PTP_INSTANCE_TYPE_PTP4L,
            host_id=self.worker.id)

        self.test_instance_phc2sys = dbutils.create_test_ptp_instance(
            name='phc2sysInstance',
            service='phc2sys',
            host_id=self.worker.id)

        self.ptp4l_ptp_interface = dbutils.create_test_ptp_interface(
            interface_id=self.test_interface.id,
            ptp_instance_id=self.test_instance_ptp4l.id)
        self.phc2sys_ptp_interface = dbutils.create_test_ptp_interface(
            interface_id=self.test_interface.id,
            ptp_instance_id=self.test_instance_phc2sys.id)
        self.dummy_ptp_interface = dbutils.create_test_ptp_interface(
            interface_id=self.dummy_interface.id,
            ptp_instance_id=self.test_instance_ptp4l.id)

    def test_list_ptp_interface_host(self):
        response = self.get_json(self.get_host_scoped_url(self.worker.uuid))
        for result in response[self.RESULT_KEY]:
            self.assertEqual(self.worker.id, result['forihostid'])
            if result['uuid'] == self.ptp4l_ptp_interface.uuid \
               or result['uuid'] == self.dummy_interface.uuid:
                self.assertEqual(self.test_instance_ptp4l.id,
                                 result['ptp_instance_id'])
            elif result['uuid'] == self.phc2sys_ptp_interface.uuid:
                self.assertEqual(self.test_instance_phc2sys.id,
                                 result['ptp_instance_id'])

    def test_list_ptp_interface_interface(self):
        response = self.get_json(self.get_host_scoped_url_interface(
            self.worker.uuid, self.test_interface.uuid))
        for result in response[self.RESULT_KEY]:
            self.assertIn(self.COMMON_FIELD, result)
            self.assertNotIn(self.dummy_interface.uuid, result)

    def test_list_ptp_interface_empty(self):
        response = self.get_json(self.get_host_scoped_url(self.controller.uuid))
        self.assertEqual([], response[self.RESULT_KEY])


class TestDeletePtpInterface(BasePtpInterfaceTestCase):
    """ Tests deletion.
        Typically delete APIs return NO CONTENT.
        python2 and python3 libraries may return different
        content_type (None, or empty json) when NO_CONTENT returned.
    """

    def setUp(self):
        super(TestDeletePtpInterface, self).setUp()

        self.test_interface = dbutils.create_test_interface(
            ifname='ptp0',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=self.worker.id,
            ihost_uuid=self.worker.uuid)

        self.test_instance_ptp4l = dbutils.create_test_ptp_instance(
            name='ptp4lInstance',
            service=constants.PTP_INSTANCE_TYPE_PTP4L,
            host_id=self.worker.id)

        self.test_ptp_interface = dbutils.create_test_ptp_interface(
            interface_id=self.test_interface.id,
            ptp_instance_id=self.test_instance_ptp4l.id)

    def test_delete_ptp_interface(self):
        response = self.delete(
            self.get_single_url(self.test_ptp_interface.uuid),
            headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

        error_message = \
            'No PTP interface with id %s found' % self.test_ptp_interface.uuid
        response = self.get_json(
            self.get_single_url(self.test_ptp_interface.uuid),
            expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.NOT_FOUND)
        self.assertIn(error_message, response.json['error_message'])

    def test_delete_ptp_interface_with_parameters_failed(self):
        ptp_parameter = dbutils.create_test_ptp_parameter(
            name='fake-param', value='fake-value',
            type=constants.PTP_PARAMETER_OWNER_INTERFACE,
            foreign_uuid=self.test_ptp_interface.uuid)
        self.assertEqual(self.test_ptp_interface.uuid,
                         ptp_parameter['foreign_uuid'])

        response = self.delete(
            self.get_single_url(self.test_ptp_interface.uuid),
            headers=self.API_HEADERS, expect_errors=True)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('has PTP parameter', response.json['error_message'])
