# Copyright (c) 2021-2022 Wind River Systems, Inc.
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

    def get_post_object(self, name='test-instance',
                        service=constants.PTP_INSTANCE_TYPE_PTP4L):
        return dbutils.get_test_ptp_instance(name=name, service=service)


class TestUpdatePtpInstance(BasePtpInstanceTestCase):
    uuid = None

    def setUp(self):
        super(TestUpdatePtpInstance, self).setUp()
        ptp_instance = dbutils.create_test_ptp_instance(
            name='test-instance',
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

    def test_update_ptp_instance_delete_parameter_failed_not_found(self):
        fake_param_keypair = "fakeParam=fakeValue"
        error_message = ("No PTP parameter object found for %s" %
            fake_param_keypair)
        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'value': fake_param_keypair,
              'op': constants.PTP_PATCH_OPERATION_DELETE}],
            headers=self.API_HEADERS,
            expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(error_message, response.json['error_message'])

    def test_update_ptp_instance_delete_parameter_failed_not_owned(self):
        fake_param_name = "fakeParam"
        fake_param_value = "fakeValue"
        fake_param_keypair = "%s=%s" % (fake_param_name, fake_param_value)
        error_message = ("No PTP parameter object %s is owned by the given "
            "instance" % fake_param_keypair)
        dbutils.create_test_ptp_parameter(name=fake_param_name,
            value=fake_param_value)
        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'value': fake_param_keypair,
              'op': constants.PTP_PATCH_OPERATION_DELETE}],
            headers=self.API_HEADERS,
            expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(error_message, response.json['error_message'])
