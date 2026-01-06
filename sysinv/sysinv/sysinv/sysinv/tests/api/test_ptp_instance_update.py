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

    def test_update_ptp_instance_add_section_parameter_ok(self):
        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'section': 'sectionA',
              'value': 'param1=value1',
              'op': constants.PTP_PATCH_OPERATION_ADD},
             {'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'section': 'sectionA',
              'value': 'param2=value2',
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # check output presentation as sectional output
        data = response.json
        self.assertEqual(data["parameters"]["sectionA"].sort(),
            ["param1=value1", "param2=value2"].sort()
        )

    def _patch_section_parameters(self, op, section, section_parameters, expect_errors=False):
        patch_list = []
        for parameter in section_parameters:
            patch_list.append(
                {
                    'path': constants.PTP_PARAMETER_ARRAY_PATH,
                    'section': section,
                    'value': parameter,
                    'op': op
                }
            )
        response = self.patch_json(
            self.get_single_url(self.uuid),
            patch_list,
            headers=self.API_HEADERS, expect_errors=expect_errors)
        return response

    def test_update_ptp_instance_add_unicast_master_table_parameters_ok(self):
        umt_parameters = [
            (
                'unicast_master_table_A',
                [
                    "table_id=1",
                    "logQueryInterval=0",
                    "peer_address=1.2.3.4",
                    "L2=00:00:00:00:00:01",
                    "L2=00:00:00:00:00:02"
                ]
            ),
            (
                'unicast_master_table_B',
                [
                    "table_id=2",
                    "logQueryInterval=1",
                    "peer_address=::1",
                    "UDPv4=1.2.3.4",
                    "UDPv4=1.2.3.5"
                ]
            ),
        ]
        for section, section_parameters in umt_parameters:
            response = self._patch_section_parameters(
                constants.PTP_PATCH_OPERATION_ADD,
                section, section_parameters
            )
            self.assertEqual(response.content_type, 'application/json')
            self.assertEqual(response.status_code, http_client.OK)

        # check output presentation as sectional output
        data = response.json
        self.assertEqual(len(data["parameters"]), len(umt_parameters))
        for section, section_parameters in umt_parameters:
            self.assertEqual(data["parameters"][section].sort(), section_parameters.sort())

    def test_update_ptp_instance_add_unicast_master_table_parameters_failed(self):
        section_a = 'unicast_master_table_A'
        section_a_parameters = [
            "table_id=1",
            "logQueryInterval=0",
            "peer_address=1.2.3.4",
        ]
        section_b = 'unicast_master_table_B'

        response = self._patch_section_parameters(
            constants.PTP_PATCH_OPERATION_ADD,
            section_a, section_a_parameters
        )
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        data = response.json
        self.assertEqual(data["parameters"][section_a].sort(), section_a_parameters.sort())

        # Adding same table_id value, would conflict
        response = self._patch_section_parameters(
            constants.PTP_PATCH_OPERATION_ADD,
            section_a, ["table_id=1"], expect_errors=True
        )
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.CONFLICT)

        # Adding different table_id value should fail
        error_message = (
            f"Parameter already exists: section:{section_a} "
            f"parameter:table_id new value:2 vs existing value:1"
        )
        response = self._patch_section_parameters(
            constants.PTP_PATCH_OPERATION_ADD,
            section_a, ["table_id=2"], expect_errors=True
        )
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(error_message, response.json['error_message'])

        # Adding same logQueryInterval value, would conflict
        response = self._patch_section_parameters(
            constants.PTP_PATCH_OPERATION_ADD,
            section_a, ["logQueryInterval=0"], expect_errors=True
        )
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.CONFLICT)

        # Adding different logQueryInterval value should fail
        error_message = (
            f"Parameter already exists: section:{section_a} "
            f"parameter:logQueryInterval new value:5 vs existing value:0"
        )
        response = self._patch_section_parameters(
            constants.PTP_PATCH_OPERATION_ADD,
            section_a, ["logQueryInterval=5"], expect_errors=True
        )
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(error_message, response.json['error_message'])

        # Adding same peer_address value would conflict
        response = self._patch_section_parameters(
            constants.PTP_PATCH_OPERATION_ADD,
            section_a, ["peer_address=1.2.3.4"], expect_errors=True
        )
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.CONFLICT)

        # Adding different peer_address value should fail
        error_message = (
            f"Parameter already exists: section:{section_a} "
            f"parameter:peer_address new value:1.2.3.5 vs existing value:1.2.3.4"
        )
        response = self._patch_section_parameters(
            constants.PTP_PATCH_OPERATION_ADD,
            section_a, ["peer_address=1.2.3.5"], expect_errors=True
        )
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(error_message, response.json['error_message'])

        # Adding new section with duplicate table_id value should fail
        error_message = f"table_id=1 is not unique, already exist in {section_a}"
        response = self._patch_section_parameters(
            constants.PTP_PATCH_OPERATION_ADD,
            section_b, ["table_id=1"], expect_errors=True
        )
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(error_message, response.json['error_message'])

    def test_update_ptp_instance_add_unicast_master_table_mix_transports_failed(self):
        section_a = 'unicast_master_table_A'
        section_a_parameters = [
            "table_id=1",
            "logQueryInterval=0",
            "peer_address=1.2.3.4",
            "L2=00:0:00:00:00:01"
        ]

        response = self._patch_section_parameters(
            constants.PTP_PATCH_OPERATION_ADD,
            section_a, section_a_parameters
        )
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)
        data = response.json
        self.assertEqual(data["parameters"][section_a].sort(), section_a_parameters.sort())

        # Add one more L2, should pass
        response = self._patch_section_parameters(
            constants.PTP_PATCH_OPERATION_ADD,
            section_a, ["L2=00:0:00:00:00:02"]
        )
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

        # Add UDPv4, should fail
        error_message = (
            f"L2 or UPPv4 or UDPv6, these parameters can not be mixed, "
            f"section: {section_a}, new parameter:UDPv4 vs existing parameter:L2"
        )
        response = self._patch_section_parameters(
            constants.PTP_PATCH_OPERATION_ADD,
            section_a, ["UDPv4=1.2.3.4"], expect_errors=True
        )
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(error_message, response.json['error_message'])

        # Add UDPv6, should fail
        error_message = (
            f"L2 or UPPv4 or UDPv6, these parameters can not be mixed, "
            f"section: {section_a}, new parameter:UDPv6 vs existing parameter:L2"
        )
        response = self._patch_section_parameters(
            constants.PTP_PATCH_OPERATION_ADD,
            section_a, ["UDPv6=::1"], expect_errors=True
        )
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn(error_message, response.json['error_message'])

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
        fake_section = "global"
        error_message = ("No PTP parameter object found for %s's %s" %
            (fake_section, fake_param_keypair))
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
        fake_section = "global"
        fake_param_keypair = "%s=%s" % (fake_param_name, fake_param_value)
        error_message = ("No PTP parameter object %s's %s is owned by the given "
            "instance" % (fake_section, fake_param_keypair))
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
