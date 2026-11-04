# Copyright (c) 2021-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from six.moves import http_client
import mock
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

    def _patch_section_parameters(self, op, section, section_parameters, expect_errors=False, instance_uuid=None):
        if instance_uuid is None:
            instance_uuid = self.uuid

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
            self.get_single_url(instance_uuid),
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

    def test_update_ptp_instance_add_unicast_master_table_same_section_ok(self):
        ptp_instance2 = dbutils.create_test_ptp_instance(
            name='test-instance-2',
            service=constants.PTP_INSTANCE_TYPE_PTP4L)
        uuid2 = ptp_instance2['uuid']

        umt_parameters = [
            (
                self.uuid,
                'unicast_master_table_1',
                [
                    "table_id=1",
                    "logQueryInterval=0",
                    "peer_address=1.2.3.4",
                    "L2=00:00:00:00:00:01",
                    "L2=00:00:00:00:00:02"
                ]
            ),
            (
                uuid2,
                'unicast_master_table_1',
                [
                    "table_id=1",
                    "logQueryInterval=1",
                    "peer_address=::1",
                    "UDPv4=1.2.3.4",
                    "UDPv4=1.2.3.5"
                ]
            ),
        ]
        for instance_uuid, section, section_parameters in umt_parameters:
            response = self._patch_section_parameters(
                constants.PTP_PATCH_OPERATION_ADD,
                section, section_parameters, instance_uuid=instance_uuid
            )
            self.assertEqual(response.content_type, 'application/json')
            self.assertEqual(response.status_code, http_client.OK)

    def test_update_ptp_instance_add_unicast_master_table_different_sections_same_table_id_ok(self):
        ptp_instance2 = dbutils.create_test_ptp_instance(
            name='test-instance-2',
            service=constants.PTP_INSTANCE_TYPE_PTP4L)
        uuid2 = ptp_instance2['uuid']

        umt_parameters = [
            (
                self.uuid,
                'unicast_master_table_A',
                [
                    "table_id=1",
                    "logQueryInterval=0",
                    "peer_address=1.2.3.4"
                ]
            ),
            (
                uuid2,
                'unicast_master_table_B',
                [
                    "table_id=1",
                    "logQueryInterval=1",
                    "peer_address=::1"
                ]
            ),
        ]
        for instance_uuid, section, section_parameters in umt_parameters:
            response = self._patch_section_parameters(
                constants.PTP_PATCH_OPERATION_ADD,
                section, section_parameters, instance_uuid=instance_uuid
            )
            self.assertEqual(response.content_type, 'application/json')
            self.assertEqual(response.status_code, http_client.OK)

    def test_update_ptp_instance_add_unicast_master_table_table_id_non_unique_fail(self):
        ptp_instance2 = dbutils.create_test_ptp_instance(
            name='test-instance-2',
            service=constants.PTP_INSTANCE_TYPE_PTP4L)
        uuid2 = ptp_instance2['uuid']

        umt_parameters = [
            (
                self.uuid,
                'unicast_master_table_1',
                [
                    "table_id=1"
                ]
            ),
            (
                uuid2,
                'unicast_master_table_inst2_1',
                [
                    "table_id=1",
                ]
            ),
        ]
        for instance_uuid, section, section_parameters in umt_parameters:
            response = self._patch_section_parameters(
                constants.PTP_PATCH_OPERATION_ADD,
                section, section_parameters, instance_uuid=instance_uuid
            )
            self.assertEqual(response.content_type, 'application/json')
            self.assertEqual(response.status_code, http_client.OK)

        umt_parameters_2 = [
            (
                uuid2,
                'unicast_master_table_1',
                [
                    "table_id=1",
                ]
            ),
        ]

        # Adding new section with duplicate table_id value should fail
        error_message = f"table_id=1 is not unique, already exist in {umt_parameters[1][1]}"
        for instance_uuid, section, section_parameters in umt_parameters_2:
            response = self._patch_section_parameters(
                constants.PTP_PATCH_OPERATION_ADD,
                section, section_parameters, instance_uuid=instance_uuid,
                expect_errors=True
            )
            self.assertEqual(response.content_type, 'application/json')
            self.assertEqual(response.status_code, http_client.BAD_REQUEST)
            self.assertIn(error_message, response.json['error_message'])

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
            f"L2 or UDPv4 or UDPv6, these parameters can not be mixed, "
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
            f"L2 or UDPv4 or UDPv6, these parameters can not be mixed, "
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


class TestUpdatePtpInstanceAptsMgr(BasePtpInstanceTestCase):
    uuid = None

    def setUp(self):
        super(TestUpdatePtpInstanceAptsMgr, self).setUp()
        ptp_instance = dbutils.create_test_ptp_instance(
            name='test-dpll-mgr',
            service=constants.PTP_INSTANCE_TYPE_DPLL_MGR)
        self.uuid = ptp_instance['uuid']

    def test_add_config_json_valid(self):
        """Add config_json with valid full JSON."""
        json_value = '{"global":{"operation_mode":"SW_BASED"},"dpll":{"dpll0":{"name":"DPLL0_FREQ"}}}'
        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'section': 'config_json',
              'value': 'config_json=%s' % json_value,
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_add_config_json_invalid_json(self):
        """Reject config_json with malformed JSON."""
        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'section': 'config_json',
              'value': 'config_json={bad json',
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS,
            expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('Invalid JSON value', response.json['error_message'])

    def test_add_config_json_unsupported_section(self):
        """Reject config_json with unsupported section in JSON."""
        json_value = '{"bad_section":{"key":"value"}}'
        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'section': 'config_json',
              'value': 'config_json=%s' % json_value,
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS,
            expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('Unsupported sections', response.json['error_message'])

    def test_add_dpll_mgr_monitoring_clockclass_passthrough_ok(self):
        """Accept clockclass_passthrough in the dpll-mgr monitoring section.

        the operator toggle is a monitoring-section param
        collectd reads from instance-monitoring.conf. dpll-mgr monitoring must be
        accepted (was previously rejected -> toggle inert -> passthrough could
        not be disabled).
        """
        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'section': 'monitoring',
              'value': 'clockclass_passthrough=disabled',
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_add_dpll_mgr_monitoring_clockclass_extended_relay_ok(self):
        """Accept clockclass_extended_relay in the dpll-mgr monitoring section.

        The extended-clockClass relay (G.8275.1 Table 2 NOTE 3) is an operator
        toggle collectd reads from instance-monitoring.conf; the dpll-mgr
        monitoring section must accept it so the relay can be opted out,
        mirroring clockclass_passthrough.
        """
        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'section': 'monitoring',
              'value': 'clockclass_extended_relay=disabled',
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_add_dpll_mgr_monitoring_unsupported_param_rejected(self):
        """Reject an unknown param in the dpll-mgr monitoring section."""
        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'section': 'monitoring',
              'value': 'not_a_real_param=1',
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS,
            expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('Unsupported dpll-mgr monitoring parameter',
                      response.json['error_message'])

    def test_add_config_json_long_value(self):
        """Accept config_json with value longer than 255 chars."""
        # Build a valid JSON > 255 chars
        large_json = '{"global":{"operation_mode":"SW_BASED"},"ptp":{"ptp_primary_attributes":{' + \
            ','.join(['"source_%d":{"clockClass":6,"clockAccuracy":"0x22","timeTraceable":1}' % i
                      for i in range(10)]) + '}}}'
        self.assertGreater(len(large_json), 255)
        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'section': 'config_json',
              'value': 'config_json=%s' % large_json,
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_replace_config_json(self):
        """Replace existing config_json with new value."""
        # Add first
        json_value1 = '{"global":{"operation_mode":"SW_BASED"}}'
        self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'section': 'config_json',
              'value': 'config_json=%s' % json_value1,
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)

        # Remove first
        self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'section': 'config_json',
              'value': 'config_json=%s' % json_value1,
              'op': constants.PTP_PATCH_OPERATION_DELETE}],
            headers=self.API_HEADERS)

        # Add new
        json_value2 = '{"global":{"operation_mode":"HW_BASED"}}'
        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'section': 'config_json',
              'value': 'config_json=%s' % json_value2,
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.OK)

    def test_delete_config_json_by_uuid(self):
        """Delete config_json parameter by UUID."""
        # Add first
        json_value = '{"global":{"operation_mode":"SW_BASED"}}'
        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'section': 'config_json',
              'value': 'config_json=%s' % json_value,
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.OK)

        # Get parameter UUID from DB
        ptp_params = self.get_json(
            '/ptp_instances/%s/ptp_parameters' % self.uuid,
            headers=self.API_HEADERS)
        param_uuid = ptp_params['ptp_parameters'][0]['uuid']

        # Delete by UUID
        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'section': 'config_json',
              'value': param_uuid,
              'op': constants.PTP_PATCH_OPERATION_DELETE}],
            headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.OK)


class TestUpdatePtpInstanceDpllMgrStructuredConfig(BasePtpInstanceTestCase):
    """Tests for the dpll-mgr structured 'config' section (story 2011783).

    Layer 1 (add time): vocabulary/format validation only.
    Layer 2 (apply time): cross-reference + required-minimum.
    """

    uuid = None

    def setUp(self):
        super(TestUpdatePtpInstanceDpllMgrStructuredConfig, self).setUp()
        ptp_instance = dbutils.create_test_ptp_instance(
            name='dpll-mgr1',
            service=constants.PTP_INSTANCE_TYPE_DPLL_MGR)
        self.uuid = ptp_instance['uuid']

    def _add_config(self, name, value, expect_errors=False):
        return self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'section': 'config',
              'value': '%s=%s' % (name, value),
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS,
            expect_errors=expect_errors)

    # ---- Layer 1: add-time vocabulary / format ----

    def test_add_config_known_key_ok(self):
        response = self._add_config('phc_interface', 'eno8703')
        self.assertEqual(response.status_code, http_client.OK)

    def test_add_config_pin_priority_map_ok(self):
        response = self._add_config(
            'dpll0_pin_priority_map', 'GNSS_REF4P:0, SDP0_REF0N:12')
        self.assertEqual(response.status_code, http_client.OK)

    def test_add_config_ptp_0_channel_warned_not_rejected(self):
        """ptp_0/1/2 forward channels are no-ops in StarlingX: the API
        warns and accepts rather than rejecting, mirroring the cgts-client,
        and does NOT store the key (the daemon never consumes it)."""
        for name in ('channel_ptp_0', 'channel_ptp_1', 'channel_ptp_2'):
            response = self._add_config(name, 'ptp01bh')
            # Accepted, not a 400.
            self.assertEqual(response.status_code, http_client.OK,
                             '%s should warn-not-reject' % name)
        # None of the warn channels were persisted.
        ptp_params = self.get_json(
            '/ptp_instances/%s/ptp_parameters' % self.uuid,
            headers=self.API_HEADERS)
        stored = {p['name'] for p in ptp_params['ptp_parameters']
                  if p['section'] == 'config'}
        self.assertNotIn('channel_ptp_0', stored)
        self.assertNotIn('channel_ptp_1', stored)
        self.assertNotIn('channel_ptp_2', stored)

    def test_add_config_unknown_key_rejected(self):
        response = self._add_config('not_a_key', 'x', expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('Unsupported dpll-mgr config key',
                      response.json['error_message'])

    def test_add_config_unknown_pin_rejected(self):
        response = self._add_config(
            'dpll0_pin_priority_map', 'NOPE_REF9Z:0', expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('Unknown dpll pin name',
                      response.json['error_message'])

    def test_add_config_priority_out_of_range_rejected(self):
        response = self._add_config(
            'dpll0_pin_priority_map', 'GNSS_REF4P:99', expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('out of range', response.json['error_message'])

    def test_add_config_priority_15_disconnect_accepted(self):
        # 15 = disconnect sentinel; a valid priority (e.g. disabling the
        # backhaul SDP pin on the EEC plane), must not be rejected.
        response = self._add_config(
            'dpll0_pin_priority_map', 'GNSS_REF4P:0, SDP0_REF0N:15')
        self.assertEqual(response.status_code, http_client.OK)

    def test_add_config_bad_operation_mode_rejected(self):
        response = self._add_config(
            'operation_mode', 'TURBO', expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('Invalid operation_mode',
                      response.json['error_message'])

    def test_add_config_primary_key_rejected(self):
        # The 'primary' hint was removed; it is no longer an accepted key.
        response = self._add_config('primary', 'gnss', expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('Unsupported dpll-mgr config key',
                      response.json['error_message'])

    def test_add_config_non_integer_holdover_rejected(self):
        response = self._add_config('ho_0', 'eight', expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('must be an integer', response.json['error_message'])

    def test_add_config_channel_not_yet_existing_accepted_at_add(self):
        """Layer 1 does NOT cross-reference; a channel may name an instance
        that does not exist yet (DM ordering)."""
        response = self._add_config('channel_ptp_bh', 'ptp01bh')
        self.assertEqual(response.status_code, http_client.OK)

    def test_config_and_raw_config_json_mutually_exclusive(self):
        # Add a raw config_json first...
        self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'section': 'config_json',
              'value': 'config_json={"global":{"operation_mode":"SW_BASED"}}',
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)
        # ...then a structured config key must be rejected.
        response = self._add_config('phc_interface', 'eno8703',
                                    expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('mutually exclusive', response.json['error_message'])

    def test_raw_config_json_rejected_when_config_exists(self):
        # Add a structured config section first...
        self._add_config('phc_interface', 'eno8703')
        # ...then a raw config_json must be rejected (reverse direction).
        response = self.patch_json(
            self.get_single_url(self.uuid),
            [{'path': constants.PTP_PARAMETER_ARRAY_PATH,
              'section': 'config_json',
              'value': 'config_json={"global":{"operation_mode":"SW_BASED"}}',
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS,
            expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('mutually exclusive', response.json['error_message'])

    def test_replace_by_name_single_row(self):
        """Re-adding ho_0 replaces the prior row (one row, not two)."""
        self._add_config('ho_0', '480')
        self._add_config('ho_0', '240')
        ptp_params = self.get_json(
            '/ptp_instances/%s/ptp_parameters' % self.uuid,
            headers=self.API_HEADERS)
        ho0_rows = [p for p in ptp_params['ptp_parameters']
                    if p['name'] == 'ho_0' and p['section'] == 'config']
        self.assertEqual(len(ho0_rows), 1)
        self.assertEqual(ho0_rows[0]['value'], '240')

    # ---- Layer 2: apply-time cross-reference + required-minimum ----

    def _assign_instance_to_controller(self, instance_id):
        response = self.patch_json(
            self.get_host_url(self.controller.uuid),
            [{'path': constants.PTP_INSTANCE_ARRAY_PATH,
              'value': instance_id,
              'op': constants.PTP_PATCH_OPERATION_ADD}],
            headers=self.API_HEADERS)
        self.assertEqual(response.status_code, http_client.OK)

    def _apply(self, expect_errors=False):
        return self.post_json(self.API_PREFIX + '/apply', {},
                              headers=self.API_HEADERS,
                              expect_errors=expect_errors)

    def test_apply_missing_required_minimum_rejected(self):
        """A config lacking a required-minimum key is rejected at apply."""
        # Only phc_interface present; missing operation_mode / channel_ptp_bh.
        self._add_config('phc_interface', 'eno8703')
        self._assign_instance_to_controller(
            self._instance_id_for_uuid(self.uuid))
        response = self._apply(expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('missing required key', response.json['error_message'])

    def test_apply_channel_references_missing_instance_rejected(self):
        """A channel naming a non-existent instance is rejected at apply."""
        self._add_config('phc_interface', 'eno8703')
        self._add_config('operation_mode', 'SW_BASED')
        self._add_config('channel_ptp_bh', 'does-not-exist')
        self._add_config('dpll0_pin_priority_map', 'GNSS_REF4P:0')
        self._assign_instance_to_controller(
            self._instance_id_for_uuid(self.uuid))
        response = self._apply(expect_errors=True)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn('does not exist', response.json['error_message'])

    @mock.patch('sysinv.conductor.rpcapi.ConductorAPI.'
                'update_ptp_instances_config')
    def test_apply_valid_config_passes(self, mock_rpc):
        """A complete, resolvable config passes Layer 2 and calls the RPC."""
        # Create a sibling ptp4l backhaul instance on the same controller.
        ptp4l = dbutils.create_test_ptp_instance(
            name='ptp01bh', service=constants.PTP_INSTANCE_TYPE_PTP4L)
        self._assign_instance_to_controller(ptp4l['id'])
        self._add_config('phc_interface', 'eno8703')
        self._add_config('operation_mode', 'SW_BASED')
        self._add_config('channel_ptp_bh', 'ptp01bh')
        self._add_config('dpll0_pin_priority_map', 'GNSS_REF4P:0, SDP0_REF0N:12')
        self._assign_instance_to_controller(
            self._instance_id_for_uuid(self.uuid))
        response = self._apply()
        self.assertEqual(response.status_code, http_client.NO_CONTENT)
        mock_rpc.assert_called_once()

    def _instance_id_for_uuid(self, uuid):
        inst = self.get_json(self.get_single_url(uuid),
                             headers=self.API_HEADERS)
        return inst['id']
