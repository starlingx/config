#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import mock
import uuid
import yaml

from cgtsclient import exc
from cgtsclient.tests import test_shell
from cgtsclient.v1.service_parameter import ServiceParameter

from http import HTTPStatus
from testtools import ExpectedException

FAKE_SERVICE_PARAMETER_1 = {
    'uuid': str(uuid.uuid4()),
    'service': 'platform',
    'section': 'config',
    'name': 'sysinv_api_workers',
    'value': 10,
    'personality': None,
    'resource': None,
}

FAKE_SERVICE_PARAMETER_2 = {
    'uuid': str(uuid.uuid4()),
    'service': 'docker',
    'section': 'docker-registry',
    'name': 'url',
    'value': 'myregistry:5000/starlingx/docker.io',
    'personality': None,
    'resource': None,
}


class MockResponse:

    def __init__(self, status_code, json_data) -> None:
        self.json_data = json_data
        self.status_code = status_code

    def json(self):
        return self.json_data


class ServiceParameterTest(test_shell.ShellTest):

    def setUp(self):
        super(ServiceParameterTest, self).setUp()
        self.make_env()

    @mock.patch('cgtsclient.v1.service_parameter.ServiceParameterManager.list')
    def test_service_parameter_list(self, mock_list):
        mock_list.return_value = [
            ServiceParameter(None, FAKE_SERVICE_PARAMETER_1, True),
            ServiceParameter(None, FAKE_SERVICE_PARAMETER_2, True),
        ]

        results_str = self.shell("service-parameter-list --format yaml")
        results_list = yaml.safe_load(results_str)

        self.assertTrue(isinstance(results_list, list),
                        "service-parameter-list should return a list")

        expected_list = [FAKE_SERVICE_PARAMETER_2, FAKE_SERVICE_PARAMETER_1]
        self.assertCountEqual(expected_list, results_list)

    @mock.patch('cgtsclient.v1.service_parameter.ServiceParameterManager.get')
    def test_service_parameter_show(self, mock_get):
        mock_get.return_value = ServiceParameter(None,
                                                 FAKE_SERVICE_PARAMETER_1,
                                                 True)
        results = self.shell("service-parameter-show --format yaml "
                             f"{FAKE_SERVICE_PARAMETER_1['uuid']}")
        service_parameter = yaml.safe_load(results)

        self.assertEqual(service_parameter['service'],
                         FAKE_SERVICE_PARAMETER_1['service'])
        self.assertEqual(service_parameter['section'],
                         FAKE_SERVICE_PARAMETER_1['section'])
        self.assertEqual(service_parameter['name'],
                         FAKE_SERVICE_PARAMETER_1['name'])
        self.assertEqual(service_parameter['value'],
                         FAKE_SERVICE_PARAMETER_1['value'])

    @mock.patch(
        'cgtsclient.v1.service_parameter.ServiceParameterManager.apply'
    )
    def test_service_parameter_apply(self, mock_apply):
        resp = MockResponse(HTTPStatus.OK, {})
        mock_apply.return_value = (resp, resp.json())
        self.shell("service-parameter-apply"
                   f" --section {FAKE_SERVICE_PARAMETER_1['section']}"
                   f" {FAKE_SERVICE_PARAMETER_1['service']}")
        mock_apply.assert_called_once()

    @mock.patch(
        'cgtsclient.v1.service_parameter.ServiceParameterManager.apply'
    )
    def test_service_parameter_apply_invalid(self, mock_apply):
        mock_apply.side_effect = exc.HTTPNotFound()
        exception_str = 'Failed to apply service parameters'
        with ExpectedException(exc.CommandError, exception_str):
            self.shell("service-parameter-apply --section invalid_section"
                       " invalid_service")

    @mock.patch(
        'cgtsclient.v1.service_parameter.ServiceParameterManager.delete'
    )
    def test_service_parameter_delete(self, mock_delete):
        self.shell(f"service-parameter-delete"
                   f" {FAKE_SERVICE_PARAMETER_1['uuid']}")
        mock_delete.assert_called_once()

    @mock.patch(
        'cgtsclient.v1.service_parameter.ServiceParameterManager.get'
    )
    @mock.patch(
        'cgtsclient.v1.service_parameter.ServiceParameterManager.create'
    )
    def test_service_parameter_add(self, mock_create, mock_get):
        body = {
            'parameters': [
                FAKE_SERVICE_PARAMETER_1
            ]
        }
        mock_create.return_value = ServiceParameter(None,
                                                    body,
                                                    True)
        mock_get.return_value = ServiceParameter(None,
                                                 FAKE_SERVICE_PARAMETER_1,
                                                 True)
        self.shell("service-parameter-add"
                   f" {FAKE_SERVICE_PARAMETER_1['service']}"
                   f" {FAKE_SERVICE_PARAMETER_1['section']}"
                   f" {FAKE_SERVICE_PARAMETER_1['name']}="
                   f" {FAKE_SERVICE_PARAMETER_1['value']}")
        mock_create.assert_called_once()
        mock_get.assert_called_once()

    def test_service_parameter_add_invalid_parameters(self):
        custom_resource = "::platform::config::params::custom"
        keyvaluepairs = "param1=true param2=disabled param3=10"
        exception_str =\
            "Cannot specify multiple parameters with custom resource."
        with ExpectedException(exc.CommandError, exception_str):
            self.shell("service-parameter-add platform config "
                       f" {keyvaluepairs} "
                       f"--resource {custom_resource}")

    @mock.patch(
        'cgtsclient.v1.service_parameter.ServiceParameterManager.create'
    )
    def test_service_parameter_add_failed(self, mock_create):
        mock_create.side_effect = exc.HTTPNotFound()
        attributes =\
            {
                FAKE_SERVICE_PARAMETER_1['name']:
                str(FAKE_SERVICE_PARAMETER_1['value'])
            }
        exception_str = \
            f'Failed to create Service parameters: {attributes} '
        with ExpectedException(exc.CommandError, exception_str):
            self.shell("service-parameter-add"
                       f" {FAKE_SERVICE_PARAMETER_1['service']}"
                       f" {FAKE_SERVICE_PARAMETER_1['section']}"
                       f" {FAKE_SERVICE_PARAMETER_1['name']}="
                       f"{FAKE_SERVICE_PARAMETER_1['value']}")

    @mock.patch(
        'cgtsclient.v1.service_parameter.ServiceParameterManager.list'
    )
    @mock.patch(
        'cgtsclient.v1.service_parameter.ServiceParameterManager.update')
    def test_service_parameter_modify(self, mock_update, mock_list):
        FAKE_SERVICE_PARAMETER_1_MODIFIED = FAKE_SERVICE_PARAMETER_1
        FAKE_SERVICE_PARAMETER_1_MODIFIED['value'] = 15
        mock_list.return_value = [
            ServiceParameter(None, FAKE_SERVICE_PARAMETER_1, True),
            ServiceParameter(None, FAKE_SERVICE_PARAMETER_2, True),
        ]
        mock_update.return_value = \
            ServiceParameter(None, FAKE_SERVICE_PARAMETER_1_MODIFIED, True)
        r = self.shell("service-parameter-modify"
                       f" {FAKE_SERVICE_PARAMETER_1['service']}"
                       f" {FAKE_SERVICE_PARAMETER_1['section']}"
                       f" {FAKE_SERVICE_PARAMETER_1['name']}="
                       f"{FAKE_SERVICE_PARAMETER_1_MODIFIED['value']}"
                       " --format yaml")

        mock_list.assert_called_once()
        mock_update.assert_called_once()

        service_parameter = yaml.safe_load(r)
        self.assertEqual(service_parameter['service'],
                         FAKE_SERVICE_PARAMETER_1['service'])
        self.assertEqual(service_parameter['section'],
                         FAKE_SERVICE_PARAMETER_1['section'])
        self.assertEqual(service_parameter['name'],
                         FAKE_SERVICE_PARAMETER_1['name'])
        self.assertEqual(service_parameter['value'],
                         FAKE_SERVICE_PARAMETER_1_MODIFIED['value'])

    def test_service_parameter_modify_invalid_parameters(self):
        custom_resource = "::platform::config::params::custom"
        keyvaluepairs = "param1=true param2=disabled param3=10"
        exception_str = \
            "Cannot specify multiple parameters with custom resource."
        with ExpectedException(exc.CommandError, exception_str):
            self.shell("service-parameter-modify platform config "
                       f" {keyvaluepairs} "
                       f"--resource {custom_resource}")
