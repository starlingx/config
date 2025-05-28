# Copyright (c) 2019-2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import itertools
import mock
import random
from six.moves import http_client
from six.moves.urllib.parse import urlencode

from sysinv.common import constants
from sysinv.db import api as dbapi
from sysinv.tests.api import base
from sysinv.api.controllers.v1 import label as policylabel
from sysinv.tests.db import utils as dbutils
from sysinv.tests.db import base as dbbase
import wsme


HEADER = {'User-Agent': 'sysinv'}
es_labels = {'elastic-data': 'enabled',
                'elastic-controller': 'enabled',
                'elastic-client': 'enabled',
                'elastic-master': 'enabled', }

es_worker_labels = {'elastic-master': 'enabled'}
es_invalid_worker_labels = {'elastic-master': 'mandalorian'}


def mock_helm_override_get(dbapi, app_name, chart_name, namespace):
    return True


def mock_get_system_enabled_k8s_plugins_return_plugins():
    return {"intel-gpu-plugin": "intelgpu=enabled",
            "intel-qat-plugin": "intelqat=enabled"}


def mock_get_system_enabled_k8s_plugins_return_none():
    return None


class LabelTestCase(base.FunctionalTest):

    def setUp(self):
        super(LabelTestCase, self).setUp()

    def _get_path(self, host=None, params=None):
        if host:
            path = '/labels/' + host
        else:
            path = '/labels'

        if params:
            path += '?' + urlencode(params)
        return path

    def validate_labels(self, input_data, response_data):
        self.assertEqual(len(input_data), len(response_data))
        for label in response_data:
            label_key = label["label_key"]
            label_value = label["label_value"]
            self.assertIn(label_key, input_data.keys())
            self.assertEqual(label_value, input_data[label_key])

    def assign_labels(self, host_uuid, input_data, parameters=None):
        response = self.post_json('%s' % self._get_path(host_uuid, parameters), input_data)
        self.assertEqual(http_client.OK, response.status_int)
        return response

    def assign_labels_failure(self, host_uuid, input_data, parameters=None):
        response = self.post_json('%s' % self._get_path(host_uuid, parameters), input_data, expect_errors=True)
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertTrue(response.json['error_message'])

    def get_host_labels(self, host_uuid):
        response = self.get_json("/ihosts/%s/labels" % host_uuid)
        return response['labels']


class LabelAssignTestCase(LabelTestCase):

    def setUp(self):
        super(LabelAssignTestCase, self).setUp()
        self.dbapi = dbapi.get_instance()
        self.system = dbutils.create_test_isystem()
        self.controller = dbutils.create_test_ihost(
            id='1',
            uuid=None,
            forisystemid=self.system.id,
            hostname='controller-0',
            personality=constants.CONTROLLER,
            subfunctions=constants.CONTROLLER,
            invprovision=constants.PROVISIONED
        )
        self.worker = dbutils.create_test_ihost(
            id='2',
            uuid=None,
            forisystemid=self.system.id,
            hostname='worker-1',
            personality=constants.WORKER,
            subfunctions=constants.WORKER,
            mgmt_mac='01:02:03:04:05:C5',
            mgmt_ip='192.168.24.14',
            invprovision=constants.PROVISIONED,
        )

    generic_labels = {
        'apps': 'enabled',
        'foo': 'bar'
    }

    def test_create_labels(self):
        host_uuid = self.worker.uuid
        input_data = self.generic_labels
        self.assign_labels(host_uuid, input_data)
        response_data = self.get_host_labels(host_uuid)
        self.validate_labels(input_data, response_data)

    def test_overwrite_labels_success(self):
        host_uuid = self.worker.uuid
        input_data = self.generic_labels
        self.assign_labels(host_uuid, input_data)

        new_input_values = {
            'apps': 'disabled',
            'foo': 'free'
        }
        self.assign_labels(host_uuid, new_input_values, parameters={'overwrite': True})
        response_data = self.get_host_labels(host_uuid)
        self.validate_labels(new_input_values, response_data)

    def test_overwrite_labels_failure(self):
        host_uuid = self.worker.uuid
        input_data = self.generic_labels
        self.assign_labels(host_uuid, input_data)

        new_input_values = {
            'apps': 'disabled',
            'foo': 'free'
        }
        # Default value should be overwrite=False
        self.assign_labels_failure(host_uuid, new_input_values)
        # Test explicit overwrite=False
        self.assign_labels_failure(host_uuid, new_input_values, parameters={'overwrite': False})

        # Labels should be unchanged from initial values
        response_data = self.get_host_labels(host_uuid)
        self.validate_labels(input_data, response_data)

    def test_create_validated_labels_success(self):
        host_uuid = self.worker.uuid
        cpu_mgr_label = {
            'kube-cpu-mgr-policy': 'static',
        }
        self.assign_labels(host_uuid, cpu_mgr_label)
        topology_mgr_label = {
            'kube-topology-mgr-policy': 'restricted',
        }
        self.assign_labels(host_uuid, topology_mgr_label)
        memory_mgr_label = {
            'kube-memory-mgr-policy': 'Static',
        }
        self.assign_labels(host_uuid, memory_mgr_label)

        input_data = {}
        for input_label in [cpu_mgr_label, topology_mgr_label, memory_mgr_label]:
            input_data.update(input_label)

        response_data = self.get_host_labels(host_uuid)
        self.validate_labels(input_data, response_data)

    def test_create_validated_labels_failure(self):
        host_uuid = self.worker.uuid
        cpu_mgr_label = {
            'kube-cpu-mgr-policy': 'invalid',
        }
        self.assign_labels_failure(host_uuid, cpu_mgr_label)
        topology_mgr_label = {
            'kube-topology-mgr-policy': 'invalid',
        }
        self.assign_labels_failure(host_uuid, topology_mgr_label)
        memory_mgr_label = {
            'kube-memory-mgr-policy': 'invalid',
        }
        self.assign_labels_failure(host_uuid, memory_mgr_label)

    def test_create_validated_labels_unsupported(self):
        host_uuid = self.worker.uuid
        cpu_mgr_label = {
            'kube-cpu-mgr-policy': 'none',
        }
        self.assign_labels_failure(host_uuid, cpu_mgr_label)

    @mock.patch('sysinv.api.controllers.v1.label._case_agnostic_check')
    def test_valid_topology_manager_label(self, mock_case_check):
        body = {
            constants.KUBE_TOPOLOGY_MANAGER_LABEL: 'best-effort'
        }

        policylabel._semantic_check_worker_labels(body)

        mock_case_check.assert_called_once_with('best-effort',
                    constants.KUBE_TOPOLOGY_MANAGER_VALUES, constants.KUBE_TOPOLOGY_MANAGER_LABEL)

    @mock.patch('sysinv.api.controllers.v1.label._case_agnostic_check')
    def test_invalid_topology_manager_label(self, mock_case_check):
        body = {
            constants.KUBE_TOPOLOGY_MANAGER_LABEL: 'BestEffort'
        }

        # Simulate invalid value in allowed values for KUBE_TOPOLOGY_MANAGER_LABEL
        mock_case_check.side_effect = wsme.exc.ClientSideError(
            "Invalid value for %s label." % constants.KUBE_TOPOLOGY_MANAGER_LABEL
        )

        self.assertRaises(wsme.exc.ClientSideError, policylabel._semantic_check_worker_labels, body)

        mock_case_check.assert_called_once_with('BestEffort',
                constants.KUBE_TOPOLOGY_MANAGER_VALUES, constants.KUBE_TOPOLOGY_MANAGER_LABEL)

    @mock.patch('sysinv.api.controllers.v1.label._case_agnostic_check')
    def test_valid_cpu_mgr_policy_label(self, mock_case_check):
        body = {
            'kube-cpu-mgr-policy': 'static'
        }

        policylabel._semantic_check_worker_labels(body)

        mock_case_check.assert_called_once_with('static',
                        constants.KUBE_CPU_MEMORY_MANAGER_VALUES, 'kube-cpu-mgr-policy')

    @mock.patch('sysinv.api.controllers.v1.label._case_agnostic_check')
    def test_invalid_cpu_mgr_policy_label(self, mock_case_check):
        body = {
            'kube-cpu-mgr-policy': 'invalid_policy'
        }

        # Simulate invalid value in allowed values for 'kube-cpu-mgr-policy'
        mock_case_check.side_effect = wsme.exc.ClientSideError(
            "Invalid value for %s label." % 'kube-cpu-mgr-policy'
        )

        self.assertRaises(wsme.exc.ClientSideError, policylabel._semantic_check_worker_labels,
                                                                                 body)

        mock_case_check.assert_called_once_with('invalid_policy',
                              constants.KUBE_CPU_MEMORY_MANAGER_VALUES, 'kube-cpu-mgr-policy')

    @mock.patch('sysinv.api.controllers.v1.label._case_agnostic_check')
    def test_invalid_kube_cpu_mgr_policy_none(self, mock_case_check):
        body = {
            'kube-cpu-mgr-policy': 'None'
        }

        # Simulate 'none' value which should raise an error
        mock_case_check.side_effect = wsme.exc.ClientSideError(
            "Setting kube-cpu-mgr-policy to 'none' is not supported"
        )

        self.assertRaises(wsme.exc.ClientSideError, policylabel._semantic_check_worker_labels,
                                                                   body)

        mock_case_check.assert_not_called()

    @mock.patch('sysinv.api.controllers.v1.label._case_agnostic_check')
    def test_valid_memory_manager_label(self, mock_case_check):
        body = {
            constants.KUBE_MEMORY_MANAGER_LABEL: 'StaTIc'
        }

        policylabel._semantic_check_worker_labels(body)

        mock_case_check.assert_called_once_with('StaTIc',
                constants.KUBE_CPU_MEMORY_MANAGER_VALUES, constants.KUBE_MEMORY_MANAGER_LABEL)

    @mock.patch('sysinv.api.controllers.v1.label._case_agnostic_check')
    def test_invalid_memory_manager_label(self, mock_case_check):
        body = {
            constants.KUBE_MEMORY_MANAGER_LABEL: 'invalid_policy'
        }

        # Simulate invalid value in allowed values for KUBE_MEMORY_MANAGER_LABEL
        mock_case_check.side_effect = wsme.exc.ClientSideError(
            "Invalid value for %s label." % constants.KUBE_MEMORY_MANAGER_LABEL
        )

        self.assertRaises(wsme.exc.ClientSideError, policylabel._semantic_check_worker_labels,
                                                body)

        mock_case_check.assert_called_once_with('invalid_policy',
                 constants.KUBE_CPU_MEMORY_MANAGER_VALUES, constants.KUBE_MEMORY_MANAGER_LABEL)

    @mock.patch('sysinv.api.controllers.v1.label._get_system_enabled_k8s_plugins',
                mock_get_system_enabled_k8s_plugins_return_plugins)
    def test_create_plugin_labels_on_supported_node(self):
        dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pclass='VGA compatible controller',
            driver='i915',)

        test_plugin_label = {'intelgpu': 'enabled', }
        self.assign_labels(self.worker.uuid, test_plugin_label)

        response_data = self.get_host_labels(self.worker.uuid)
        self.validate_labels(test_plugin_label, response_data)

    @mock.patch('sysinv.api.controllers.v1.label._get_system_enabled_k8s_plugins',
                mock_get_system_enabled_k8s_plugins_return_plugins)
    def test_create_plugin_labels_on_unsupported_node(self):
        dbutils.create_test_pci_device(
            host_id=self.worker.id,
            pclass='VGA compatible controller',
            driver='',)
        test_plugin_label = {'intelgpu': 'enabled', }
        self.assign_labels_failure(self.worker.uuid, test_plugin_label)

    @mock.patch('sysinv.api.controllers.v1.label._get_system_enabled_k8s_plugins',
                mock_get_system_enabled_k8s_plugins_return_none)
    def test_create_plugin_labels_on_non_plugin_system(self):
        test_plugin_label = {'intelgpu': 'enabled', }

        self.assign_labels(self.worker.uuid, test_plugin_label)

        response_data = self.get_host_labels(self.worker.uuid)
        self.validate_labels(test_plugin_label, response_data)


class FakeConductorAPI(object):

    def __init__(self):
        self.update_kubernetes_label = mock.MagicMock()
        self.update_grub_config = mock.MagicMock()
        self.configure_power_manager = mock.MagicMock()
        self.configure_stalld = mock.MagicMock()


class StalldLabelTestCase(LabelTestCase, dbbase.BaseHostTestCase):

    def _create_host(self, personality, subfunction=None,
                     mgmt_mac=None, mgmt_ip=None,
                     admin=None,
                     invprovision=constants.PROVISIONED, **kw):
        host = self._create_test_host(personality=personality,
                                      subfunction=subfunction,
                                      administrative=(admin or
                                      constants.ADMIN_UNLOCKED),
                                      invprovision=invprovision,
                                      **kw)
        return host

    def _setup_context(self):
        self.fake_conductor_api = FakeConductorAPI()
        p = mock.patch('sysinv.conductor.rpcapiproxy.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)

    def _create_standard_system(self):
        self.controller = self._create_host(constants.CONTROLLER)
        self.worker = self._create_host(constants.WORKER)
        self._create_test_host_cpus(self.worker,
                                    application=8)
        self.storage = self._create_host(constants.STORAGE)

    def _create_aio_system(self):
        self.controller = self._create_host(constants.CONTROLLER,
                                            subfunction=constants.WORKER)
        self._create_test_host_cpus(self.controller,
                                    platform=2,
                                    application=6)

    def setUp(self):
        super(StalldLabelTestCase, self).setUp()
        self._setup_context()

    def test_stalld_enable_successful_on_aio_controller(self):
        self._create_aio_system()
        host_uuid = self.controller.uuid
        input_data = {
            constants.LABEL_STALLD: constants.LABEL_VALUE_STALLD_ENABLED
        }
        parameters = {'overwrite': True}
        self.assign_labels(host_uuid, input_data, parameters)
        response_data = self.get_host_labels(host_uuid)
        self.validate_labels(input_data, response_data)

        # Verify that the method configure_stalld() is called
        self.fake_conductor_api.configure_stalld.assert_called_once()

    def test_stalld_disable_successful_on_aio_controller(self):
        self._create_aio_system()
        host_uuid = self.controller.uuid
        input_data = {
            constants.LABEL_STALLD: constants.LABEL_VALUE_STALLD_DISABLED
        }
        parameters = {'overwrite': True}
        self.assign_labels(host_uuid, input_data, parameters)
        response_data = self.get_host_labels(host_uuid)
        self.validate_labels(input_data, response_data)

        # Verify that the method configure_stalld() is called
        self.fake_conductor_api.configure_stalld.assert_called_once()

    def test_stalld_enable_successful_on_worker_node(self):
        self._create_standard_system()
        host_uuid = self.worker.uuid
        input_data = {
            constants.LABEL_STALLD: constants.LABEL_VALUE_STALLD_ENABLED
        }
        parameters = {'overwrite': True}
        self.assign_labels(host_uuid, input_data, parameters)
        response_data = self.get_host_labels(host_uuid)
        self.validate_labels(input_data, response_data)

        # Verify that the method configure_stalld() is called
        self.fake_conductor_api.configure_stalld.assert_called_once()

    def test_stalld_disable_successful_on_worker_node(self):
        self._create_standard_system()
        host_uuid = self.worker.uuid
        input_data = {
            constants.LABEL_STALLD: constants.LABEL_VALUE_STALLD_DISABLED
        }
        parameters = {'overwrite': True}
        self.assign_labels(host_uuid, input_data, parameters)
        response_data = self.get_host_labels(host_uuid)
        self.validate_labels(input_data, response_data)

        # Verify that the method configure_stalld() is called
        self.fake_conductor_api.configure_stalld.assert_called_once()

    def test_stalld_enable_fails_on_standard_controller(self):
        self._create_standard_system()
        host_uuid = self.controller.uuid
        input_data = {
            constants.LABEL_STALLD: constants.LABEL_VALUE_STALLD_ENABLED
        }
        parameters = {'overwrite': True}
        self.assign_labels_failure(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is not called
        self.fake_conductor_api.configure_stalld.assert_not_called()

    def test_stalld_enable_fails_on_storage_node(self):
        self._create_standard_system()
        host_uuid = self.storage.uuid
        input_data = {
            constants.LABEL_STALLD: constants.LABEL_VALUE_STALLD_ENABLED
        }
        parameters = {'overwrite': True}
        self.assign_labels_failure(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is not called
        self.fake_conductor_api.configure_stalld.assert_not_called()

    def test_stalld_assign_application_cpus_successful(self):
        """Labels assigned together
        """
        self._create_standard_system()
        host_uuid = self.worker.uuid
        input_data = {
            constants.LABEL_STALLD: constants.LABEL_VALUE_STALLD_ENABLED,
            constants.LABEL_STALLD_CPU_FUNCTIONS: constants.LABEL_VALUE_CPU_APPLICATION
        }
        parameters = {'overwrite': True}
        self.assign_labels(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is called
        self.fake_conductor_api.configure_stalld.assert_called_once()

    def test_stalld_assign_all_cpus_successful(self):
        """Labels assigned together
        """
        self._create_standard_system()
        host_uuid = self.worker.uuid
        input_data = {
            constants.LABEL_STALLD: constants.LABEL_VALUE_STALLD_ENABLED,
            constants.LABEL_STALLD_CPU_FUNCTIONS: constants.LABEL_VALUE_CPU_ALL
        }
        parameters = {'overwrite': True}
        self.assign_labels(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is called
        self.fake_conductor_api.configure_stalld.assert_called_once()

    def test_stalld_assign_application_isolated_cpus_fails(self):
        """Fails because no cpus are assigned to application isolated function
           on the worker node.
        """
        self._create_standard_system()
        host_uuid = self.worker.uuid
        input_data = {
            constants.LABEL_STALLD: constants.LABEL_VALUE_STALLD_ENABLED,
            constants.LABEL_STALLD_CPU_FUNCTIONS: constants.LABEL_VALUE_CPU_APPLICATION_ISOLATED
        }
        parameters = {'overwrite': True}
        self.assign_labels_failure(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is not called
        self.fake_conductor_api.configure_stalld.assert_not_called()

    def _generate_case_insensite_permutations(self,
                                              label_values: list[str],
                                              sample_size=5) -> list:
        all_permutations = []
        for label_value in label_values:
            character_tuples = ((c.lower(), c.upper()) for c in label_value)
            label_permutations = [
                ''.join(x) for x in itertools.product(*character_tuples)
            ]
            # randomly sample 'n' permutation because the list could be very long
            sample_size = min(sample_size, len(label_permutations))
            all_permutations.extend(random.sample(label_permutations,
                                                  k=sample_size))
        return all_permutations

    def test_stalld_assign_case_insensitive(self):
        """Labels assigned together
        """
        self._create_standard_system()
        host_uuid = self.worker.uuid
        label_values = self._generate_case_insensite_permutations([
            'enabled',
            'disabled'
        ])
        parameters = {'overwrite': True}
        for label_value in label_values:
            input_data = {
                constants.LABEL_STALLD: label_value
            }
            self.assign_labels(host_uuid, input_data, parameters)

            # Verify that the method configure_stalld() is called
            self.fake_conductor_api.configure_stalld.assert_called_once()
            self.fake_conductor_api.configure_stalld.reset_mock()

    def test_stalld_assign_cpu_function_case_insensitive(self):
        """Labels assigned together
        """
        self._create_standard_system()
        host_uuid = self.worker.uuid
        label_values = self._generate_case_insensite_permutations([
            'all',
            'Application',
            'Application-isolated'
        ])
        parameters = {'overwrite': True}
        for label_value in label_values:
            input_data = {
                constants.LABEL_STALLD_CPU_FUNCTIONS: label_value
            }
            self.assign_labels(host_uuid, input_data, parameters)

            # Verify that the method configure_stalld() is called
            self.fake_conductor_api.configure_stalld.assert_called_once()
            self.fake_conductor_api.configure_stalld.reset_mock()

    def test_stalld_enable_fails_if_assigned_app_iso_cpus_prior(self):
        """Fails because no cpus are assigned to application isolated function
           on the worker node.
           While stalld is disabled we can assign the isolated cpu functions
           but if we try to enable stalld it will fail
        """
        self._create_standard_system()
        host_uuid = self.worker.uuid
        input_data = {
            constants.LABEL_STALLD: constants.LABEL_VALUE_STALLD_DISABLED,
            constants.LABEL_STALLD_CPU_FUNCTIONS: constants.LABEL_VALUE_CPU_APPLICATION_ISOLATED
        }
        parameters = {'overwrite': True}
        self.assign_labels(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is called
        self.fake_conductor_api.configure_stalld.assert_called_once()

        # after cpu functions are assigned attempt to enable stalld
        self.fake_conductor_api.configure_stalld.reset_mock()
        input_data = {
            constants.LABEL_STALLD: constants.LABEL_VALUE_STALLD_ENABLED
        }
        parameters = {'overwrite': True}
        self.assign_labels_failure(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is not called
        self.fake_conductor_api.configure_stalld.assert_not_called()

    def test_stalld_assign_cpus_before_enable_successful(self):
        """Labels assigned in sequence
           1. starlingx.io/stalld_cpu_functions=application
           2. starlingx.io/stalld_cpu_functions=all
           3. starlingx.io/stalld=enabled
        """
        self._create_standard_system()
        host_uuid = self.worker.uuid
        input_data = {
            constants.LABEL_STALLD_CPU_FUNCTIONS: constants.LABEL_VALUE_CPU_APPLICATION
        }
        parameters = {'overwrite': True}
        self.assign_labels(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is called
        self.fake_conductor_api.configure_stalld.assert_called_once()
        self.fake_conductor_api.configure_stalld.reset_mock()

        input_data = {
            constants.LABEL_STALLD_CPU_FUNCTIONS: constants.LABEL_VALUE_CPU_ALL
        }
        parameters = {'overwrite': True}
        self.assign_labels(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is called
        self.fake_conductor_api.configure_stalld.assert_called_once()
        self.fake_conductor_api.configure_stalld.reset_mock()

        input_data = {
            constants.LABEL_STALLD: constants.LABEL_VALUE_STALLD_ENABLED
        }
        parameters = {'overwrite': True}
        self.assign_labels(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is called
        self.fake_conductor_api.configure_stalld.assert_called_once()

    def test_stalld_assign_different_cpu_functions(self):
        """Labels assigned in sequence
           1. starlingx.io/stalld=enabled
           2. starlingx.io/stalld_cpu_functions=all
           3. starlingx.io/stalld_cpu_functions=application
           4. starlingx.io/stalld_cpu_functions=application-isolated <- fails
           5. assign application-isolated function to 1 cpu of the worker node
           6. starlingx.io/stalld_cpu_functions=application-isolated <- success
        """
        self._create_standard_system()
        host_uuid = self.worker.uuid
        input_data = {
            constants.LABEL_STALLD: constants.LABEL_VALUE_STALLD_ENABLED
        }
        parameters = {'overwrite': True}
        self.assign_labels(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is called
        self.fake_conductor_api.configure_stalld.assert_called_once()
        self.fake_conductor_api.configure_stalld.reset_mock()

        input_data = {
            constants.LABEL_STALLD_CPU_FUNCTIONS: constants.LABEL_VALUE_CPU_ALL
        }
        parameters = {'overwrite': True}
        self.assign_labels(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is called
        self.fake_conductor_api.configure_stalld.assert_called_once()
        self.fake_conductor_api.configure_stalld.reset_mock()

        input_data = {
            constants.LABEL_STALLD_CPU_FUNCTIONS: constants.LABEL_VALUE_CPU_APPLICATION
        }
        parameters = {'overwrite': True}
        self.assign_labels(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is called
        self.fake_conductor_api.configure_stalld.assert_called_once()
        self.fake_conductor_api.configure_stalld.reset_mock()

        input_data = {
            constants.LABEL_STALLD_CPU_FUNCTIONS: constants.LABEL_VALUE_CPU_APPLICATION_ISOLATED
        }
        parameters = {'overwrite': True}
        self.assign_labels_failure(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is called
        self.fake_conductor_api.configure_stalld.assert_not_called()
        self.fake_conductor_api.configure_stalld.reset_mock()

        # Change the last cpu to application-isolated
        last_cpu = self.dbapi.icpu_get_by_ihost(host_uuid)[-1]
        values = {"allocated_function": constants.ISOLATED_FUNCTION}
        self.dbapi.icpu_update(last_cpu.uuid, values)

        # try again
        self.assign_labels(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is called
        self.fake_conductor_api.configure_stalld.assert_called_once()

    def test_stalld_assign_custom_label_to_worker_successful(self):
        """Custom stalld label on worker node
           1. starlingx.io/stalld.custom_label=custom_value
        """
        self._create_standard_system()
        host_uuid = self.worker.uuid
        custom_stalld_label = f"{constants.LABEL_STALLD}.customlabel"
        input_data = {
            custom_stalld_label: "custom_value"
        }
        parameters = {'overwrite': True}
        self.assign_labels(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is called
        self.fake_conductor_api.configure_stalld.assert_called_once()

    def test_stalld_assign_custom_label_to_storage_fails(self):
        """Custom stalld label on worker node
           1. starlingx.io/stalld.custom_label=custom_value
        """
        self._create_standard_system()
        host_uuid = self.storage.uuid
        custom_stalld_label = f"{constants.LABEL_STALLD}.customlabel"
        input_data = {
            custom_stalld_label: "custom_value"
        }
        parameters = {'overwrite': True}
        self.assign_labels_failure(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is not called
        self.fake_conductor_api.configure_stalld.assert_not_called()

    def test_stalld_assign_custom_label_invalid_format(self):
        """Custom stalld label on worker node
           1. starlingx.io/stalld_custom_label=custom_value
           should be a '.' not an '_' character
        """
        self._create_standard_system()
        host_uuid = self.worker.uuid
        custom_stalld_label = f"{constants.LABEL_STALLD}_customlabel"
        input_data = {
            custom_stalld_label: "custom_value"
        }
        parameters = {'overwrite': True}
        self.assign_labels_failure(host_uuid, input_data, parameters)

        # Verify that the method configure_stalld() is not called
        self.fake_conductor_api.configure_stalld.assert_not_called()
