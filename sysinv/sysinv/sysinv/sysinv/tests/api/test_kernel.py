# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- encoding: utf-8 -*-
#
#
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /ihosts/<uuid>/kernel methods.
"""
import mock
from six.moves import http_client
from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase


class FakeConductorAPI(object):

    def __init__(self):
        self.kernel_runtime_manifests = mock.MagicMock()


class FakeException(Exception):
        pass


class TestKernel(base.FunctionalTest, dbbase.BaseHostTestCase):
    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    def _setup_configuration(self):
        pass

    def _setup_context(self):
        self.fake_conductor_api = FakeConductorAPI()
        p = mock.patch('sysinv.conductor.rpcapiproxy.ConductorAPI')
        self.mock_conductor_api = p.start()
        self.mock_conductor_api.return_value = self.fake_conductor_api
        self.addCleanup(p.stop)

    def setUp(self):
        super(TestKernel, self).setUp()
        self._setup_context()

    def _get_path(self, host_uuid):
        return f'/ihosts/{host_uuid}/kernel'

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


class TestPatchKernel(TestKernel):
    def setUp(self):
        super(TestPatchKernel, self).setUp()

    def test_update_worker_kernel_noop(self):
        """ Test updating the kernel from
            standard -> standard of a locked worker node
        """
        worker = self._create_host(constants.WORKER,
                                   admin=constants.ADMIN_LOCKED)
        hostid = worker['uuid']
        hostname = worker['hostname']

        # Verify DB - lowlatency is not in subfunctions before update
        host = self._get_test_host_by_hostname(hostname)
        subfunctions = host[constants.SUBFUNCTIONS]
        self.assertNotIn(constants.LOWLATENCY, subfunctions)

        url = '%s' % self._get_path(hostid)
        response = self.patch_dict_json(url,
                                        headers=self.API_HEADERS,
                                        kernel_provisioned=constants.KERNEL_STANDARD,
                                        expect_errors=False)

        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual(constants.KERNEL_STANDARD,
                         response.json['kernel_provisioned'])

        # Verify DB - lowlatency is not in subfunctions after update
        host = self._get_test_host_by_hostname(hostname)
        subfunctions = host[constants.SUBFUNCTIONS]
        self.assertNotIn(constants.LOWLATENCY, subfunctions)

        # Verify that the method that updates kernel config is not called
        self.fake_conductor_api.kernel_runtime_manifests.assert_not_called()

    def test_update_worker_kernel(self):
        """ Test updating the kernel from
            standard -> lowlatency of a locked worker node
        """
        worker = self._create_host(constants.WORKER,
                                   admin=constants.ADMIN_LOCKED)
        hostid = worker['uuid']
        hostname = worker['hostname']

        # Verify DB - lowlatency is not in subfunctions before update
        host = self._get_test_host_by_hostname(hostname)
        subfunctions = host[constants.SUBFUNCTIONS]
        self.assertNotIn(constants.LOWLATENCY, subfunctions)

        url = '%s' % self._get_path(hostid)
        response = self.patch_dict_json(url,
                                        headers=self.API_HEADERS,
                                        kernel_provisioned=constants.KERNEL_LOWLATENCY,
                                        expect_errors=False)

        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual(constants.KERNEL_LOWLATENCY,
                         response.json['kernel_provisioned'])

        # Verify DB - lowlatency is in subfunctions after update
        host = self._get_test_host_by_hostname(hostname)
        subfunctions = host[constants.SUBFUNCTIONS]
        self.assertIn(constants.LOWLATENCY, subfunctions)

        # Verify that the method that updates kernel config is called once
        self.fake_conductor_api.kernel_runtime_manifests.assert_called_once()

    def test_update_lowlatency_worker_kernel(self):
        """ Test updating the kernel from
            lowlatency -> standard of a locked worker node
        """
        worker = self._create_host(constants.WORKER,
                                   subfunction=constants.LOWLATENCY,
                                   kernel_running=constants.KERNEL_LOWLATENCY,
                                   admin=constants.ADMIN_LOCKED)
        hostid = worker['uuid']
        hostname = worker['hostname']

        # Verify DB - lowlatency is in subfunctions before update
        host = self._get_test_host_by_hostname(hostname)
        subfunctions = host[constants.SUBFUNCTIONS]
        self.assertIn(constants.LOWLATENCY, subfunctions)

        url = '%s' % self._get_path(hostid)
        response = self.patch_dict_json(url,
                                        headers=self.API_HEADERS,
                                        kernel_provisioned=constants.KERNEL_STANDARD,
                                        expect_errors=False)

        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual(constants.KERNEL_STANDARD, response.json['kernel_provisioned'])

        # Verify DB - lowlatency is not in subfunctions after update
        host = self._get_test_host_by_hostname(hostname)
        subfunctions = host[constants.SUBFUNCTIONS]
        self.assertNotIn(constants.LOWLATENCY, subfunctions)

        # Verify that the method that updates kernel config is called once
        self.fake_conductor_api.kernel_runtime_manifests.assert_called_once()

    def test_update_unlocked_worker_kernel(self):
        """ Test updating the kernel from
            standard -> lowlatency of a unlocked worker node
        """
        worker = self._create_host(constants.WORKER,
                                    admin=constants.ADMIN_UNLOCKED)
        hostid = worker['uuid']
        hostname = worker['hostname']

        # Verify DB - lowlatency is not in subfunctions before update
        host = self._get_test_host_by_hostname(hostname)
        subfunctions = host[constants.SUBFUNCTIONS]
        self.assertNotIn(constants.LOWLATENCY, subfunctions)

        url = '%s' % self._get_path(hostid)
        response = self.patch_dict_json(url,
                                        headers=self.API_HEADERS,
                                        kernel_provisioned=constants.KERNEL_LOWLATENCY,
                                        expect_errors=True)

        self.assertEqual(http_client.BAD_REQUEST, response.status_code)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Host must be locked',
                      response.json['error_message'])

        # Verify DB - lowlatency is not in subfunctions after update
        host = self._get_test_host_by_hostname(hostname)
        subfunctions = host[constants.SUBFUNCTIONS]
        self.assertNotIn(constants.LOWLATENCY, subfunctions)

        # Verify that the method that updates kernel config is not called
        self.fake_conductor_api.kernel_runtime_manifests.assert_not_called()

    def test_update_storage_kernel(self):
        """ Test updating the kernel from
            standard -> lowlatency of a locked storage node
        """
        storage = self._create_host(constants.STORAGE,
                                    admin=constants.ADMIN_LOCKED)
        hostid = storage['uuid']
        hostname = storage['hostname']

        # Verify DB - lowlatency is not in subfunctions before update
        host = self._get_test_host_by_hostname(hostname)
        subfunctions = host[constants.SUBFUNCTIONS]
        self.assertNotIn(constants.LOWLATENCY, subfunctions)

        url = '%s' % self._get_path(hostid)
        response = self.patch_dict_json(url,
                                        headers=self.API_HEADERS,
                                        kernel_provisioned=constants.KERNEL_LOWLATENCY,
                                        expect_errors=True)

        self.assertEqual(http_client.BAD_REQUEST, response.status_code)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Can only modify worker nodes',
                      response.json['error_message'])

        # Verify DB - lowlatency is not in subfunctions after update
        host = self._get_test_host_by_hostname(hostname)
        subfunctions = host[constants.SUBFUNCTIONS]
        self.assertNotIn(constants.LOWLATENCY, subfunctions)

        # Verify that the method that updates kernel config is not called
        self.fake_conductor_api.kernel_runtime_manifests.assert_not_called()

    def test_update_standard_controller_kernel(self):
        """ Test updating the kernel from
            standard -> lowlatency of a locked standard controller node
        """
        controller = self._create_host(constants.CONTROLLER,
                                    admin=constants.ADMIN_LOCKED)
        hostid = controller['uuid']
        hostname = controller['hostname']

        # Verify DB - lowlatency is not in subfunctions before update
        host = self._get_test_host_by_hostname(hostname)
        subfunctions = host[constants.SUBFUNCTIONS]
        self.assertNotIn(constants.LOWLATENCY, subfunctions)

        url = '%s' % self._get_path(hostid)
        response = self.patch_dict_json(url,
                                        headers=self.API_HEADERS,
                                        kernel_provisioned=constants.KERNEL_LOWLATENCY,
                                        expect_errors=True)

        self.assertEqual(http_client.BAD_REQUEST, response.status_code)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Can only modify worker nodes',
                      response.json['error_message'])

        # Verify DB - lowlatency is not in subfunctions after update
        host = self._get_test_host_by_hostname(hostname)
        subfunctions = host[constants.SUBFUNCTIONS]
        self.assertNotIn(constants.LOWLATENCY, subfunctions)

        # Verify that the method that updates kernel config is not called
        self.fake_conductor_api.kernel_runtime_manifests.assert_not_called()

    def test_update_aio_controller_kernel(self):
        """ Test updating the kernel from
            standard -> lowlatency of a locked ALL-IN-ONE controller node
        """
        controller = self._create_host(constants.CONTROLLER,
                                   subfunction=constants.WORKER,
                                   admin=constants.ADMIN_LOCKED)
        hostid = controller['uuid']
        hostname = controller['hostname']

        # Verify DB - lowlatency is not in subfunctions before update
        host = self._get_test_host_by_hostname(hostname)
        subfunctions = host[constants.SUBFUNCTIONS]
        self.assertNotIn(constants.LOWLATENCY, subfunctions)

        url = '%s' % self._get_path(hostid)
        response = self.patch_dict_json(url,
                                        headers=self.API_HEADERS,
                                        kernel_provisioned=constants.KERNEL_LOWLATENCY,
                                        expect_errors=False)

        self.assertEqual('application/json', response.content_type)
        self.assertEqual(http_client.OK, response.status_code)
        self.assertEqual(constants.KERNEL_LOWLATENCY,
                         response.json['kernel_provisioned'])

        # Verify DB - lowlatency is in subfunctions after update
        host = self._get_test_host_by_hostname(hostname)
        subfunctions = host[constants.SUBFUNCTIONS]
        self.assertIn(constants.LOWLATENCY, subfunctions)

        # Verify that the method that updates kernel config is called once
        self.fake_conductor_api.kernel_runtime_manifests.assert_called_once()
