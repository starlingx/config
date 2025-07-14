# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- encoding: utf-8 -*-
#
#
# Copyright (c) 2017-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /storage_backend/ methods.
"""

import mock
from collections import namedtuple
from six.moves import http_client

from sysinv.db import api as dbapi
from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils
from sysinv.common import constants
from sysinv.common.storage_backend_conf import StorageBackendConfig
from oslo_serialization import jsonutils
from sysinv.api.controllers.v1 import storage_file as test_storage_file
from sysinv.api.controllers.v1 import storage_lvm as test_storage_lvm
from sysinv.api.controllers.v1 import storage_ceph as test_storage_ceph
from sysinv.api.controllers.v1.utils import SBApiHelper

# Monkey patches
#
# the hiera_data required for the file backend
test_storage_file.HIERA_DATA = {
    'backend': ['test_bparam1'],
    constants.SB_SVC_GLANCE: ['test_gparam1', 'test_gparam2']
}

test_storage_lvm.HIERA_DATA = {
    'backend': [],
    constants.SB_SVC_CINDER: ['test_cparam1', 'test_cparam2']
}

test_storage_ceph.HIERA_DATA = {
    'backend': ['test_bparam3'],
    constants.SB_SVC_CINDER: ['test_cparam3'],
    constants.SB_SVC_RBD_PROVISIONER: ['test_rparam3'],
    constants.SB_SVC_GLANCE: ['test_gparam3'],
    constants.SB_SVC_SWIFT: ['test_sparam1'],
    constants.SB_SVC_NOVA: ['test_nparam1'],
}

test_storage_ceph.CAPABILITIES = {
    'backend': ['test_bparam3'],
    constants.SB_SVC_CINDER: ['test_cparam3'],
    constants.SB_SVC_RBD_PROVISIONER: ['test_rparam3'],
    constants.SB_SVC_GLANCE: ['test_gparam3'],
    constants.SB_SVC_SWIFT: ['test_sparam1'],
    constants.SB_SVC_NOVA: ['test_nparam1'],
}

test_storage_ceph.MANDATORY_CAP = {
    'backend': ['test_bparam3'],
    constants.SB_SVC_CINDER: ['test_cparam3'],
    constants.SB_SVC_RBD_PROVISIONER: ['test_rparam3'],
    constants.SB_SVC_GLANCE: ['test_gparam3'],
    constants.SB_SVC_SWIFT: ['test_sparam1'],
    constants.SB_SVC_NOVA: ['test_nparam1'],
}

orig_set_backend_data = SBApiHelper.set_backend_data


def set_backend_state_configured(requested, defaults, checks, supported_svcs, current=None):
    ret = orig_set_backend_data(requested, defaults, checks,
                                supported_svcs, current)
    ret['state'] = constants.SB_STATE_CONFIGURED
    return ret


class StorageBackendTestCases(base.FunctionalTest):

    def setUp(self):
        super(StorageBackendTestCases, self).setUp()
        self.system = dbutils.create_test_isystem()
        self.cluster = dbutils.create_test_cluster(system_id=self.system.id)
        self.tier = dbutils.create_test_storage_tier(forclusterid=self.cluster.id)
        self.host = dbutils.create_test_ihost(forisystemid=self.system.id)
        self.lvg = dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Patch management network for ceph
        self.dbapi = dbapi.get_instance()
        p = mock.patch.object(self.dbapi, 'networks_get_by_type')
        p.start().return_value = [{'network_type': constants.NETWORK_TYPE_MGMT}]
        self.addCleanup(p.stop)

    def assertDeleted(self, fullPath):
        self.get_json(fullPath, expect_errors=True)  # Make sure this line raises an error

    #
    # StorageBackend API:
    #

    def test_post_no_backend(self):
        response = self.post_json('/storage_backend', {}, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('This operation requires a storage backend to be specified',
                      response.json['error_message'])

    #
    # StorageBackend API: File
    #

    def test_post_file_missing_backend_param(self):
        vals = {
            'backend': constants.SB_TYPE_FILE
        }
        response = self.post_json('/storage_backend', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Missing required backend parameter: test_bparam1',
                      response.json['error_message'])

    def test_post_file_missing_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'capabilities': {'test_bparam1': 'foo'}
        }
        response = self.post_json('/storage_backend', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('WARNING : THIS OPERATION IS NOT REVERSIBLE AND CANNOT BE CANCELLED',
                      response.json['error_message'])

    def test_post_file_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_FILE,  # Expected
                         self.get_json('/storage_backend/%s/' % response.json['uuid'])['backend'])  # Result

    def test_post_file_with_invalid_svc_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'services': constants.SB_SVC_CINDER,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Service cinder is not supported',
                      response.json['error_message'])

    def test_post_file_with_valid_svc_no_svc_param_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'services': constants.SB_SVC_GLANCE,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Missing required glance service parameter',
                      response.json['error_message'])

    def test_post_file_and_confirm_modify_param(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_FILE,  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_backend/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              capabilities=jsonutils.dumps({'test_bparam1': 'bar'}),
                                              expect_errors=True)
        self.assertEqual(http_client.OK, patch_response.status_int)
        self.assertEqual({'test_bparam1': 'bar'},  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       patch_response.json['uuid'])['capabilities'])  # Result

    def test_post_file_with_valid_svc_some_svc_param_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'services': constants.SB_SVC_GLANCE,
            'capabilities': {'test_bparam1': 'foo',
                             'test_gparam1': 'bar'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])

    def test_post_file_with_valid_svc_all_svc_param_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'services': constants.SB_SVC_GLANCE,
            'capabilities': {'test_bparam1': 'foo',
                             'test_gparam1': 'bar',
                             'test_gparam2': 'far'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_FILE,  # Expected
                         self.get_json('/storage_backend/%s/' % response.json['uuid'])['backend'])  # Result

    def test_post_file_and_confirm_modify_with_invalid_svc(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_FILE,  # Expected
                         self.get_json('/storage_backend/%s/' % response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_backend/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services=constants.SB_SVC_CINDER,
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Service cinder is not supported', patch_response.json['error_message'])

    def test_post_file_and_confirm_modify_with_svc_missing_params(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_FILE,  # Expected
                         self.get_json('/storage_backend/%s/' % response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_backend/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services=constants.SB_SVC_GLANCE,
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Missing required glance service parameter', patch_response.json['error_message'])

    def test_post_file_and_confirm_modify_with_svc_missing_some_params(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_FILE,  # Expected
                         self.get_json('/storage_backend/%s/' % response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_backend/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services=constants.SB_SVC_GLANCE,
                                              capabilities=jsonutils.dumps({'test_param2': 'bar'}),
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Missing required glance service parameter', patch_response.json['error_message'])

    def test_post_file_and_confirm_modify_with_svc_with_params(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_FILE,  # Expected
                         self.get_json('/storage_backend/%s/' % response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_backend/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services=constants.SB_SVC_GLANCE,
                                              capabilities=jsonutils.dumps({'test_gparam1': 'bar',
                                                                            'test_gparam2': 'far'}),
                                              expect_errors=False)
        self.assertEqual(http_client.OK, patch_response.status_int)
        self.assertEqual(constants.SB_SVC_GLANCE,  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       response.json['uuid'])['services'])  # Result

        self.assertEqual({'test_bparam1': 'foo',
                          'test_gparam1': 'bar',
                          'test_gparam2': 'far'},  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       response.json['uuid'])['capabilities'])  # Result

    def test_post_file_and_list(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend/', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_FILE,  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       response.json['uuid'])['backend'])  # Result
        self.assertEqual(constants.SB_TYPE_FILE,
                         self.get_json('/storage_backend')['storage_backends'][0]['backend'])

    #
    # StorageBackend API: LVM
    #
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    def test_post_lvm_missing_confirm(self, mock_apply, mock_validate,):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': constants.SB_SVC_CINDER,
            'capabilities': {'test_cparam1': 'bar',
                             'test_cparam2': 'far'},
        }
        response = self.post_json('/storage_backend', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('WARNING : THIS OPERATION IS NOT REVERSIBLE AND CANNOT BE CANCELLED',
                      response.json['error_message'])

    def test_post_lvm_without_svc_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Service cinder is mandatory for the lvm backend.',
                      response.json['error_message'])

    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    def test_post_lvm_with_valid_svc_all_svc_param_and_confirm(self, mock_apply, mock_validate):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': constants.SB_SVC_CINDER,
            'capabilities': {'test_cparam1': 'bar',
                             'test_cparam2': 'far'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual('lvm',  # Expected
                         self.get_json('/storage_backend/%s/' % response.json['uuid'])['backend'])  # Result

    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    def test_post_lvm_with_invalid_svc_and_confirm(self, mock_apply, mock_validate):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': (',').join([constants.SB_SVC_CINDER, constants.SB_SVC_GLANCE]),
            'capabilities': {'test_cparam1': 'bar',
                             'test_cparam2': 'far'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Service glance is not supported',
                      response.json['error_message'])

    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    def test_post_lvm_with_valid_svc_no_svc_param_and_confirm(self, mock_apply, mock_validate):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': constants.SB_SVC_CINDER,
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Missing required cinder service parameter',
                      response.json['error_message'])

    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    def test_post_lvm_with_valid_svc_some_svc_param_and_confirm(self, mock_apply, mock_validate):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': constants.SB_SVC_CINDER,
            'capabilities': {'test_cparam1': 'bar'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Missing required cinder service parameter',
                      response.json['error_message'])

    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    def test_post_lvm_and_remove_svc(self, mock_apply, mock_validate):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': constants.SB_SVC_CINDER,
            'capabilities': {'test_cparam1': 'bar',
                             'test_cparam2': 'far'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual('lvm',  # Expected
                         self.get_json('/storage_backend/%s/' % response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_backend/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services=constants.SB_SVC_GLANCE,
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Removing cinder is not supported', patch_response.json['error_message'])

    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    @mock.patch.object(SBApiHelper, 'set_backend_data',
                       side_effect=set_backend_state_configured)
    def test_post_lvm_and_confirm_modify_with_invalid_svc(self, mock_set_backend_data, mock_apply,
                                                          mock_validate):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': constants.SB_SVC_CINDER,
            'capabilities': {'test_cparam1': 'bar',
                             'test_cparam2': 'far'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual('lvm',  # Expected
                         self.get_json('/storage_backend/%s/' % response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_backend/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services=(',').join([constants.SB_SVC_CINDER,
                                                                   constants.SB_SVC_GLANCE]),
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Service glance is not supported', patch_response.json['error_message'])

    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    def test_post_lvm_and_confirm_modify_with_no_changes(self, mock_apply, mock_validate):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': constants.SB_SVC_CINDER,
            'capabilities': {'test_cparam1': 'bar',
                             'test_cparam2': 'far'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual('lvm',  # Expected
                         self.get_json('/storage_backend/%s/' % response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_backend/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services=constants.SB_SVC_CINDER,
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('No changes to the existing backend settings were detected',
                      patch_response.json['error_message'])

    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    @mock.patch.object(SBApiHelper, 'set_backend_data',
                       side_effect=set_backend_state_configured)
    def test_post_lvm_and_confirm_modify_with_svc_with_params(self, mock_set_backend_data,
                                                              mock_apply, mock_validate):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': constants.SB_SVC_CINDER,
            'capabilities': {'test_cparam1': 'bar',
                             'test_cparam2': 'far'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual('lvm',  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_backend/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services=constants.SB_SVC_CINDER,
                                              capabilities=jsonutils.dumps({'test_cparam1': 'bar2',
                                                                            'test_cparam2': 'far2'}),
                                              expect_errors=False)
        self.assertEqual(http_client.OK, patch_response.status_int)
        self.assertEqual(constants.SB_SVC_CINDER,  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       response.json['uuid'])['services'])  # Result
        self.assertEqual({'test_cparam1': 'bar2',
                          'test_cparam2': 'far2'},  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       response.json['uuid'])['capabilities'])  # Result

    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    def test_post_lvm_and_list(self, mock_apply, mock_validate):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': constants.SB_SVC_CINDER,
            'capabilities': {'test_cparam1': 'bar',
                             'test_cparam2': 'far'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend/', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_LVM,  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       response.json['uuid'])['backend'])  # Result
        self.assertEqual(constants.SB_TYPE_LVM,
                         self.get_json('/storage_backend')['storage_backends'][0]['backend'])

    #
    # StorageBackend API: Ceph
    #

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    def test_post_ceph_missing_backend_param(self, mock_mon_ip):
        # Test skipped. Fix later.
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        vals = {
            'backend': constants.SB_TYPE_CEPH
        }
        response = self.post_json('/storage_backend', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Missing required backend parameter: test_bparam3',
                      response.json['error_message'])

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    def test_post_ceph_missing_confirm(self, mock_mon_ip):
        # Test skipped. Fix later.
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'capabilities': {'test_bparam3': 'foo'}
        }
        response = self.post_json('/storage_backend', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('WARNING : THIS OPERATION IS NOT REVERSIBLE AND CANNOT BE CANCELLED',
                      response.json['error_message'])

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    def test_post_ceph_and_confirm(self, mock_mon_ip):
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'capabilities': {'test_bparam3': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual('ceph',  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       response.json['uuid'])['backend'])  # Result

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    def test_post_ceph_with_invalid_svc_and_confirm(self, mock_mon_ip):
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'services': 'invalid_svc',
            'capabilities': {'test_bparam3': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Service invalid_svc is not supported for the ceph backend',
                      response.json['error_message'])

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    @mock.patch('sysinv.api.controllers.v1.storage_ceph._discover_and_validate_cinder_capabilities')
    @mock.patch('sysinv.api.controllers.v1.storage_ceph._apply_backend_changes')
    def test_post_ceph_with_valid_svc_no_svc_param_and_confirm(self,
                                                               mock_apply,
                                                               mock_validate,
                                                               mock_mon_ip):
        # Test skipped. Fix later.
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'services': constants.SB_SVC_CINDER,
            'capabilities': {'test_bparam3': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Missing required cinder service parameter',
                      response.json['error_message'])

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    @mock.patch('sysinv.api.controllers.v1.storage_ceph._discover_and_validate_cinder_capabilities')
    @mock.patch('sysinv.api.controllers.v1.storage_ceph._apply_backend_changes')
    def test_post_ceph_with_valid_svc_some_svc_param_and_confirm(self,
                                                                 mock_apply,
                                                                 mock_validate,
                                                                 mock_mon_ip):
        # Test skipped. Fix later.
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'services': (',').join([constants.SB_SVC_CINDER, constants.SB_SVC_GLANCE]),
            'capabilities': {'test_bparam3': 'foo',
                             'test_cparam3': 'bar'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Missing required glance service parameter',
                      response.json['error_message'])

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    @mock.patch('sysinv.api.controllers.v1.storage_ceph._discover_and_validate_cinder_capabilities')
    @mock.patch('sysinv.api.controllers.v1.storage_ceph._apply_backend_changes')
    def test_post_ceph_with_valid_svc_all_svc_param_and_confirm(self,
                                                                mock_apply,
                                                                mock_validate,
                                                                mock_mon_ip):
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'services': (',').join([constants.SB_SVC_CINDER, constants.SB_SVC_GLANCE]),
            'capabilities': {'test_bparam3': 'foo',
                             'test_cparam3': 'bar',
                             'test_gparam3': 'too'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual('ceph',  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       response.json['uuid'])['backend'])  # Result

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    @mock.patch.object(SBApiHelper, 'set_backend_data',
                       side_effect=set_backend_state_configured)
    def test_post_ceph_and_confirm_modify_with_invalid_svc(self, mock_set_backend_data,
                                                           mock_mon_ip):
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'capabilities': {'test_bparam3': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual('ceph',  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_backend/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services='invalid_svc',
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Service invalid_svc is not supported for the ceph backend',
                      patch_response.json['error_message'])

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    @mock.patch('sysinv.api.controllers.v1.storage_ceph._discover_and_validate_cinder_capabilities')
    @mock.patch('sysinv.api.controllers.v1.storage_ceph._apply_backend_changes')
    @mock.patch.object(SBApiHelper, 'set_backend_data',
                   side_effect=set_backend_state_configured)
    def test_post_ceph_and_confirm_modify_with_svc_missing_params(self, mock_set_backend_data,
                                                                  mock_apply, mock_validate,
                                                                  mock_mon_ip):
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'capabilities': {'test_bparam3': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual('ceph',  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_backend/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services=constants.SB_SVC_CINDER,
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Missing required cinder service parameter',
                      patch_response.json['error_message'])

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    @mock.patch('sysinv.api.controllers.v1.storage_ceph._discover_and_validate_cinder_capabilities')
    @mock.patch('sysinv.api.controllers.v1.storage_ceph._apply_backend_changes')
    @mock.patch.object(SBApiHelper, 'set_backend_data',
               side_effect=set_backend_state_configured)
    def test_post_ceph_and_confirm_modify_with_svc_missing_some_params(self,
                                                                       mock_set_backend_data,
                                                                       mock_apply,
                                                                       mock_validate,
                                                                       mock_mon_ip):
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'capabilities': {'test_bparam3': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual('ceph',  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_backend/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services=(',').join([constants.SB_SVC_CINDER,
                                                                   constants.SB_SVC_GLANCE]),
                                              capabilities=jsonutils.dumps({'test_cparam3': 'bar'}),
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Missing required glance service parameter',
                      patch_response.json['error_message'])

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    @mock.patch('sysinv.api.controllers.v1.storage_ceph._discover_and_validate_cinder_capabilities')
    @mock.patch('sysinv.api.controllers.v1.storage_ceph._apply_backend_changes')
    @mock.patch.object(SBApiHelper, 'set_backend_data',
           side_effect=set_backend_state_configured)
    def test_post_ceph_and_confirm_modify_with_svc_with_params(self, mock_set_backend_data,
                                                               mock_apply, mock_validate,
                                                               mock_mon_ip):
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'capabilities': {'test_bparam3': 'foo'},
            'confirmed': True
        }
        services_string = '%s,%s' % (constants.SB_SVC_CINDER, constants.SB_SVC_GLANCE)
        services_string2 = '%s,%s' % (constants.SB_SVC_GLANCE, constants.SB_SVC_CINDER)
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual('ceph',  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_backend/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services=services_string,
                                              capabilities=jsonutils.dumps({'test_cparam3': 'bar',
                                                                            'test_gparam3': 'too'}),
                                              expect_errors=False)
        self.assertEqual(http_client.OK, patch_response.status_int)
        json_result = self.get_json('/storage_backend/%s/' %
                                    response.json['uuid'])['services']
        self.assertTrue(services_string == json_result or services_string2 == json_result)
        self.assertEqual({'test_bparam3': 'foo',
                          'test_cparam3': 'bar',
                          'test_gparam3': 'too'},  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       response.json['uuid'])['capabilities'])  # Result

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    def test_post_ceph_and_list(self, mock_mon_ip):
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'capabilities': {'test_bparam3': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_backend/', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_CEPH,  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       response.json['uuid'])['backend'])  # Result
        self.assertEqual(constants.SB_TYPE_CEPH,
                         self.get_json('/storage_backend')['storage_backends'][0]['backend'])

    #
    # StorageBackend API: Ceph-rook
    #

    def test_post_rook_ceph_valid_deployment_model_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_CEPH_ROOK,
            'capabilities': {constants.CEPH_ROOK_BACKEND_DEPLOYMENT_CAP:
                             constants.CEPH_ROOK_DEPLOYMENT_OPEN},
            'confirmed': True
        }
        response = self.post_json('/storage_backend', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.CEPH_ROOK_DEPLOYMENT_OPEN,  # Expected
                         self.get_json('/storage_backend/%s/' %
                                       response.json['uuid'])['capabilities']
                                       [constants.CEPH_ROOK_BACKEND_DEPLOYMENT_CAP])  # Result


class StorageFileTestCases(base.FunctionalTest):

    def setUp(self):
        super(StorageFileTestCases, self).setUp()
        self.system = dbutils.create_test_isystem()
        self.host = dbutils.create_test_ihost(forisystemid=self.system.id)

    def assertDeleted(self, fullPath):
        self.get_json(fullPath, expect_errors=True)  # Make sure this line raises an error

    #
    # StorageFile API
    #

    def test_post_missing_backend_param(self):
        vals = {
            'backend': constants.SB_TYPE_FILE
        }
        response = self.post_json('/storage_file', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Missing required backend parameter: test_bparam1',
                      response.json['error_message'])

    def test_post_missing_confirm(self):
        # Test skipped. Fix later.
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'capabilities': {'test_bparam1': 'foo'}
        }
        response = self.post_json('/storage_file', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('WARNING : THIS OPERATION IS NOT REVERSIBLE AND CANNOT BE CANCELLED',
                      response.json['error_message'])

    def test_post_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_file', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_FILE,  # Expected
                         self.get_json('/storage_file/%s/' %
                                       response.json['uuid'])['backend'])  # Result

    def test_post_with_invalid_svc_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'services': constants.SB_SVC_CINDER,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_file', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Service cinder is not supported',
                      response.json['error_message'])

    def test_post_with_valid_svc_no_svc_param_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'services': constants.SB_SVC_GLANCE,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_file', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Missing required glance service parameter: test_gparam1',
                      response.json['error_message'])

    def test_post_and_confirm_modify_param(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_file', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_FILE,  # Expected
                         self.get_json('/storage_file/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_file/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              capabilities=jsonutils.dumps({'test_bparam1': 'bar'}),
                                              expect_errors=True)
        self.assertEqual(http_client.OK, patch_response.status_int)
        self.assertEqual({'test_bparam1': 'bar'},  # Expected
                         self.get_json('/storage_file/%s/' %
                                       patch_response.json['uuid'])['capabilities'])  # Result

    def test_post_with_valid_svc_some_svc_param_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'services': constants.SB_SVC_GLANCE,
            'capabilities': {'test_bparam1': 'foo',
                             'test_gparam1': 'bar'},
            'confirmed': True
        }
        response = self.post_json('/storage_file', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Missing required glance service parameter: test_gparam2',
                      response.json['error_message'])

    def test_post_with_valid_svc_all_svc_param_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'services': constants.SB_SVC_GLANCE,
            'capabilities': {'test_bparam1': 'foo',
                             'test_gparam1': 'bar',
                             'test_gparam2': 'far'},
            'confirmed': True
        }
        response = self.post_json('/storage_file', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_FILE,  # Expected
                         self.get_json('/storage_file/%s/' %
                                       response.json['uuid'])['backend'])  # Result

    @mock.patch.object(SBApiHelper, 'set_backend_data',
           side_effect=set_backend_state_configured)
    def test_post_and_confirm_modify_with_invalid_svc(self, mock_set_backend_data):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_file', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_FILE,  # Expected
                         self.get_json('/storage_file/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_file/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services=constants.SB_SVC_CINDER,
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Service cinder is not supported',
                      patch_response.json['error_message'])

    def test_post_and_confirm_modify_with_svc_missing_params(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_file', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_FILE,  # Expected
                         self.get_json('/storage_file/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_file/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services=constants.SB_SVC_GLANCE,
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Missing required glance service parameter',
                      patch_response.json['error_message'])

    def test_post_and_confirm_modify_with_svc_missing_some_params(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_file', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_FILE,  # Expected
                         self.get_json('/storage_file/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_file/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services=constants.SB_SVC_GLANCE,
                                              capabilities=jsonutils.dumps({'test_gparam1': 'bar'}),
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Missing required glance service parameter',
                      patch_response.json['error_message'])

    def test_post_and_confirm_modify_with_svc_with_params(self):
        # Test skipped. Fix later.
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_file', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_FILE,  # Expected
                         self.get_json('/storage_file/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_file/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services=constants.SB_SVC_GLANCE,
                                              capabilities=jsonutils.dumps({'test_gparam1': 'bar',
                                                                            'test_gparam2': 'far'}),
                                              expect_errors=False)
        self.assertEqual(http_client.OK, patch_response.status_int)
        self.assertEqual(constants.SB_SVC_GLANCE,  # Expected
                         self.get_json('/storage_file/%s/' %
                                       response.json['uuid'])['services'])  # Result

        self.assertEqual({'test_bparam1': 'foo',
                          'test_gparam1': 'bar',
                          'test_gparam2': 'far'},  # Expected
                         self.get_json('/storage_file/%s/' %
                                       response.json['uuid'])['capabilities'])  # Result

    def test_post_and_list(self):
        vals = {
            'backend': constants.SB_TYPE_FILE,
            'capabilities': {'test_bparam1': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_file/', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_FILE,  # Expected
                         self.get_json('/storage_file/%s/' %
                                       response.json['uuid'])['backend'])  # Result
        self.assertEqual(constants.SB_TYPE_FILE,
                         self.get_json('/storage_backend')['storage_backends'][0]['backend'])


class StorageLvmTestCases(base.FunctionalTest):

    def setUp(self):
        super(StorageLvmTestCases, self).setUp()
        self.system = dbutils.create_test_isystem()
        self.host = dbutils.create_test_ihost(forisystemid=self.system.id)

    def assertDeleted(self, fullPath):
        self.get_json(fullPath, expect_errors=True)  # Make sure this line raises an error

    #
    # StorageLvm API
    #

    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    def test_post_missing_confirm(self, mock_apply, mock_validate,):
        # Test skipped. Fix later.
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': constants.SB_SVC_CINDER,
            'capabilities': {'test_cparam1': 'bar',
                             'test_cparam2': 'far'},
        }
        response = self.post_json('/storage_lvm', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('WARNING : THIS OPERATION IS NOT REVERSIBLE AND CANNOT BE CANCELLED',
                      response.json['error_message'])

    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    def test_post_and_confirm(self, mock_apply, mock_validate):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': constants.SB_SVC_CINDER,
            'capabilities': {'test_cparam1': 'bar',
                             'test_cparam2': 'far'},
            'confirmed': True
        }
        response = self.post_json('/storage_lvm', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_LVM,  # Expected
                         self.get_json('/storage_lvm/%s/' %
                                       response.json['uuid'])['backend'])  # Result

    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    def test_post_with_invalid_svc_and_confirm(self, mock_apply, mock_validate):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': (',').join([constants.SB_SVC_CINDER, constants.SB_SVC_GLANCE]),
            'capabilities': {'test_cparam1': 'bar',
                             'test_cparam2': 'far'},
            'confirmed': True
        }
        response = self.post_json('/storage_lvm', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Service glance is not supported',
                      response.json['error_message'])

    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    def test_post_with_valid_svc_no_svc_param_and_confirm(self, mock_apply, mock_validate):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': constants.SB_SVC_CINDER,
            'confirmed': True
        }
        response = self.post_json('/storage_lvm', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Missing required cinder service parameter',
                      response.json['error_message'])

    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    def test_post_with_valid_svc_some_svc_param_and_confirm(self, mock_apply, mock_validate):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': constants.SB_SVC_CINDER,
            'capabilities': {'test_cparam1': 'bar'},
            'confirmed': True
        }
        response = self.post_json('/storage_lvm', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Missing required cinder service parameter',
                      response.json['error_message'])

    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    def test_post_with_valid_svc_all_svc_param_and_confirm(self, mock_apply, mock_validate):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': constants.SB_SVC_CINDER,
            'capabilities': {'test_cparam1': 'bar',
                             'test_cparam2': 'far'},
            'confirmed': True
        }
        response = self.post_json('/storage_lvm', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_LVM,  # Expected
                         self.get_json('/storage_lvm/%s/' % response.json['uuid'])['backend'])  # Result

    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    @mock.patch.object(SBApiHelper, 'set_backend_data',
                   side_effect=set_backend_state_configured)
    def test_post_and_confirm_modify_with_invalid_svc(self, mock_set_backend_data,
                                                      mock_apply, mock_validate):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': constants.SB_SVC_CINDER,
            'capabilities': {'test_cparam1': 'bar',
                             'test_cparam2': 'far'},
            'confirmed': True
        }
        response = self.post_json('/storage_lvm', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_LVM,  # Expected
                         self.get_json('/storage_lvm/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_lvm/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services=(',').join([constants.SB_SVC_CINDER,
                                                                   constants.SB_SVC_GLANCE]),
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Service glance is not supported', patch_response.json['error_message'])

    @mock.patch('sysinv.api.controllers.v1.storage_lvm._discover_and_validate_cinder_hiera_data')
    @mock.patch('sysinv.api.controllers.v1.storage_lvm._apply_backend_changes')
    def test_post_and_list(self, mock_apply, mock_validate):
        vals = {
            'backend': constants.SB_TYPE_LVM,
            'services': constants.SB_SVC_CINDER,
            'capabilities': {'test_cparam1': 'bar',
                             'test_cparam2': 'far'},
            'confirmed': True
        }
        response = self.post_json('/storage_lvm/', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_LVM,  # Expected
                         self.get_json('/storage_lvm/%s/' %
                                       response.json['uuid'])['backend'])  # Result
        self.assertEqual(constants.SB_TYPE_LVM,
                         self.get_json('/storage_backend')['storage_backends'][0]['backend'])


class StorageCephTestCases(base.FunctionalTest):

    def setUp(self):
        super(StorageCephTestCases, self).setUp()
        self.system = dbutils.create_test_isystem()
        self.cluster = dbutils.create_test_cluster(system_id=self.system.id)
        self.tier = dbutils.create_test_storage_tier(forclusterid=self.cluster.id)
        self.host = dbutils.create_test_ihost(forisystemid=self.system.id)
        self.lvg = dbutils.create_test_lvg(lvm_vg_name='cgts-vg',
                                forihostid=self.host.id)

        # Patch management network for ceph
        self.dbapi = dbapi.get_instance()
        p = mock.patch.object(self.dbapi, 'networks_get_by_type')
        p.start().return_value = [{'network_type': constants.NETWORK_TYPE_MGMT}]
        self.addCleanup(p.stop)

    def assertDeleted(self, fullPath):
        self.get_json(fullPath, expect_errors=True)  # Make sure this line raises an error

    #
    # StorageCeph API
    #

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    def test_post_missing_confirm(self, mock_mon_ip):
        # Test skipped. Fix later.
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'capabilities': {'test_bparam3': 'foo'}
        }
        response = self.post_json('/storage_ceph', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('nWARNING : THIS OPERATION IS NOT REVERSIBLE AND CANNOT BE CANCELLED',
                      response.json['error_message'])

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    def test_post_and_confirm(self, mock_mon_ip):
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'capabilities': {'test_bparam3': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_ceph', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_CEPH,  # Expected
                         self.get_json('/storage_ceph/%s/' %
                                       response.json['uuid'])['backend'])  # Result

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    def test_post_with_invalid_svc_and_confirm(self, mock_mon_ip):
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'services': 'invalid_svc',
            'capabilities': {'test_bparam3': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_ceph', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Service invalid_svc is not supported for the ceph backend',
                      response.json['error_message'])

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    def test_post_with_valid_svc_all_svc_param_and_confirm(self, mock_mon_ip):
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'services': constants.SB_SVC_SWIFT,
            'capabilities': {'test_bparam3': 'foo',
                             'test_sparam1': 'bar'},
            'confirmed': True
        }
        response = self.post_json('/storage_ceph', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_CEPH,  # Expected
                         self.get_json('/storage_ceph/%s/' %
                                       response.json['uuid'])['backend'])  # Result

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    @mock.patch.object(SBApiHelper, 'set_backend_data',
                       side_effect=set_backend_state_configured)
    def test_post_and_confirm_modify_with_invalid_svc(self,
                                                      mock_set_backend_data,
                                                      mock_mon_ip):
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'capabilities': {'test_bparam3': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_ceph', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_CEPH,  # Expected
                         self.get_json('/storage_ceph/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_ceph/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services='invalid_svc',
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Service invalid_svc is not supported',
                      patch_response.json['error_message'])

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    def test_post_and_confirm_modify_with_svc_with_params(self, mock_mon_ip):
        # Test skipped. Fix later.
        self.skipTest("Skipping to prevent failure notification on Jenkins")
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'capabilities': {'test_bparam3': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_ceph', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_CEPH,  # Expected
                         self.get_json('/storage_ceph/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_ceph/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services=constants.SB_SVC_SWIFT,
                                              capabilities=jsonutils.dumps({'test_sparam1': 'bar'}),
                                              expect_errors=False)
        self.assertEqual(http_client.OK, patch_response.status_int)
        self.assertEqual(constants.SB_SVC_SWIFT,  # Expected
                         self.get_json('/storage_ceph/%s/' %
                                       response.json['uuid'])['services'])  # Result
        self.assertEqual({'test_bparam3': 'foo',
                          'test_sparam1': 'bar'},  # Expected
                         self.get_json('/storage_ceph/%s/' %
                                       response.json['uuid'])['capabilities'])  # Result

    @mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses')
    def test_post_and_list(self, mock_mon_ip):
        vals = {
            'backend': constants.SB_TYPE_CEPH,
            'capabilities': {'test_bparam3': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_ceph/', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_CEPH,  # Expected
                         self.get_json('/storage_ceph/%s/' %
                                       response.json['uuid'])['backend'])  # Result
        self.assertEqual(constants.SB_TYPE_CEPH,
                         self.get_json('/storage_backend')['storage_backends'][0]['backend'])


class StorageCephRookTestCases(base.FunctionalTest):

    def setUp(self):
        super(StorageCephRookTestCases, self).setUp()
        self.system = dbutils.create_test_isystem()
        self.cluster = dbutils.create_test_cluster(system_id=self.system.id)
        self.tier = dbutils.create_test_storage_tier(forclusterid=self.cluster.id)
        self.host = dbutils.create_test_ihost(forisystemid=self.system.id)

        # Patch management network for ceph
        self.dbapi = dbapi.get_instance()
        p = mock.patch.object(self.dbapi, 'networks_get_by_type')
        p.start().return_value = [{'network_type': constants.NETWORK_TYPE_MGMT}]
        self.addCleanup(p.stop)

    def assertDeleted(self, fullPath):
        self.get_json(fullPath, expect_errors=True)  # Make sure this line raises an error

    #
    # StorageCephRook API
    #

    def test_post_missing_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_CEPH_ROOK,
            'capabilities': {'test_bparam3': 'foo'}
        }
        response = self.post_json('/storage_ceph_rook', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('nWARNING : THIS OPERATION IS NOT REVERSIBLE AND CANNOT BE CANCELLED',
                      response.json['error_message'])

    def test_post_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_CEPH_ROOK,
            'capabilities': {'test_bparam3': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_ceph_rook', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_CEPH_ROOK,  # Expected
                         self.get_json('/storage_ceph_rook/%s/' %
                                       response.json['uuid'])['backend'])  # Result

    def test_post_with_invalid_svc_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_CEPH_ROOK,
            'services': 'invalid_svc',
            'capabilities': {'test_bparam3': 'foo'},
            'confirmed': True
        }
        response = self.post_json('/storage_ceph_rook', vals, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Service invalid_svc is not supported for the ceph-rook backend',
                      response.json['error_message'])

    def test_post_with_valid_svc_all_svc_param_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_CEPH_ROOK,
            'services': constants.SB_SVC_CEPH_ROOK_BLOCK,
            'capabilities': {'test_bparam3': 'foo',
                             'test_sparam1': 'bar'},
            'confirmed': True
        }
        response = self.post_json('/storage_ceph_rook', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_CEPH_ROOK,  # Expected
                         self.get_json('/storage_ceph_rook/%s/' %
                                       response.json['uuid'])['backend'])  # Result

    def test_post_with_svc_deployment_model_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_CEPH_ROOK,
            'services': constants.SB_SVC_CEPH_ROOK_BLOCK,
            'deployment': constants.CEPH_ROOK_DEPLOYMENT_OPEN,
            'confirmed': True
        }
        response = self.post_json('/storage_ceph_rook', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_CEPH_ROOK,  # Expected
                         self.get_json('/storage_ceph_rook/%s/' %
                                       response.json['uuid'])['backend'])  # Result
        self.assertEqual(constants.SB_SVC_CEPH_ROOK_BLOCK,  # Expected
                         self.get_json('/storage_ceph_rook/%s/' %
                                       response.json['uuid'])['services'])  # Result
        self.assertEqual(constants.CEPH_ROOK_DEPLOYMENT_OPEN,  # Expected
                         self.get_json('/storage_ceph_rook/%s/' %
                                       response.json['uuid'])['capabilities']['deployment_model'])  # Result

    def test_post_with_invalid_deployment_model_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_CEPH_ROOK,
            'deployment': 'invalid_deployment_model',
            'confirmed': True
        }
        response = self.post_json('/storage_ceph_rook', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.CEPH_ROOK_DEPLOYMENT_CONTROLLER,  # Expected
                         self.get_json('/storage_ceph_rook/%s/' %
                                       response.json['uuid'])['capabilities']['deployment_model'])  # Result

    def test_post_with_valid_deployment_model_and_confirm(self):
        vals = {
            'backend': constants.SB_TYPE_CEPH_ROOK,
            'deployment': constants.CEPH_ROOK_DEPLOYMENT_OPEN,
            'confirmed': True
        }
        response = self.post_json('/storage_ceph_rook', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.CEPH_ROOK_DEPLOYMENT_OPEN,  # Expected
                         self.get_json('/storage_ceph_rook/%s/' %
                                       response.json['uuid'])['capabilities']['deployment_model'])  # Result

    def test_post_and_confirm_modify_with_invalid_svc(self):
        vals = {
            'backend': constants.SB_TYPE_CEPH_ROOK,
            'confirmed': True
        }
        default_services = f'{constants.SB_SVC_CEPH_ROOK_BLOCK},{constants.SB_SVC_CEPH_ROOK_FILESYSTEM}'
        response = self.post_json('/storage_ceph_rook', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_CEPH_ROOK,  # Expected
                         self.get_json('/storage_ceph_rook/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_ceph_rook/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services='%s,invalid_svc' % default_services,
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Service invalid_svc is not supported for the '
                      'ceph-rook backend', patch_response.json['error_message'])

    def test_post_and_confirm_modify_with_exclusive_svc(self):
        vals = {
            'backend': constants.SB_TYPE_CEPH_ROOK,
            'confirmed': True
        }
        default_services = f'{constants.SB_SVC_CEPH_ROOK_BLOCK},{constants.SB_SVC_CEPH_ROOK_FILESYSTEM}'
        response = self.post_json('/storage_ceph_rook', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_CEPH_ROOK,  # Expected
                         self.get_json('/storage_ceph_rook/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_ceph_rook/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services='%s,%s' % (default_services, constants.SB_SVC_CEPH_ROOK_ECBLOCK),
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Service block and ecblock are not supported for the ceph-rook backend in same time',
                      patch_response.json['error_message'])

    def test_post_and_confirm_modify_with_svc_with_params(self):
        vals = {
            'backend': constants.SB_TYPE_CEPH_ROOK,
            'capabilities': {'test_bparam3': 'foo'},
            'confirmed': True
        }
        default_services = f'{constants.SB_SVC_CEPH_ROOK_BLOCK},{constants.SB_SVC_CEPH_ROOK_FILESYSTEM}'
        response = self.post_json('/storage_ceph_rook', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_CEPH_ROOK,  # Expected
                         self.get_json('/storage_ceph_rook/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_ceph_rook/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              services='%s,%s' % (default_services, constants.SB_SVC_CEPH_ROOK_OBJECT),
                                              capabilities=jsonutils.dumps({'test_sparam1': 'bar'}),
                                              expect_errors=False)
        self.assertEqual(http_client.OK, patch_response.status_int)
        self.assertIn(constants.SB_SVC_CEPH_ROOK_OBJECT,  # Expected
                         self.get_json('/storage_ceph_rook/%s/' %
                                       response.json['uuid'])['services'])  # Result
        self.assertEqual({constants.CEPH_ROOK_BACKEND_DEPLOYMENT_CAP: constants.CEPH_ROOK_DEPLOYMENT_CONTROLLER,
                          constants.CEPH_BACKEND_REPLICATION_CAP:
                            constants.CEPH_BACKEND_CAP_DEFAULT[constants.CEPH_BACKEND_REPLICATION_CAP],
                          constants.CEPH_BACKEND_MIN_REPLICATION_CAP:
                            constants.CEPH_BACKEND_CAP_DEFAULT[constants.CEPH_BACKEND_MIN_REPLICATION_CAP],
                          'test_sparam1': 'bar'},  # Expected
                         self.get_json('/storage_ceph_rook/%s/' %
                                       response.json['uuid'])['capabilities'])  # Result

    def test_post_and_confirm_modify_with_valid_deployment_model(self):
        vals = {
            'backend': constants.SB_TYPE_CEPH_ROOK,
            'confirmed': True
        }
        response = self.post_json('/storage_ceph_rook', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_CEPH_ROOK,  # Expected
                         self.get_json('/storage_ceph_rook/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_ceph_rook/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              capabilities=jsonutils.dumps({
                                                  constants.CEPH_ROOK_BACKEND_DEPLOYMENT_CAP:
                                                  constants.CEPH_ROOK_DEPLOYMENT_OPEN}),
                                              expect_errors=False)
        self.assertEqual(http_client.OK, patch_response.status_int)
        self.assertEqual(constants.CEPH_ROOK_DEPLOYMENT_OPEN,  # Expected
                         self.get_json('/storage_ceph_rook/%s/' %
                                       response.json['uuid'])['capabilities']['deployment_model'])  # Result

    def test_post_and_confirm_modify_with_invalid_deployment_model(self):
        vals = {
            'backend': constants.SB_TYPE_CEPH_ROOK,
            'confirmed': True
        }
        response = self.post_json('/storage_ceph_rook', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_CEPH_ROOK,  # Expected
                         self.get_json('/storage_ceph_rook/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_ceph_rook/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              capabilities=jsonutils.dumps({
                                                  constants.CEPH_ROOK_BACKEND_DEPLOYMENT_CAP:
                                                  'invalid_deployment_model'}),
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Deployment_model invalid_deployment_model is not supported',
                      patch_response.json['error_message'])

    def test_post_and_confirm_modify_with_unsupported_deployment_model(self):
        vals = {
            'backend': constants.SB_TYPE_CEPH_ROOK,
            'confirmed': True
        }
        response = self.post_json('/storage_ceph_rook', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_CEPH_ROOK,  # Expected
                         self.get_json('/storage_ceph_rook/%s/' %
                                       response.json['uuid'])['backend'])  # Result

        patch_response = self.patch_dict_json('/storage_ceph_rook/%s' % response.json['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              capabilities=jsonutils.dumps({
                                                  constants.CEPH_ROOK_BACKEND_DEPLOYMENT_CAP:
                                                  constants.CEPH_ROOK_DEPLOYMENT_DEDICATED}),
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Change deployment model controller<->dedicated is not supported.',
                      patch_response.json['error_message'])

    def test_post_and_list(self):
        vals = {
            'backend': constants.SB_TYPE_CEPH_ROOK,
            'capabilities': {constants.CEPH_ROOK_BACKEND_DEPLOYMENT_CAP: constants.CEPH_ROOK_DEPLOYMENT_CONTROLLER},
            'confirmed': True
        }
        response = self.post_json('/storage_ceph_rook/', vals, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_TYPE_CEPH_ROOK,  # Expected
                         self.get_json('/storage_ceph_rook/%s/' %
                                       response.json['uuid'])['backend'])  # Result
        self.assertEqual(constants.SB_TYPE_CEPH_ROOK,
                         self.get_json('/storage_backend')['storage_backends'][0]['backend'])


class StorageBackendConfigTest(base.FunctionalTest):
    def setUp(self):
        super(StorageBackendConfigTest, self).setUp()
        self.dbapi = dbapi.get_instance()

        pool_mgmt = dbutils.create_test_address_pool(
            name='mgmt',
            network='192.168.204.0',
            ranges=[['192.168.204.2', '192.168.204.254']],
            prefix=24)
        dbutils.create_test_network(
            type=constants.NETWORK_TYPE_MGMT,
            address_pool_id=pool_mgmt.id,
            primary_pool_family="IPv4")

        pool_clhost = dbutils.create_test_address_pool(
            name='clhost',
            network='193.168.204.0',
            ranges=[['193.168.204.2', '193.168.204.254']],
            prefix=24)
        dbutils.create_test_network(
            type=constants.NETWORK_TYPE_CLUSTER_HOST,
            address_pool_id=pool_clhost.id,
            primary_pool_family="IPv4")

    def test_get_ceph_mon_ip_addresses(self):
        self._test_get_ceph_mon_ip_addresses(constants.NETWORK_TYPE_MGMT)
        self._test_get_ceph_mon_ip_addresses(constants.NETWORK_TYPE_CLUSTER_HOST)
        pass

    def _test_get_ceph_mon_ip_addresses(self, network_type):
        hostnames = [constants.CONTROLLER_HOSTNAME,
                     constants.CONTROLLER_0_HOSTNAME,
                     constants.CONTROLLER_1_HOSTNAME]
        ips_mock = ['1', '2', '3']
        placeholders = [constants.CEPH_FLOATING_MON,
                        constants.CEPH_MON_0,
                        constants.CEPH_MON_1]
        result_mock = dict(map(lambda x, y: (x, y), placeholders, ips_mock))

        addresses = list(map(lambda x: '{}-{}'.format(x, network_type), hostnames))
        addresses_mock = \
            list(map(lambda x, y: ({'name': x, 'address': y,
                                    'family': constants.IPV4_FAMILY}), addresses, ips_mock))
        addresses_mock_object = \
            list(map(lambda x: namedtuple("Addresses", x.keys())(*x.values()), addresses_mock))

        p = mock.patch.object(self.dbapi, 'ceph_mon_get_list')
        p.start().return_value = list(map(lambda x: {'hostname': x}, hostnames))
        self.addCleanup(p.stop)

        p = mock.patch.object(self.dbapi, 'storage_ceph_get_list')
        p.start().return_value = [{'network': network_type}]
        self.addCleanup(p.stop)

        p = mock.patch.object(self.dbapi, 'addresses_get_all')
        p.start().return_value = addresses_mock_object
        self.addCleanup(p.stop)

        ceph_network_type, result = StorageBackendConfig.get_ceph_mon_ip_addresses(self.dbapi)
        self.assertDictEqual(result, result_mock)
        self.assertEqual(ceph_network_type, network_type)


class StorageBackendConfigTestIPv6(base.FunctionalTest):
    def setUp(self):
        super(StorageBackendConfigTestIPv6, self).setUp()
        self.dbapi = dbapi.get_instance()

        pool_mgmt = dbutils.create_test_address_pool(
            name='mgmt-ipv6',
            network='fd00::',
            ranges=[['fd00::1', 'fd00::ffff']],
            prefix=64, family=constants.IPV6_FAMILY)
        dbutils.create_test_network(
            type=constants.NETWORK_TYPE_MGMT,
            address_pool_id=pool_mgmt.id,
            primary_pool_family="IPv6")

        pool_clhost = dbutils.create_test_address_pool(
            name='clhost-ipv6',
            network='fd01::',
            ranges=[['fd01::1', 'fd00::ffff']],
            prefix=64, family=constants.IPV6_FAMILY)
        dbutils.create_test_network(
            type=constants.NETWORK_TYPE_CLUSTER_HOST,
            address_pool_id=pool_clhost.id,
            primary_pool_family="IPv6")

    def test_get_ceph_mon_ipv6_addresses(self):
        self._test_get_ceph_mon_ip_addresses(constants.NETWORK_TYPE_MGMT)
        self._test_get_ceph_mon_ip_addresses(constants.NETWORK_TYPE_CLUSTER_HOST)
        pass

    def _test_get_ceph_mon_ip_addresses(self, network_type):
        hostnames = [constants.CONTROLLER_HOSTNAME,
                     constants.CONTROLLER_0_HOSTNAME,
                     constants.CONTROLLER_1_HOSTNAME]
        ips_mock = ['1', '2', '3']
        placeholders = [constants.CEPH_FLOATING_MON,
                        constants.CEPH_MON_0,
                        constants.CEPH_MON_1]
        result_mock = dict(map(lambda x, y: (x, y), placeholders, ips_mock))

        addresses = list(map(lambda x: '{}-{}'.format(x, network_type), hostnames))
        addresses_mock = \
            list(map(lambda x, y: ({'name': x, 'address': y,
                                    'family': constants.IPV6_FAMILY}), addresses, ips_mock))
        addresses_mock_object = \
            list(map(lambda x: namedtuple("Addresses", x.keys())(*x.values()), addresses_mock))

        p = mock.patch.object(self.dbapi, 'ceph_mon_get_list')
        p.start().return_value = list(map(lambda x: {'hostname': x}, hostnames))
        self.addCleanup(p.stop)

        p = mock.patch.object(self.dbapi, 'storage_ceph_get_list')
        p.start().return_value = [{'network': network_type}]
        self.addCleanup(p.stop)

        p = mock.patch.object(self.dbapi, 'addresses_get_all')
        p.start().return_value = addresses_mock_object
        self.addCleanup(p.stop)

        ceph_network_type, result = StorageBackendConfig.get_ceph_mon_ip_addresses(self.dbapi)
        self.assertDictEqual(result, result_mock)
        self.assertEqual(ceph_network_type, network_type)
