#
# Copyright (c) 2020-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API / network / methods.
"""

import mock
from six.moves import http_client

from oslo_utils import uuidutils
from sysinv.common import constants

from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils


class NetworkTestCase(base.FunctionalTest, dbbase.BaseHostTestCase):

    # API_HEADERS are a generic header passed to most API calls
    API_HEADERS = {'User-Agent': 'sysinv-test'}

    # API_PREFIX is the prefix for the URL
    API_PREFIX = '/networks'

    # RESULT_KEY is the python table key for the list of results
    RESULT_KEY = 'networks'

    # COMMON_FIELD is a field that is known to exist for inputs and outputs
    COMMON_FIELD = 'type'

    # expected_api_fields are attributes that should be populated by
    # an API query
    expected_api_fields = ['id',
                           'uuid',
                           'name',
                           'type',
                           'dynamic',
                           'pool_uuid',
                           ]

    # hidden_api_fields are attributes that should not be populated by
    # an API query
    hidden_api_fields = ['forihostid']

    def setUp(self):
        super(NetworkTestCase, self).setUp()

    def get_single_url(self, uuid):
        return '%s/%s' % (self.API_PREFIX, uuid)

    def assert_fields(self, api_object):
        # check the uuid is a uuid
        assert(uuidutils.is_uuid_like(api_object['uuid']))

        # Verify that expected attributes are returned
        for field in self.expected_api_fields:
            self.assertIn(field, api_object)

        # Verify that hidden attributes are not returned
        for field in self.hidden_api_fields:
            self.assertNotIn(field, api_object)

    def get_post_object(self, network_type, address_pool_id):
        net_db = dbutils.get_test_network(
            type=network_type,
            address_pool_id=address_pool_id
        )

        # pool_uuid in api corresponds to address_pool_id in db
        net_db['pool_uuid'] = net_db.pop('address_pool_id')

        return net_db

    def _create_db_object(self, network_type=constants.NETWORK_TYPE_MGMT):
        return self._create_test_network(
            name=network_type,
            network_type=network_type,
            subnet=self.mgmt_subnet,
        )

    # Don't create default test networks
    def _create_test_networks(self):
        pass

    def _create_test_oam(self):
        pass

    # Skip creating static pxeboot ip
    def _create_test_static_ips(self):
        hostnames = [
            constants.CONTROLLER_GATEWAY,
            constants.CONTROLLER_HOSTNAME,
            constants.CONTROLLER_0_HOSTNAME,
            constants.CONTROLLER_1_HOSTNAME
        ]

        self._create_test_addresses(
            hostnames,
            self.mgmt_subnet,
            constants.NETWORK_TYPE_MGMT)

        self._create_test_addresses(
            hostnames, self.oam_subnet,
            constants.NETWORK_TYPE_OAM)

        self._create_test_addresses(
            hostnames, self.cluster_host_subnet,
            constants.NETWORK_TYPE_CLUSTER_HOST)

        self._create_test_addresses(
            hostnames, self.storage_subnet,
            constants.NETWORK_TYPE_STORAGE)

        self._create_test_addresses(
            hostnames, self.admin_subnet,
            constants.NETWORK_TYPE_ADMIN)

        self._create_test_addresses(
            hostnames, self.system_controller_subnet,
            constants.NETWORK_TYPE_SYSTEM_CONTROLLER)

        self._create_test_addresses(
            hostnames, self.system_controller_oam_subnet,
            constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM)


class TestPostMixin(NetworkTestCase):

    def setUp(self):
        super(TestPostMixin, self).setUp()

    def _test_create_network_success(self, name, network_type, subnet):
        # Test creation of object

        address_pool_id = self._create_test_address_pool(name, subnet)['uuid']

        ndict = self.get_post_object(network_type, address_pool_id)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)

        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        # Check that an expected field matches.
        self.assertEqual(response.json[self.COMMON_FIELD],
                         ndict[self.COMMON_FIELD])

        uuid = response.json['uuid']
        # Verify that the object was created and some basic attribute matches
        response = self.get_json(self.get_single_url(uuid))
        self.assertEqual(response[self.COMMON_FIELD],
                         ndict[self.COMMON_FIELD])

    def _test_create_network_fail_duplicate(self, name, network_type, subnet):
        # Test creation of object

        address_pool_id = self._create_test_address_pool(name, subnet)['uuid']

        ndict = self.get_post_object(network_type, address_pool_id)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS)

        # Check HTTP response is successful
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.CONFLICT)
        self.assertIn("Network of type %s already exists." % network_type,
                      response.json['error_message'])

    def test_create_success_system_controller_oam(self):
        self._create_test_host(constants.CONTROLLER)
        m = mock.Mock()
        update_dnsmasq_config = "sysinv.conductor.rpcapi." \
                                        "ConductorAPI." \
                                        "update_dnsmasq_config"
        with mock.patch('sysinv.common.utils.is_initial_config_complete',
                        lambda: True), \
            mock.patch(update_dnsmasq_config,
                       m.update_dnsmasq_config):
            self._test_create_network_success(
                'system-controller-oam',
                constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM,
                self.system_controller_oam_subnet)
        m.update_dnsmasq_config.assert_called_once()

    def test_create_success_system_controller(self):
        self._create_test_host(constants.CONTROLLER)
        m = mock.Mock()
        update_ldap_client_config = "sysinv.conductor.rpcapi." \
                                        "ConductorAPI." \
                                        "update_ldap_client_config"
        with mock.patch('sysinv.common.utils.is_initial_config_complete',
                        lambda: True), \
            mock.patch(update_ldap_client_config,
                       m.update_ldap_client_config):
            self._test_create_network_success(
                'system-controller',
                constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
                self.system_controller_subnet)
        m.update_ldap_client_config.assert_called_once()

    def test_create_success_pxeboot(self):
        self._test_create_network_success(
            'pxeboot',
            constants.NETWORK_TYPE_PXEBOOT,
            self.pxeboot_subnet)

    def test_create_success_management(self):
        self._test_create_network_success(
            'management',
            constants.NETWORK_TYPE_MGMT,
            self.mgmt_subnet)

    def test_create_success_oam(self):
        self._test_create_network_success(
            'oam',
            constants.NETWORK_TYPE_OAM,
            self.oam_subnet)

    def test_create_oam_calls_reconfigure_service_endpoints(self):
        self._create_test_host(constants.CONTROLLER)
        m = mock.Mock()
        reconfigure_service_endpoints = "sysinv.conductor.rpcapi." \
                                        "ConductorAPI." \
                                        "reconfigure_service_endpoints"
        with mock.patch(reconfigure_service_endpoints,
                        m.reconfigure_service_endpoints):
            self._test_create_network_success(
                'oam',
                constants.NETWORK_TYPE_OAM,
                self.oam_subnet)
        m.reconfigure_service_endpoints.assert_called_once()

    def test_create_success_cluster_host(self):
        self._test_create_network_success(
            'cluster-host',
            constants.NETWORK_TYPE_CLUSTER_HOST,
            self.cluster_host_subnet)

    def test_create_success_cluster_pod(self):
        self._test_create_network_success(
            'cluster-pod',
            constants.NETWORK_TYPE_CLUSTER_POD,
            self.cluster_pod_subnet)

    def test_create_success_cluster_service(self):
        self._test_create_network_success(
            'cluster-service',
            constants.NETWORK_TYPE_CLUSTER_SERVICE,
            self.cluster_service_subnet)

    def test_create_success_storage(self):
        self._test_create_network_success(
            'storage',
            constants.NETWORK_TYPE_STORAGE,
            self.storage_subnet)

    def test_create_success_admin(self):
        self._test_create_network_success(
            'admin',
            constants.NETWORK_TYPE_ADMIN,
            self.admin_subnet)

    def test_create_fail_duplicate_pxeboot(self):
        self._test_create_network_fail_duplicate(
            'pxeboot',
            constants.NETWORK_TYPE_PXEBOOT,
            self.pxeboot_subnet)

    def test_create_fail_duplicate_management(self):
        self._test_create_network_fail_duplicate(
            'management',
            constants.NETWORK_TYPE_MGMT,
            self.mgmt_subnet)

    def test_create_fail_duplicate_oam(self):
        self._test_create_network_fail_duplicate(
            'oam',
            constants.NETWORK_TYPE_OAM,
            self.oam_subnet)

    def test_create_fail_duplicate_cluster_host(self):
        self._test_create_network_fail_duplicate(
            'cluster-host',
            constants.NETWORK_TYPE_CLUSTER_HOST,
            self.cluster_host_subnet)

    def test_create_fail_duplicate_cluster_pod(self):
        self._test_create_network_fail_duplicate(
            'cluster-pod',
            constants.NETWORK_TYPE_CLUSTER_POD,
            self.cluster_pod_subnet)

    def test_create_fail_duplicate_cluster_service(self):
        self._test_create_network_fail_duplicate(
            'cluster-service',
            constants.NETWORK_TYPE_CLUSTER_SERVICE,
            self.cluster_service_subnet)

    def test_create_fail_duplicate_storage(self):
        self._test_create_network_fail_duplicate(
            'storage',
            constants.NETWORK_TYPE_STORAGE,
            self.storage_subnet)

    def test_create_fail_duplicate_admin(self):
        self._test_create_network_fail_duplicate(
            'admin',
            constants.NETWORK_TYPE_ADMIN,
            self.admin_subnet)

    def test_create_with_invalid_type(self):
        # Test creation with an invalid type
        address_pool_id = self._create_test_address_pool(
            'management',
            self.mgmt_subnet
        )['uuid']
        ndict = self.get_post_object(constants.NETWORK_TYPE_DATA,
                                     address_pool_id)
        ndict['type'] = constants.NETWORK_TYPE_DATA
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code,
                         http_client.INTERNAL_SERVER_ERROR)
        self.assertIn("Network type data not supported",
                      response.json['error_message'])

    def test_create_with_invalid_additional_attributes(self):
        # Test creation with an invalid attribute called 'foo'
        address_pool_id = self._create_test_address_pool(
            'management',
            self.mgmt_subnet
        )['uuid']
        ndict = self.get_post_object(constants.NETWORK_TYPE_MGMT,
                                     address_pool_id)
        ndict['foo'] = 'some value'
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        # Check HTTP response is failed
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.BAD_REQUEST)
        self.assertIn("Unknown attribute for argument network: foo",
                      response.json['error_message'])


class TestDelete(NetworkTestCase):
    """ Tests deletion.
        Typically delete APIs return NO CONTENT.
        python2 and python3 libraries may return different
        content_type (None, or empty json) when NO_CONTENT returned.
    """

    def setUp(self):
        super(TestDelete, self).setUp()

    def _test_delete_allowed(self, network_type):
        # Delete the API object
        self.delete_object = self._create_db_object(network_type=network_type)
        uuid = self.delete_object.uuid
        response = self.delete(self.get_single_url(uuid),
                               headers=self.API_HEADERS)

        # Verify the expected API response for the delete
        self.assertEqual(response.status_code, http_client.NO_CONTENT)

    def _test_delete_after_initial_config_not_allowed(self, network_type):
        # Delete the API object
        self.delete_object = self._create_db_object(network_type=network_type)
        with mock.patch('sysinv.common.utils.is_initial_config_complete',
                        lambda: True):
            uuid = self.delete_object.uuid
            response = self.delete(self.get_single_url(uuid),
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

            # Verify the expected API response for the delete
            self.assertEqual(response.status_code, http_client.BAD_REQUEST)
            expected_error = ("Cannot delete type %s network %s after"
                              " initial configuration completion" %
                              (network_type, uuid))
            self.assertIn(expected_error, response.json['error_message'])

    def _test_delete_after_initial_config_allowed(self, network_type):
        # Delete the API object
        self.delete_object = self._create_db_object(network_type=network_type)
        with mock.patch('sysinv.common.utils.is_initial_config_complete',
                        lambda: True):
            uuid = self.delete_object.uuid
            response = self.delete(self.get_single_url(uuid),
                                   headers=self.API_HEADERS)

            # Verify the expected API response for the delete
            self.assertEqual(response.status_code, http_client.NO_CONTENT)

    def test_delete_pxeboot(self):
        self._test_delete_allowed(constants.NETWORK_TYPE_PXEBOOT)

    def test_delete_pxeboot_after_initial_config(self):
        self._test_delete_after_initial_config_not_allowed(
            constants.NETWORK_TYPE_PXEBOOT
        )

    def test_delete_management(self):
        self._test_delete_allowed(constants.NETWORK_TYPE_MGMT)

    def test_delete_management_after_initial_config(self):
        self._test_delete_after_initial_config_not_allowed(
            constants.NETWORK_TYPE_MGMT
        )

    def test_delete_oam(self):
        self._test_delete_allowed(constants.NETWORK_TYPE_OAM)

    def test_delete_oam_after_initial_config(self):
        self._test_delete_after_initial_config_not_allowed(
            constants.NETWORK_TYPE_OAM
        )

    def test_delete_cluster_host(self):
        self._test_delete_allowed(constants.NETWORK_TYPE_CLUSTER_HOST)

    def test_delete_cluster_host_after_initial_config(self):
        self._test_delete_after_initial_config_not_allowed(
            constants.NETWORK_TYPE_CLUSTER_HOST
        )

    def test_delete_cluster_pod(self):
        self._test_delete_allowed(constants.NETWORK_TYPE_CLUSTER_POD)

    def test_delete_cluster_pod_after_initial_config(self):
        self._test_delete_after_initial_config_not_allowed(
            constants.NETWORK_TYPE_CLUSTER_POD
        )

    def test_delete_cluster_service(self):
        self._test_delete_allowed(constants.NETWORK_TYPE_CLUSTER_SERVICE)

    def test_delete_cluster_service_after_initial_config(self):
        self._test_delete_after_initial_config_not_allowed(
            constants.NETWORK_TYPE_CLUSTER_SERVICE
        )

    def test_delete_storage_subnet(self):
        self._test_delete_allowed(constants.NETWORK_TYPE_STORAGE)

    def test_delete_storage_subnet_after_initial_config(self):
        self._test_delete_after_initial_config_not_allowed(
            constants.NETWORK_TYPE_STORAGE
        )

    def test_delete_admin_subnet(self):
        self._test_delete_allowed(constants.NETWORK_TYPE_ADMIN)

    def test_delete_admin_subnet_after_initial_config(self):
        self._test_delete_after_initial_config_not_allowed(
            constants.NETWORK_TYPE_ADMIN)

    def test_delete_data(self):
        self._test_delete_allowed(constants.NETWORK_TYPE_DATA)

    def test_delete_data_after_initial_config(self):
        self._test_delete_after_initial_config_allowed(
            constants.NETWORK_TYPE_DATA
        )


class TestList(NetworkTestCase):
    """ Network list operations
    """

    def setUp(self):
        super(TestList, self).setUp()

    def test_empty_list(self):
        response = self.get_json(self.API_PREFIX)
        self.assertEqual([], response[self.RESULT_KEY])

    def test_single_entry(self):
        # create a single object
        self.single_object = self._create_db_object()
        response = self.get_json(self.API_PREFIX)
        self.assertEqual(1, len(response[self.RESULT_KEY]))


class TestPatch(NetworkTestCase):
    patch_path = '/dynamic'
    patch_field = 'dynamic'
    patch_value = False

    def setUp(self):
        super(TestPatch, self).setUp()
        self.patch_object = self._create_db_object()

    def test_patch_not_allowed(self):
        # Try and patch an unmodifiable value

        response = self.patch_json(self.get_single_url(self.patch_object.uuid),
                                   [{'path': '/junk_field',
                                     'value': self.patch_value,
                                     'op': 'replace'}],
                                   headers=self.API_HEADERS,
                                   expect_errors=True)

        # Verify the expected API response
        self.assertEqual(response.content_type, 'application/json')
        self.assertEqual(response.status_code, http_client.METHOD_NOT_ALLOWED)
        self.assertIn("The method PATCH is not allowed for this resource.",
                      response.json['error_message'])


class IPv4TestPost(TestPostMixin,
                   NetworkTestCase):
    pass


class IPv6TestPost(TestPostMixin,
                   dbbase.BaseIPv6Mixin,
                   NetworkTestCase):
    pass
