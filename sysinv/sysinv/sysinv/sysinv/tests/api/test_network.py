#
# Copyright (c) 2020-2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API / network / methods.
"""

import mock
import netaddr

from six.moves import http_client

from oslo_utils import uuidutils
from sysinv.common import constants
from sysinv.common import exception

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
                           'primary_pool_family'
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
        assert (uuidutils.is_uuid_like(api_object['uuid']))

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
            subnets=self.mgmt_subnets,
        )

    # Don't create default test networks
    def _create_test_networks(self):
        pass

    def _create_test_oam(self):
        pass

    HOSTNAMES = [constants.CONTROLLER_GATEWAY,
                 constants.CONTROLLER_HOSTNAME,
                 constants.CONTROLLER_0_HOSTNAME,
                 constants.CONTROLLER_1_HOSTNAME]

    # Skip creating static pxeboot ip
    def _create_test_static_ips(self):
        self._create_test_addresses(
            self.HOSTNAMES,
            self.mgmt_subnets,
            constants.NETWORK_TYPE_MGMT)

        self._create_test_addresses(
            self.HOSTNAMES, self.oam_subnets,
            constants.NETWORK_TYPE_OAM)

        self._create_test_addresses(
            self.HOSTNAMES, self.cluster_host_subnets,
            constants.NETWORK_TYPE_CLUSTER_HOST)

        self._create_test_addresses(
            self.HOSTNAMES, self.storage_subnets,
            constants.NETWORK_TYPE_STORAGE)

        self._create_test_addresses(
            self.HOSTNAMES, self.admin_subnets,
            constants.NETWORK_TYPE_ADMIN)

        self._create_test_addresses(
            self.HOSTNAMES, self.system_controller_subnets,
            constants.NETWORK_TYPE_SYSTEM_CONTROLLER)

        self._create_test_addresses(
            self.HOSTNAMES, self.system_controller_oam_subnets,
            constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM)

    def _create_test_static_ips_for_subnet(self, network_type, subnet):
        self._create_test_addresses(self.HOSTNAMES, [subnet], network_type)

    def create_test_interface(self, ifname, host):
        interface = dbutils.create_test_interface(
            ifname=ifname,
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=host.id,
            ihost_uuid=host.uuid)
        return interface


class TestPostMixin(object):

    def setUp(self):
        super(TestPostMixin, self).setUp()

    def _test_create_network_success(self, network_type, addrpool):
        # Test creation of object
        ndict = self.get_post_object(network_type, addrpool.uuid)
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
        return addrpool.id

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

    def _check_pool_address(self, addrpool, field, name):
        address_id = getattr(addrpool, field)
        self.assertIsNotNone(address_id)
        address = self.dbapi.address_get(address_id)
        self.assertEqual(name, address.name)
        self.assertEqual(addrpool.uuid, address.pool_uuid)

    def _check_pool_addresses(self, addrpool, field_name_index):
        for field, name in field_name_index.items():
            self._check_pool_address(addrpool, field, name)

    def _remove_static_addresses(self, subnet, first, last):
        for offset in range(first, last + 1):
            try:
                address = self.dbapi.address_get_by_address(str(subnet[offset]))
                self.dbapi.address_destroy(address.id)
            except exception.AddressNotFoundByAddress:
                pass

    def test_create_success_system_controller_oam(self):
        self._create_test_host(constants.CONTROLLER)
        addrpool = self._create_test_address_pool('system-controller-oam',
                                                  self.system_controller_oam_subnet)
        m = mock.Mock()
        update_dnsmasq_config = "sysinv.conductor.rpcapi.ConductorAPI.update_dnsmasq_config"
        with mock.patch('sysinv.common.utils.is_initial_config_complete', lambda: True), \
                        mock.patch(update_dnsmasq_config, m.update_dnsmasq_config):
            address_pool_id = self._test_create_network_success(
                constants.NETWORK_TYPE_SYSTEM_CONTROLLER_OAM, addrpool)
        m.update_dnsmasq_config.assert_called_once()

        address_pool = self.dbapi.address_pool_get(address_pool_id)
        self.assertIsNone(address_pool.floating_address)
        self.assertIsNone(address_pool.controller0_address)
        self.assertIsNone(address_pool.controller1_address)
        self.assertIsNone(address_pool.gateway_address)

    def test_create_success_system_controller(self):
        self._create_test_host(constants.CONTROLLER)
        addrpool = self._create_test_address_pool('system-controller',
                                                  self.system_controller_subnet)
        m = mock.Mock()
        update_ldap_client_config = "sysinv.conductor.rpcapi.ConductorAPI.update_ldap_client_config"
        update_ldap_nat_config = "sysinv.conductor.rpcapi.ConductorAPI.update_ldap_nat_config"
        with mock.patch('sysinv.common.utils.is_initial_config_complete', lambda: True), \
                        mock.patch(update_ldap_client_config, m.update_ldap_client_config), \
                        mock.patch(update_ldap_nat_config, m.update_ldap_nat_config):
            self._test_create_network_success(constants.NETWORK_TYPE_SYSTEM_CONTROLLER, addrpool)
        m.update_ldap_client_config.assert_called_once()
        m.update_ldap_nat_config.assert_called_once()

        updated_addrpool = self.dbapi.address_pool_get(addrpool.id)
        self.assertIsNone(updated_addrpool.floating_address)
        self.assertIsNone(updated_addrpool.controller0_address)
        self.assertIsNone(updated_addrpool.controller1_address)
        self.assertIsNone(updated_addrpool.gateway_address)

    def test_create_success_pxeboot(self):
        addrpool = self._create_test_address_pool('pxeboot', self.pxeboot_subnet)
        self._test_create_network_success(constants.NETWORK_TYPE_PXEBOOT, addrpool)
        updated_addrpool = self.dbapi.address_pool_get(addrpool.id)
        self._check_pool_addresses(updated_addrpool,
                                   {'floating_address_id': 'controller-pxeboot',
                                   'controller0_address_id': 'controller-0-pxeboot',
                                   'controller1_address_id': 'controller-1-pxeboot'})
        self.assertIsNone(updated_addrpool.gateway_address)

    def test_create_success_management_existing_unassigned_addresses(self):
        gateway_addr = self.dbapi.address_get_by_address(str(self.mgmt_subnet[1]))
        floating_addr = self.dbapi.address_get_by_address(str(self.mgmt_subnet[2]))
        c0_addr = self.dbapi.address_get_by_address(str(self.mgmt_subnet[3]))
        c1_addr = self.dbapi.address_get_by_address(str(self.mgmt_subnet[4]))

        other_pool = self._create_test_address_pool('other-ipv4', self.mgmt_subnet)
        self.dbapi.address_pool_update(other_pool.id, {'floating_address_id': floating_addr.id,
                                                       'controller0_address_id': c0_addr.id,
                                                       'controller1_address_id': c1_addr.id})
        self.dbapi.address_update(floating_addr.uuid, {'name': 'floating-other',
                                                       'address_pool_id': other_pool.id})
        self.dbapi.address_update(c0_addr.uuid, {'name': 'c0-other',
                                                 'address_pool_id': other_pool.id})
        self.dbapi.address_update(c1_addr.uuid, {'name': 'c1-other',
                                                 'address_pool_id': other_pool.id})

        mgmt_pool = self._create_test_address_pool('mgmt', self.mgmt_subnet)
        self.dbapi.address_update(gateway_addr.uuid, {'name': 'mgmt-gw',
                                                      'address_pool_id': mgmt_pool.id})
        self.dbapi.address_pool_update(mgmt_pool.id, {'gateway_address_id': gateway_addr.id})

        self._test_create_network_success(constants.NETWORK_TYPE_MGMT, mgmt_pool)

        updated_other_pool = self.dbapi.address_pool_get(other_pool.id)
        self.assertIsNone(updated_other_pool.floating_address_id)
        self.assertIsNone(updated_other_pool.controller0_address_id)
        self.assertIsNone(updated_other_pool.controller1_address_id)

        updated_mgmt_pool = self.dbapi.address_pool_get(mgmt_pool.id)
        for addr, field, name in ((gateway_addr, 'gateway_address_id', 'controller-gateway-mgmt'),
                                  (floating_addr, 'floating_address_id', 'controller-mgmt'),
                                  (c0_addr, 'controller0_address_id', 'controller-0-mgmt'),
                                  (c1_addr, 'controller1_address_id', 'controller-1-mgmt')):
            addr_id = getattr(updated_mgmt_pool, field)
            self.assertEqual(addr.id, addr_id)
            updated_addr = self.dbapi.address_get(addr_id)
            self.assertEqual(name, updated_addr.name)
            self.assertEqual(mgmt_pool.uuid, updated_addr.pool_uuid)

    def test_create_success_management_existing_assigned_addresses(self):
        mgmt_pool = self._create_test_address_pool('mgmt', self.mgmt_subnet, link_addresses=True)
        gateway_addr = self.dbapi.address_get(mgmt_pool.gateway_address_id)
        floating_addr = self.dbapi.address_get(mgmt_pool.floating_address_id)
        c0_addr = self.dbapi.address_get(mgmt_pool.controller0_address_id)
        c1_addr = self.dbapi.address_get(mgmt_pool.controller1_address_id)

        self.dbapi.address_update(gateway_addr.uuid, {'name': 'mgmt-gw'})
        self.dbapi.address_update(floating_addr.uuid, {'name': 'mgmt-floating'})
        self.dbapi.address_update(c0_addr.uuid, {'name': 'mgmt-c0'})
        self.dbapi.address_update(c1_addr.uuid, {'name': 'mgmt-c1'})

        self._test_create_network_success(constants.NETWORK_TYPE_MGMT, mgmt_pool)

        updated_mgmt_pool = self.dbapi.address_pool_get(mgmt_pool.id)
        for addr, field, name in ((gateway_addr, 'gateway_address_id', 'controller-gateway-mgmt'),
                                  (floating_addr, 'floating_address_id', 'controller-mgmt'),
                                  (c0_addr, 'controller0_address_id', 'controller-0-mgmt'),
                                  (c1_addr, 'controller1_address_id', 'controller-1-mgmt')):
            addr_id = getattr(updated_mgmt_pool, field)
            self.assertEqual(addr.id, addr_id)
            updated_addr = self.dbapi.address_get(addr_id)
            self.assertEqual(name, updated_addr.name)
            self.assertEqual(mgmt_pool.uuid, updated_addr.pool_uuid)

    def test_create_success_management_new_addresses(self):
        self._remove_static_addresses(self.mgmt_subnet, 2, 4)
        addrpool = self._create_test_address_pool('mgmt', self.mgmt_subnet)
        gateway_addr = self.dbapi.address_get_by_address(str(self.mgmt_subnet[1]))
        self.dbapi.address_update(gateway_addr.uuid, {'name': 'mgmt-gw',
                                                      'address_pool_id': addrpool.id})
        self.dbapi.address_pool_update(addrpool.id, {'gateway_address_id': gateway_addr.id})

        self._test_create_network_success(constants.NETWORK_TYPE_MGMT, addrpool)

        updated_addrpool = self.dbapi.address_pool_get(addrpool.id)
        self._check_pool_addresses(updated_addrpool,
                                   {'floating_address_id': 'controller-mgmt',
                                    'controller0_address_id': 'controller-0-mgmt',
                                    'controller1_address_id': 'controller-1-mgmt',
                                    'gateway_address_id': 'controller-gateway-mgmt'})

    def test_create_success_management_subcloud(self):
        self._set_dc_role(constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD)

        mgmt_pool = self._create_test_address_pool('mgmt', self.mgmt_subnet, link_addresses=True)
        gateway_addr = self.dbapi.address_get(mgmt_pool.gateway_address_id)
        self.dbapi.address_update(gateway_addr.uuid, {'name': 'mgmt-gw'})

        self._test_create_network_success(constants.NETWORK_TYPE_MGMT, mgmt_pool)

        updated_mgmt_pool = self.dbapi.address_pool_get(mgmt_pool.id)
        self.assertEqual(updated_mgmt_pool.uuid, gateway_addr.pool_uuid)
        self.assertEqual(updated_mgmt_pool.gateway_address_id, gateway_addr.id)

        updated_addr = self.dbapi.address_get(gateway_addr.id)
        self.assertEqual('system-controller-gateway-ip-mgmt', updated_addr.name)

    def test_create_success_oam(self):
        addrpool = self._create_test_address_pool('oam', self.oam_subnet, link_addresses=True)
        addresses = self.dbapi.addresses_get_by_pool(addrpool.id)
        for address in addresses:
            self.dbapi.address_update(address.id, {'name': f"address-{address.id}"})
        self._test_create_network_success(constants.NETWORK_TYPE_OAM, addrpool)
        updated_addrpool = self.dbapi.address_pool_get(addrpool.id)
        self._check_pool_addresses(updated_addrpool,
                                   {'floating_address_id': 'controller-oam',
                                   'controller0_address_id': 'controller-0-oam',
                                   'controller1_address_id': 'controller-1-oam',
                                   'gateway_address_id': 'controller-gateway-oam'})

    def test_create_oam_calls_reconfigure_service_endpoints(self):
        self._create_test_host(constants.CONTROLLER)
        addrpool = self._create_test_address_pool('oam', self.oam_subnet)
        m = mock.Mock()
        reconfigure_service_endpoints = "sysinv.conductor.rpcapi." \
                                        "ConductorAPI." \
                                        "reconfigure_service_endpoints"
        with mock.patch(reconfigure_service_endpoints,
                        m.reconfigure_service_endpoints):
            self._test_create_network_success(
                constants.NETWORK_TYPE_OAM,
                addrpool)
        m.reconfigure_service_endpoints.assert_called_once()

    def test_create_success_cluster_host(self):
        addrpool = self._create_test_address_pool('cluster-host', self.cluster_host_subnet)
        self._test_create_network_success(constants.NETWORK_TYPE_CLUSTER_HOST, addrpool)
        updated_addrpool = self.dbapi.address_pool_get(addrpool.id)
        self._check_pool_addresses(updated_addrpool,
                                   {'floating_address_id': 'controller-cluster-host',
                                   'controller0_address_id': 'controller-0-cluster-host',
                                   'controller1_address_id': 'controller-1-cluster-host'})
        self.assertIsNone(updated_addrpool.gateway_address)

    def test_create_success_cluster_pod(self):
        addrpool = self._create_test_address_pool('cluster-pod', self.cluster_pod_subnet)
        self._test_create_network_success(constants.NETWORK_TYPE_CLUSTER_POD, addrpool)
        updated_addrpool = self.dbapi.address_pool_get(addrpool.id)
        self.assertIsNone(updated_addrpool.floating_address)
        self.assertIsNone(updated_addrpool.controller0_address)
        self.assertIsNone(updated_addrpool.controller1_address)
        self.assertIsNone(updated_addrpool.gateway_address)

    def test_create_success_cluster_pod_with_overlap_cluster_service(self):
        if self.cluster_pod_subnet.version == 4:
            cluster_svc_subnet = netaddr.IPNetwork('172.16.0.0/24')
        else:
            cluster_svc_subnet = netaddr.IPNetwork('fd03::/112')

        self.assertTrue(cluster_svc_subnet in self.cluster_pod_subnet)
        self._create_test_network('cluster-service', constants.NETWORK_TYPE_CLUSTER_SERVICE,
                                  [cluster_svc_subnet])

        addrpool = self._create_test_address_pool('cluster-pod', self.cluster_pod_subnet)
        self._test_create_network_success(constants.NETWORK_TYPE_CLUSTER_POD, addrpool)

    def test_create_success_cluster_service(self):
        addrpool = self._create_test_address_pool('cluster-service', self.cluster_service_subnet)
        self._test_create_network_success(constants.NETWORK_TYPE_CLUSTER_SERVICE, addrpool)
        updated_addrpool = self.dbapi.address_pool_get(addrpool.id)
        self.assertIsNone(updated_addrpool.floating_address)
        self.assertIsNone(updated_addrpool.controller0_address)
        self.assertIsNone(updated_addrpool.controller1_address)
        self.assertIsNone(updated_addrpool.gateway_address)

    def test_create_success_cluster_service_with_overlap_cluster_pod(self):

        if self.cluster_service_subnet.version == 4:
            cluster_pod_subnet = netaddr.IPNetwork('10.96.0.0/10')
        else:
            cluster_pod_subnet = netaddr.IPNetwork('fd04::/64')

        self.assertTrue(self.cluster_service_subnet in cluster_pod_subnet)

        self._create_test_network('cluster-pod', constants.NETWORK_TYPE_CLUSTER_POD,
                                  [cluster_pod_subnet])

        addrpool = self._create_test_address_pool('cluster-service', self.cluster_service_subnet)
        self._test_create_network_success(constants.NETWORK_TYPE_CLUSTER_SERVICE, addrpool)

    def test_create_success_storage(self):
        addrpool = self._create_test_address_pool('storage', self.storage_subnet)
        self._test_create_network_success(constants.NETWORK_TYPE_STORAGE, addrpool)
        updated_addrpool = self.dbapi.address_pool_get(addrpool.id)
        self._check_pool_addresses(updated_addrpool,
                                   {'floating_address_id': 'controller-storage',
                                   'controller0_address_id': 'controller-0-storage',
                                   'controller1_address_id': 'controller-1-storage'})
        self.assertIsNone(updated_addrpool.gateway_address)

    def test_create_success_admin(self):
        self._set_dc_role(constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD)

        addrpool = self._create_test_address_pool('admin', self.admin_subnet)
        gateway_addr = self.dbapi.address_get_by_address(str(self.admin_subnet[1]))
        self.dbapi.address_update(gateway_addr.uuid, {'name': 'admin-gw',
                                                      'address_pool_id': addrpool.id})
        self.dbapi.address_pool_update(addrpool.id, {'gateway_address_id': gateway_addr.id})

        self._test_create_network_success(constants.NETWORK_TYPE_ADMIN, addrpool)

        updated_addrpool = self.dbapi.address_pool_get(addrpool.id)
        self._check_pool_addresses(updated_addrpool,
                                   {'floating_address_id': 'controller-admin',
                                   'controller0_address_id': 'controller-0-admin',
                                   'controller1_address_id': 'controller-1-admin',
                                   'gateway_address_id': 'system-controller-gateway-ip-admin'})

    def test_create_success_admin_non_subcloud(self):
        addrpool = self._create_test_address_pool('admin', self.admin_subnet)
        p = mock.patch('sysinv.api.controllers.v1.utils.get_distributed_cloud_role')
        self.mock_utils_get_distributed_cloud_role = p.start()
        self.mock_utils_get_distributed_cloud_role.return_value = \
            constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER
        self.addCleanup(p.stop)

        self._test_create_network_success(
            constants.NETWORK_TYPE_ADMIN,
            addrpool)

    def test_create_fail_duplicate_pxeboot(self):
        self._test_create_network_fail_duplicate(
            'pxeboot',
            constants.NETWORK_TYPE_PXEBOOT,
            self.pxeboot_subnet)

    def test_create_fail_duplicate_management(self):
        self._test_create_network_fail_duplicate(
            'mgmt',
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
        self._set_dc_role(constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD)
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

    def test_fail_address_pool_overlap(self):
        oamnet = self._create_test_network('oam',
                                           constants.NETWORK_TYPE_OAM,
                                           self.oam_subnets,
                                           link_addresses=True)

        chnet = self._create_test_network('cluster-host',
                                          constants.NETWORK_TYPE_CLUSTER_HOST,
                                          self.cluster_host_subnets,
                                          link_addresses=True)

        mgmtnet = self._create_test_network('management',
                                            constants.NETWORK_TYPE_MGMT,
                                            self.mgmt_subnets,
                                            link_addresses=True)

        oam_pool = self._find_network_address_pools(oamnet.id)[0]
        ch_pool = self._find_network_address_pools(chnet.id)[0]
        mgmt_pool = self._find_network_address_pools(mgmtnet.id)[0]

        self.dbapi.network_destroy(mgmtnet.uuid)

        if self.mgmt_subnet.version == constants.IPV4_FAMILY:
            oam_subnet = netaddr.IPNetwork('192.169.1.0/24')
            ch_subnet = netaddr.IPNetwork('192.169.2.0/24')
            mgmt_subnet = netaddr.IPNetwork('192.169.0.0/16')
        else:
            oam_subnet = netaddr.IPNetwork('fdaa:0:0:1:1::/80')
            ch_subnet = netaddr.IPNetwork('fdaa:0:0:1:2::/80')
            mgmt_subnet = netaddr.IPNetwork('fdaa:0:0:1::/64')

        self.dbapi.address_pool_update(oam_pool.uuid,
                                       {'network': str(oam_subnet.ip),
                                        'prefix': str(oam_subnet.prefixlen),
                                        'ranges': [[str(oam_subnet[1]), str(oam_subnet[-1])]]})
        self.dbapi.address_pool_update(ch_pool.uuid,
                                       {'network': str(ch_subnet.ip),
                                        'prefix': str(ch_subnet.prefixlen),
                                        'ranges': [[str(ch_subnet[1]), str(ch_subnet[-1])]]})
        self.dbapi.address_pool_update(mgmt_pool.uuid,
                                       {'network': str(mgmt_subnet.ip),
                                        'prefix': str(mgmt_subnet.prefixlen),
                                        'ranges': [[str(mgmt_subnet[1]), str(mgmt_subnet[-1])]]})

        oam_addr_pool = self.dbapi.address_pool_get(oam_pool.uuid)
        self.assertEqual(oam_addr_pool.ranges, [[str(oam_subnet[1]), str(oam_subnet[-1])]])
        controller0 = self._create_test_host(constants.CONTROLLER)

        c0_if0 = dbutils.create_test_interface(
            ifname='c0-if0',
            ifclass=constants.INTERFACE_CLASS_PLATFORM,
            forihostid=controller0.id,
            ihost_uuid=controller0.uuid)

        self.dbapi.address_mode_update(c0_if0.id, {'family': oam_pool.family, 'mode': 'pool',
                                                   'address_pool_id': oam_pool.id})

        ndict = self.get_post_object(constants.NETWORK_TYPE_MGMT,
                                     mgmt_pool.uuid)
        response = self.post_json(self.API_PREFIX,
                                  ndict,
                                  headers=self.API_HEADERS,
                                  expect_errors=True)

        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.CONFLICT)
        msg = (f"Address pool '{mgmt_pool.name}' {{{mgmt_pool.uuid}}} "
               f"{mgmt_subnet.ip}/{mgmt_subnet.prefixlen} overlaps with: "
               f"'{oam_pool.name}' {{{oam_pool.uuid}}} assigned to oam network and "
               f"to '{c0_if0.ifname}' interface in host {controller0.hostname}, "
               f"'{ch_pool.name}' {{{ch_pool.uuid}}} assigned to cluster-host network")
        self.assertIn(msg, response.json['error_message'])

    def test_create_management_existing_addresses(self):
        subnet = self.mgmt_subnet

        mgmt_pool = dbutils.create_test_address_pool(
            name='management',
            family=subnet.version,
            network=str(subnet.ip),
            prefix=subnet.prefixlen,
            ranges=[[str(subnet[2]), str(subnet[-1])]])

        other_pool = dbutils.create_test_address_pool(
            name='existing-pool',
            family=subnet.version,
            network=str(subnet.ip),
            prefix=subnet.prefixlen,
            ranges=[[str(subnet[1]), str(subnet[-1])]])

        updates = {}
        addresses = {}
        ip_address = subnet[2]
        fields = ['floating_address_id', 'controller0_address_id', 'controller1_address_id']
        values = {'family': subnet.version,
                  'prefix': subnet.prefixlen,
                  'address_pool_id': other_pool.id}
        for id_field in fields:
            address = self.dbapi.address_get_by_address(str(ip_address))
            values['name'] = id_field
            self.dbapi.address_update(address.id, values)
            ip_address += 1
            updates[id_field] = address.id
            addresses[id_field] = address

        gateway_address = self.dbapi.address_get_by_address(str(subnet[1]))
        values['name'] = 'gateway_address'
        self.dbapi.address_update(gateway_address.id, values)

        self.dbapi.address_pool_update(other_pool.uuid, updates)
        self.dbapi.address_pool_update(mgmt_pool.uuid, {'gateway_address_id': gateway_address.id})

        ndict = self.get_post_object(constants.NETWORK_TYPE_MGMT, mgmt_pool.uuid)
        response = self.post_json(self.API_PREFIX, ndict, headers=self.API_HEADERS)
        self.assertEqual('application/json', response.content_type)
        self.assertEqual(response.status_code, http_client.OK)

        gateway_address = self.dbapi.address_get(gateway_address.id)
        floating_address = self.dbapi.address_get(addresses['floating_address_id'].id)
        c0_address = self.dbapi.address_get(addresses['controller0_address_id'].id)
        c1_address = self.dbapi.address_get(addresses['controller1_address_id'].id)

        self.assertEqual(mgmt_pool.uuid, floating_address.pool_uuid)
        self.assertEqual(mgmt_pool.uuid, c0_address.pool_uuid)
        self.assertEqual(mgmt_pool.uuid, c1_address.pool_uuid)

        self.assertEqual('controller-gateway-mgmt', gateway_address.name)
        self.assertEqual('controller-mgmt', floating_address.name)
        self.assertEqual('controller-0-mgmt', c0_address.name)
        self.assertEqual('controller-1-mgmt', c1_address.name)


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
        self._test_delete_after_initial_config_allowed(
            constants.NETWORK_TYPE_ADMIN)

    def test_delete_data(self):
        self._test_delete_allowed(constants.NETWORK_TYPE_DATA)

    def test_delete_data_after_initial_config(self):
        self._test_delete_after_initial_config_allowed(
            constants.NETWORK_TYPE_DATA
        )

    def test_delete_admin_dual_stack(self):
        p = mock.patch('sysinv.conductor.rpcapi.ConductorAPI.update_admin_config')
        self.mock_rpcapi_update_admin_config = p.start()
        self.addCleanup(p.stop)

        p = mock.patch('sysinv.api.controllers.v1.utils.get_distributed_cloud_role')
        self.mock_get_distributed_cloud_role = p.start()
        self.mock_get_distributed_cloud_role.return_value =\
            constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD
        self.addCleanup(p.stop)

        mgmt_network = self._create_test_network(
            name=constants.NETWORK_TYPE_MGMT,
            network_type=constants.NETWORK_TYPE_MGMT,
            subnets=[dbbase.MGMT_SUBNET_IPV4, dbbase.MGMT_SUBNET_IPV6],
            link_addresses=True)
        mgmt_pools = self._find_network_address_pools(mgmt_network.id)

        self._create_test_static_ips_for_subnet(constants.NETWORK_TYPE_ADMIN,
                                                dbbase.ADMIN_SUBNET_IPV6)
        admin_network = self._create_test_network(
            name=constants.NETWORK_TYPE_ADMIN,
            network_type=constants.NETWORK_TYPE_ADMIN,
            subnets=[dbbase.ADMIN_SUBNET_IPV4, dbbase.ADMIN_SUBNET_IPV6],
            link_addresses=True)
        admin_pools = self._find_network_address_pools(admin_network.id)
        admin_nw_pools = self.dbapi.network_addrpool_get_by_network_id(admin_network.id)

        self._create_test_network(
            name=constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
            network_type=constants.NETWORK_TYPE_SYSTEM_CONTROLLER,
            subnets=[dbbase.SYSTEM_CONTROLLER_SUBNET_IPV4, dbbase.SYSTEM_CONTROLLER_SUBNET_IPV6])

        controller0 = self._create_test_host(constants.CONTROLLER, unit=0)
        c0_mgmt0 = self.create_test_interface('c0_mgm0', controller0)
        c0_admin0 = self.create_test_interface('c0_admin0', controller0)

        controller1 = self._create_test_host(constants.CONTROLLER, unit=1)
        c1_mgmt0 = self.create_test_interface('c1_mgm0', controller1)
        c1_admin0 = self.create_test_interface('c1_admin0', controller1)

        mgmt_gateway = mgmt_pools[0].gateway_address
        admin_gateway = admin_pools[0].gateway_address

        admin_routes = []
        for iface in [c0_admin0, c1_admin0]:
            admin_routes.append(dbutils.create_test_route(
                interface_id=iface.id,
                family=dbbase.SYSTEM_CONTROLLER_SUBNET_IPV4.version,
                network=str(dbbase.SYSTEM_CONTROLLER_SUBNET_IPV4.ip),
                prefix=dbbase.SYSTEM_CONTROLLER_SUBNET_IPV4.prefixlen,
                gateway=admin_gateway,
                metric=1))

        dbutils.create_test_interface_network(interface_id=c0_mgmt0.id,
                                              network_id=mgmt_network.id)
        dbutils.create_test_interface_network(interface_id=c0_admin0.id,
                                              network_id=admin_network.id)
        dbutils.create_test_interface_network(interface_id=c1_mgmt0.id,
                                              network_id=mgmt_network.id)
        dbutils.create_test_interface_network(interface_id=c1_admin0.id,
                                              network_id=admin_network.id)

        for admin_pool in admin_pools:
            self.dbapi.address_update(admin_pool.controller0_address_id,
                                      {'interface_id': c0_admin0.id})
            self.dbapi.address_update(admin_pool.controller1_address_id,
                                      {'interface_id': c1_admin0.id})

        with mock.patch('sysinv.common.utils.is_initial_config_complete', lambda: True):
            response = self.delete(self.get_single_url(admin_network.uuid),
                                   headers=self.API_HEADERS)
            self.assertEqual(response.status_code, http_client.NO_CONTENT)

        for net_pool in admin_nw_pools:
            self.assertRaises(exception.NetworkAddrpoolNotFound,
                              self.dbapi.network_addrpool_get, net_pool.uuid)

        self.assertRaises(exception.NetworkNotFound, self.dbapi.network_get, admin_network.id)

        for route in admin_routes:
            self.assertRaises(exception.RouteNotFound, self.dbapi.route_get, route.uuid)

        for iface in [c0_mgmt0, c1_mgmt0]:
            new_route = self.dbapi.routes_get_by_interface(c0_mgmt0.id)[0]
            self.assertEqual(mgmt_gateway, new_route.gateway)

        for admin_pool in admin_pools:
            for field in ['controller0_address_id', 'controller1_address_id']:
                address = self.dbapi.address_get(getattr(admin_pool, field))
                self.assertIsNone(address.interface_id)

        self.mock_rpcapi_update_admin_config.assert_called()
        self.assertEqual(2, self.mock_rpcapi_update_admin_config.call_count)
        for call in self.mock_rpcapi_update_admin_config.call_args_list:
            self.assertEqual(True, call.args[2])


class TestDeleteAIOSimplex(NetworkTestCase):
    """ Tests AIO Simplex deletion.
        Typically delete APIs return NO CONTENT.
        python2 and python3 libraries may return different
        content_type (None, or empty json) when NO_CONTENT returned.
    """
    system_type = constants.TIS_AIO_BUILD
    system_mode = constants.SYSTEM_MODE_SIMPLEX

    def setUp(self):
        super(TestDeleteAIOSimplex, self).setUp()

    def _setup_context(self, host_locked=False):
        if host_locked:
            admin = constants.ADMIN_LOCKED
        else:
            admin = constants.ADMIN_UNLOCKED

        self.host = self._create_test_host(constants.CONTROLLER, constants.WORKER,
                            administrative=admin,
                            operational=constants.OPERATIONAL_ENABLED,
                            availability=constants.AVAILABILITY_AVAILABLE,
                            invprovision=constants.PROVISIONED,
                            vim_progress_status=constants.VIM_SERVICES_ENABLED)

        self._create_test_host_cpus(self.host, platform=2, vswitch=2, application=11)

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

    def _test_delete_mgmt_after_initial_config_not_allowed(self, network_type):
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
            expected_error = ("Cannot delete type %s network %s because Host "
                              "controller-0 is in administrative state = unlocked" %
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

    def test_delete_management(self):

        self._test_delete_allowed(constants.NETWORK_TYPE_MGMT)

    def test_delete_management_after_initial_config_not_allowed_host_unlocked(self):
        self._setup_context(host_locked=False)

        self._test_delete_mgmt_after_initial_config_not_allowed(
            constants.NETWORK_TYPE_MGMT
        )

    def test_delete_management_after_initial_config_allowed_host_locked(self):
        self._setup_context(host_locked=True)

        self._test_delete_after_initial_config_allowed(
            constants.NETWORK_TYPE_MGMT
        )

    # just to make sure that the other networks can't be deleted
    def test_delete_oam(self):
        self._setup_context(host_locked=False)

        self._test_delete_allowed(constants.NETWORK_TYPE_OAM)

    def test_delete_oam_after_initial_config(self):
        self._setup_context(host_locked=False)

        self._test_delete_after_initial_config_not_allowed(
            constants.NETWORK_TYPE_OAM
        )

    def test_delete_data(self):
        self._setup_context(host_locked=False)

        self._test_delete_allowed(constants.NETWORK_TYPE_DATA)

    def test_delete_data_after_initial_config(self):
        self._setup_context(host_locked=False)

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
