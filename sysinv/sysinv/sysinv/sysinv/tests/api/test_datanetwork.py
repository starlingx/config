# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the DataNetwork API controller validation logic.
Exercises _check_datanetwork and its sub-checks:
  - _check_network_type
  - _check_datanetwork_name
  - _check_new_datanetwork_mtu_or_set_default
  - _check_datanetwork_vxlan
"""

from six.moves import http_client

from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils


class TestDataNetworkValidation(base.FunctionalTest):
    """Tests for POST /datanetworks validation."""

    def setUp(self):
        super(TestDataNetworkValidation, self).setUp()
        self.system = dbutils.create_test_isystem()

    def _get_path(self, path=None):
        if path:
            return '/datanetworks/' + path
        return '/datanetworks'

    def _post_datanetwork(self, data, expect_errors=False):
        return self.post_json(self._get_path(), data,
                              expect_errors=expect_errors)

    # ---------------------------------------------------------------
    # _check_network_type tests
    # ---------------------------------------------------------------
    def test_create_flat_success(self):
        data = {'name': 'dn-flat-0',
                'network_type': constants.DATANETWORK_TYPE_FLAT}
        response = self._post_datanetwork(data)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual('dn-flat-0', response.json['name'])
        self.assertEqual(constants.DATANETWORK_TYPE_FLAT,
                         response.json['network_type'])
        # Default MTU should be applied
        self.assertEqual(constants.DEFAULT_MTU, response.json['mtu'])

    def test_create_vlan_success(self):
        data = {'name': 'dn-vlan-0',
                'network_type': constants.DATANETWORK_TYPE_VLAN}
        response = self._post_datanetwork(data)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.DATANETWORK_TYPE_VLAN,
                         response.json['network_type'])

    def test_create_invalid_network_type(self):
        data = {'name': 'dn-bad',
                'network_type': 'invalid-type'}
        response = self._post_datanetwork(data, expect_errors=True)
        self.assertEqual(http_client.INTERNAL_SERVER_ERROR,
                         response.status_int)
        self.assertIn('not supported', response.json['error_message'])

    def test_create_missing_network_type(self):
        data = {'name': 'dn-notype'}
        response = self._post_datanetwork(data, expect_errors=True)
        self.assertEqual(http_client.INTERNAL_SERVER_ERROR,
                         response.status_int)
        self.assertIn('not supported', response.json['error_message'])

    # ---------------------------------------------------------------
    # _check_datanetwork_name tests
    # ---------------------------------------------------------------
    def test_create_missing_name(self):

        data = {'network_type': constants.DATANETWORK_TYPE_FLAT}
        response = self._post_datanetwork(data, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)

    def test_create_name_none_reserved(self):

        data = {'name': 'none',
                'network_type': constants.DATANETWORK_TYPE_FLAT}
        response = self._post_datanetwork(data, expect_errors=True)
        self.assertEqual(http_client.INTERNAL_SERVER_ERROR,
                         response.status_int)
        self.assertIn('not allowed', response.json['error_message'])

    def test_create_name_with_invalid_chars(self):

        data = {'name': 'dn bad name',
                'network_type': constants.DATANETWORK_TYPE_FLAT}
        response = self._post_datanetwork(data, expect_errors=True)
        self.assertEqual(http_client.INTERNAL_SERVER_ERROR,
                         response.status_int)

        data = {'name': 'dn_bad_name?',
                'network_type': constants.DATANETWORK_TYPE_FLAT}
        response = self._post_datanetwork(data, expect_errors=True)
        self.assertEqual(http_client.INTERNAL_SERVER_ERROR,
                         response.status_int)

        data = {'name': 'dn_bad_name_ç',
                'network_type': constants.DATANETWORK_TYPE_FLAT}
        response = self._post_datanetwork(data, expect_errors=True)
        self.assertEqual(http_client.INTERNAL_SERVER_ERROR,
                         response.status_int)

        data = {'name': 'dn_bad_name_é',
                'network_type': constants.DATANETWORK_TYPE_FLAT}
        response = self._post_datanetwork(data, expect_errors=True)
        self.assertEqual(http_client.INTERNAL_SERVER_ERROR,
                         response.status_int)
        self.assertIn('not allowed', response.json['error_message'])

    def test_create_name_valid_special_chars(self):
        """Names with underscores, periods, and hyphens are allowed."""

        data = {'name': 'dn_test-0.net',
                'network_type': constants.DATANETWORK_TYPE_FLAT}
        response = self._post_datanetwork(data)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual('dn_test-0.net', response.json['name'])

    # ---------------------------------------------------------------
    # _check_new_datanetwork_mtu_or_set_default tests
    # ---------------------------------------------------------------
    def test_create_with_custom_mtu(self):
        data = {'name': 'dn-mtu',
                'network_type': constants.DATANETWORK_TYPE_FLAT,
                'mtu': 9000}
        response = self._post_datanetwork(data)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(9000, response.json['mtu'])

    def test_create_mtu_too_small(self):

        data = {'name': 'dn-mtu-small',
                'network_type': constants.DATANETWORK_TYPE_FLAT,
                'mtu': 100}
        response = self._post_datanetwork(data, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)

    def test_create_mtu_too_large(self):

        data = {'name': 'dn-mtu-large',
                'network_type': constants.DATANETWORK_TYPE_FLAT,
                'mtu': 99999}
        response = self._post_datanetwork(data, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)

    # ---------------------------------------------------------------
    # _check_datanetwork_vxlan tests
    # ---------------------------------------------------------------
    def test_create_vxlan_dynamic_success(self):
        data = {'name': 'dn-vxlan-0',
                'network_type': constants.DATANETWORK_TYPE_VXLAN,
                'multicast_group': '239.0.2.1',
                'port_num': 4789,
                'ttl': 1,
                'mode': constants.DATANETWORK_MODE_DYNAMIC}
        response = self._post_datanetwork(data)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual('239.0.2.1', response.json['multicast_group'])
        self.assertEqual(4789, response.json['port_num'])
        self.assertEqual(1, response.json['ttl'])
        self.assertEqual(constants.DATANETWORK_MODE_DYNAMIC,
                         response.json['mode'])

    def test_create_vxlan_static_success(self):
        data = {'name': 'dn-vxlan-static',
                'network_type': constants.DATANETWORK_TYPE_VXLAN,
                'port_num': 4789,
                'ttl': 3,
                'mode': constants.DATANETWORK_MODE_STATIC}
        response = self._post_datanetwork(data)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.DATANETWORK_MODE_STATIC,
                         response.json['mode'])

    def test_create_vxlan_dynamic_missing_multicast(self):
        """Dynamic mode requires multicast_group."""

        data = {'name': 'dn-vxlan-nomc',
                'network_type': constants.DATANETWORK_TYPE_VXLAN,
                'port_num': 4789,
                'ttl': 1,
                'mode': constants.DATANETWORK_MODE_DYNAMIC}
        response = self._post_datanetwork(data, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)

    def test_create_vxlan_dynamic_invalid_multicast(self):
        """Dynamic mode requires a valid multicast address."""

        data = {'name': 'dn-vxlan-badmc',
                'network_type': constants.DATANETWORK_TYPE_VXLAN,
                'multicast_group': '10.10.10.1',  # Not multicast
                'port_num': 4789,
                'ttl': 1,
                'mode': constants.DATANETWORK_MODE_DYNAMIC}
        response = self._post_datanetwork(data, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)

    def test_create_vxlan_static_with_multicast_rejected(self):
        """Static mode does not support multicast_group."""

        data = {'name': 'dn-vxlan-static-mc',
                'network_type': constants.DATANETWORK_TYPE_VXLAN,
                'multicast_group': '239.0.2.1',
                'port_num': 4789,
                'ttl': 1,
                'mode': constants.DATANETWORK_MODE_STATIC}
        response = self._post_datanetwork(data, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)

    def test_create_vxlan_missing_required_params(self):
        """VxLAN without port_num and ttl should fail."""

        data = {'name': 'dn-vxlan-missing',
                'network_type': constants.DATANETWORK_TYPE_VXLAN,
                'multicast_group': '239.0.2.1',
                'mode': constants.DATANETWORK_MODE_DYNAMIC}
        response = self._post_datanetwork(data, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
