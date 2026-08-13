#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for drbdconfig and datanetwork API controllers."""

from six.moves import http_client

from sysinv.common import constants
from sysinv.tests.api import base
from sysinv.tests.db import base as dbbase


class DatanetworkTestCase(base.FunctionalTest,
                          dbbase.BaseSystemTestCase
                          ):

    def setUp(self):
        super(DatanetworkTestCase, self).setUp()

    def test_create_flat_datanetwork(self):
        ndict = {'name': 'test-dn',
                 'network_type': constants.DATANETWORK_TYPE_FLAT}
        response = self.post_json('/datanetworks', ndict,
                                  headers={'User-Agent': 'sysinv-test'})
        self.assertEqual(response.status_code, http_client.OK)
        self.assertEqual(response.json['name'], 'test-dn')

    def test_create_vlan_datanetwork(self):
        ndict = {'name': 'test-vlan',
                 'network_type': constants.DATANETWORK_TYPE_VLAN}
        response = self.post_json('/datanetworks', ndict,
                                  headers={'User-Agent': 'sysinv-test'})
        self.assertEqual(response.status_code, http_client.OK)

    def test_create_vxlan_datanetwork(self):
        ndict = {'name': 'test-vxlan',
                 'network_type': constants.DATANETWORK_TYPE_VXLAN,
                 'multicast_group': '239.0.0.1',
                 'port_num': 4789,
                 'ttl': 1,
                 'mode': 'dynamic'}
        response = self.post_json('/datanetworks', ndict,
                                  headers={'User-Agent': 'sysinv-test'})
        self.assertEqual(response.status_code, http_client.OK)

    def test_delete_datanetwork(self):
        ndict = {'name': 'test-del',
                 'network_type': constants.DATANETWORK_TYPE_FLAT}
        response = self.post_json('/datanetworks', ndict,
                                  headers={'User-Agent': 'sysinv-test'})
        uuid = response.json['uuid']
        self.delete('/datanetworks/%s' % uuid,
                    headers={'User-Agent': 'sysinv-test'})

    def test_create_duplicate_name_fails(self):
        ndict = {'name': 'dup-dn',
                 'network_type': constants.DATANETWORK_TYPE_FLAT}
        self.post_json('/datanetworks', ndict,
                       headers={'User-Agent': 'sysinv-test'})
        response = self.post_json('/datanetworks', ndict,
                                  headers={'User-Agent': 'sysinv-test'},
                                  expect_errors=True)
        self.assertEqual(response.status_code, http_client.CONFLICT)
