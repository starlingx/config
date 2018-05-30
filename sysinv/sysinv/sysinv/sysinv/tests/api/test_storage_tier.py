# vim: tabstop=4 shiftwidth=4 softtabstop=4
# -*- encoding: utf-8 -*-
#
#
# Copyright (c) 2017-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the API /storage_tiers/ methods.
"""

import mock
from six.moves import http_client

from cephclient import wrapper as ceph
from contextlib import nested
from oslo_serialization import jsonutils
from sysinv.conductor import manager
from sysinv.conductor import rpcapi
from sysinv.common import ceph as ceph_utils
from sysinv.common import constants
from sysinv.common.storage_backend_conf import StorageBackendConfig
from sysinv.db import api as dbapi
from sysinv.openstack.common import context
from sysinv.openstack.common import uuidutils
from sysinv.tests.api import base
from sysinv.tests.db import utils as dbutils


class StorageTierIndependentTCs(base.FunctionalTest):

    def setUp(self):
        super(StorageTierIndependentTCs, self).setUp()
        self.system = dbutils.create_test_isystem()
        self.cluster = dbutils.create_test_cluster(system_id=self.system.id, name='ceph_cluster')
        self.load = dbutils.create_test_load()
        self.host = dbutils.create_test_ihost(forisystemid=self.system.id)

    def assertDeleted(self, fullPath):
        self.get_json(fullPath, expect_errors=True)  # Make sure this line raises an error

    #
    # StorageTier API:
    #

    def test_tier_post_empty(self):
        values = {}

        response = self.post_json('/storage_tiers', values, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('No cluster information was provided for tier creation.',
                      response.json['error_message'])

    def test_tier_post_name_without_default(self):
        values = {'cluster_uuid': self.cluster.uuid,
                  'name': 'gold'}

        response = self.post_json('/storage_tiers', values, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Default system storage tier (%s) must be present '
                      'before adding additional tiers.' %
                      constants.SB_TIER_DEFAULT_NAMES[constants.SB_TIER_TYPE_CEPH],
                      response.json['error_message'])

    def test_tier_post_no_name(self):
        values = {'cluster_uuid': self.cluster.uuid}

        response = self.post_json('/storage_tiers', values, expect_errors=True)
        self.assertEqual(http_client.OK, response.status_int)

        confirm = self.get_json('/storage_tiers/%s/' % response.json['uuid'])
        self.assertEqual(confirm['uuid'], response.json['uuid'])
        self.assertEqual(confirm['name'], constants.SB_TIER_DEFAULT_NAMES[constants.SB_TIER_TYPE_CEPH])
        self.assertEqual(confirm['type'], constants.SB_TIER_TYPE_CEPH)
        self.assertEqual(confirm['status'], constants.SB_TIER_STATUS_DEFINED)
        self.assertEqual(confirm['backend_uuid'], None)
        self.assertEqual(confirm['cluster_uuid'], self.cluster.uuid)
        self.assertEqual(confirm['stors'], [])
        self.assertEqual(confirm['capabilities'], {})

    def test_tier_post_no_name_again(self):
        self.test_tier_post_no_name()

        values = {'cluster_uuid': self.cluster.uuid}

        response = self.post_json('/storage_tiers', values, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Storage tier (%s) already present' %
                      constants.SB_TIER_DEFAULT_NAMES[constants.SB_TIER_TYPE_CEPH],
                      response.json['error_message'])

    def test_tier_post_no_name_and_second(self):
        self.test_tier_post_no_name()

        values = {'cluster_uuid': self.cluster.uuid,
                  'name': 'gold'}

        with mock.patch.object(ceph_utils.CephApiOperator, 'crushmap_tiers_add') as mock_tiers_add:
            response = self.post_json('/storage_tiers', values, expect_errors=True)
        self.assertEqual(http_client.OK, response.status_int)

        confirm = self.get_json('/storage_tiers/%s/' % response.json['uuid'])
        self.assertEqual(confirm['uuid'], response.json['uuid'])
        self.assertEqual(confirm['name'], 'gold')
        self.assertEqual(confirm['type'], constants.SB_TIER_TYPE_CEPH)
        self.assertEqual(confirm['status'], constants.SB_TIER_STATUS_DEFINED)
        self.assertEqual(confirm['backend_uuid'], None)
        self.assertEqual(confirm['cluster_uuid'], self.cluster.uuid)
        self.assertEqual(confirm['stors'], [])
        self.assertEqual(confirm['capabilities'], {})

    def test_tier_post_no_name_and_second_again(self):
        self.test_tier_post_no_name_and_second()

        values = {'cluster_uuid': self.cluster.uuid,
                  'name': 'gold'}

        response = self.post_json('/storage_tiers', values, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Storage tier (gold) already present',
                      response.json['error_message'])

    def test_tier_get_one_and_all(self):
        self.test_tier_post_no_name_and_second()

        values = {'cluster_uuid': self.cluster.uuid,
                  'name': 'platinum'}

        with mock.patch.object(ceph_utils.CephApiOperator, 'crushmap_tiers_add') as mock_tiers_add:
            response = self.post_json('/storage_tiers', values, expect_errors=True)
        self.assertEqual(http_client.OK, response.status_int)

        confirm = self.get_json('/storage_tiers/%s' % response.json['uuid'])
        self.assertEqual(confirm['uuid'], response.json['uuid'])
        self.assertEqual(confirm['name'], 'platinum')
        self.assertEqual(confirm['type'], constants.SB_TIER_TYPE_CEPH)
        self.assertEqual(confirm['status'], constants.SB_TIER_STATUS_DEFINED)
        self.assertEqual(confirm['backend_uuid'], None)
        self.assertEqual(confirm['cluster_uuid'], self.cluster.uuid)
        self.assertEqual(confirm['stors'], [])
        self.assertEqual(confirm['capabilities'], {})

        tier_list = self.get_json('/storage_tiers')
        self.assertIn('platinum', [t['name'] for t in tier_list['storage_tiers']])
        self.assertIn('gold', [t['name'] for t in tier_list['storage_tiers']])
        self.assertIn(constants.SB_TIER_DEFAULT_NAMES[constants.SB_TIER_TYPE_CEPH],
                      [t['name'] for t in tier_list['storage_tiers']])

        tier_list = self.get_json('/clusters/%s/storage_tiers' % confirm['cluster_uuid'])
        self.assertIn('platinum', [t['name'] for t in tier_list['storage_tiers']])
        self.assertIn('gold', [t['name'] for t in tier_list['storage_tiers']])
        self.assertIn(constants.SB_TIER_DEFAULT_NAMES[constants.SB_TIER_TYPE_CEPH],
                      [t['name'] for t in tier_list['storage_tiers']])

    def test_tier_detail(self):
        values = {'cluster_uuid': self.cluster.uuid}

        response = self.post_json('/storage_tiers', values, expect_errors=True)
        self.assertEqual(http_client.OK, response.status_int)

        confirm = self.get_json('/storage_tiers/%s/' % response.json['uuid'])
        self.assertEqual(confirm['uuid'], response.json['uuid'])
        self.assertEqual(confirm['name'], constants.SB_TIER_DEFAULT_NAMES[constants.SB_TIER_TYPE_CEPH])
        self.assertEqual(confirm['type'], constants.SB_TIER_TYPE_CEPH)
        self.assertEqual(confirm['status'], constants.SB_TIER_STATUS_DEFINED)
        self.assertEqual(confirm['backend_uuid'], None)
        self.assertEqual(confirm['cluster_uuid'], self.cluster.uuid)
        self.assertEqual(confirm['stors'], [])
        self.assertEqual(confirm['capabilities'], {})

        response = self.get_json('/storage_tiers/%s/detail' % confirm['uuid'], expect_errors=True)
        self.assertEqual(http_client.NOT_FOUND, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Resource could not be found.', response.json['error_message'])

        tier_list = self.get_json('/storage_tiers/detail')
        self.assertIn(constants.SB_TIER_DEFAULT_NAMES[constants.SB_TIER_TYPE_CEPH],
                      [t['name'] for t in tier_list['storage_tiers']])

    def test_tier_patch(self):
        values = {'cluster_uuid': self.cluster.uuid}

        response = self.post_json('/storage_tiers', values, expect_errors=True)
        self.assertEqual(http_client.OK, response.status_int)

        confirm = self.get_json('/storage_tiers/%s/' % response.json['uuid'])
        self.assertEqual(confirm['uuid'], response.json['uuid'])
        self.assertEqual(confirm['name'], constants.SB_TIER_DEFAULT_NAMES[constants.SB_TIER_TYPE_CEPH])
        self.assertEqual(confirm['type'], constants.SB_TIER_TYPE_CEPH)
        self.assertEqual(confirm['status'], constants.SB_TIER_STATUS_DEFINED)
        self.assertEqual(confirm['backend_uuid'], None)
        self.assertEqual(confirm['cluster_uuid'], self.cluster.uuid)
        self.assertEqual(confirm['stors'], [])
        self.assertEqual(confirm['capabilities'], {})

        # Default: uuid
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              uuid=uuidutils.generate_uuid(),
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('\'/uuid\' is an internal attribute and can not be updated"',
                      patch_response.json['error_message'])

        # Default: name
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              name='newname',
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Storage Tier %s cannot be renamed.' %
                      constants.SB_TIER_DEFAULT_NAMES[constants.SB_TIER_TYPE_CEPH],
                      patch_response.json['error_message'])

        # Default: type
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              type='lvm',
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn("Cannot modify 'type' with this operation.",
                      patch_response.json['error_message'])

        # Default: status
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              status=constants.SB_TIER_STATUS_IN_USE,
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn("Cannot modify 'status' with this operation.",
                      patch_response.json['error_message'])

        # Default: capabilities
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              capabilities=jsonutils.dumps({'test_param': 'foo'}),
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('The capabilities of storage tier %s cannot be changed.' %
                      constants.SB_TIER_DEFAULT_NAMES[constants.SB_TIER_TYPE_CEPH],
                      patch_response.json['error_message'])

        # Default: backend_uuid
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              backend_uuid=uuidutils.generate_uuid(),
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('No entry found for storage backend',
                      patch_response.json['error_message'])

        # Default: cluster_uuid
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              cluster_uuid=uuidutils.generate_uuid(),
                                              expect_errors=True)
        self.assertEqual(http_client.NOT_FOUND, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])

        values = {'cluster_uuid': self.cluster.uuid,
                  'name': 'gold'}

        with mock.patch.object(ceph_utils.CephApiOperator, 'crushmap_tiers_add') as mock_tiers_add:
            response = self.post_json('/storage_tiers', values, expect_errors=True)
        self.assertEqual(http_client.OK, response.status_int)

        confirm = self.get_json('/storage_tiers/%s/' % response.json['uuid'])
        self.assertEqual(confirm['uuid'], response.json['uuid'])
        self.assertEqual(confirm['name'], 'gold')
        self.assertEqual(confirm['type'], constants.SB_TIER_TYPE_CEPH)
        self.assertEqual(confirm['status'], constants.SB_TIER_STATUS_DEFINED)
        self.assertEqual(confirm['backend_uuid'], None)
        self.assertEqual(confirm['cluster_uuid'], self.cluster.uuid)
        self.assertEqual(confirm['stors'], [])
        self.assertEqual(confirm['capabilities'], {})

        # Other Defined: uuid
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              uuid=uuidutils.generate_uuid(),
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('\'/uuid\' is an internal attribute and can not be updated"',
                      patch_response.json['error_message'])

        # Other Defined: name
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              name='newname',
                                              expect_errors=True)
        self.assertEqual(http_client.OK, patch_response.status_int)
        self.assertEqual('newname',  # Expected
                         self.get_json('/storage_tiers/%s/' % patch_response.json['uuid'])['name'])  # Result

        # Other Defined: type
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              type='lvm',
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn("Cannot modify 'type' with this operation.",
                      patch_response.json['error_message'])

        # Other Defined: status
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              status=constants.SB_TIER_STATUS_IN_USE,
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn("Cannot modify 'status' with this operation.",
                      patch_response.json['error_message'])

        # Other Defined: capabilities
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              capabilities=jsonutils.dumps({'test_param': 'foo'}),
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('The capabilities of storage tier newname cannot be changed.',
                      patch_response.json['error_message'])

        # Other Defined: backend_uuid
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              backend_uuid=uuidutils.generate_uuid(),
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('No entry found for storage backend',
                      patch_response.json['error_message'])

        # Other Defined: cluster_uuid
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              cluster_uuid=uuidutils.generate_uuid(),
                                              expect_errors=True)
        self.assertEqual(http_client.NOT_FOUND, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])

        values = {'cluster_uuid': self.cluster.uuid,
                  'name': 'platinum',
                  'status': constants.SB_TIER_STATUS_IN_USE}

        with mock.patch.object(ceph_utils.CephApiOperator, 'crushmap_tiers_add') as mock_tiers_add:
            response = self.post_json('/storage_tiers', values, expect_errors=True)
        self.assertEqual(http_client.OK, response.status_int)

        confirm = self.get_json('/storage_tiers/%s/' % response.json['uuid'])
        self.assertEqual(confirm['uuid'], response.json['uuid'])
        self.assertEqual(confirm['name'], 'platinum')
        self.assertEqual(confirm['type'], constants.SB_TIER_TYPE_CEPH)
        self.assertEqual(confirm['status'], constants.SB_TIER_STATUS_IN_USE)
        self.assertEqual(confirm['backend_uuid'], None)
        self.assertEqual(confirm['cluster_uuid'], self.cluster.uuid)
        self.assertEqual(confirm['stors'], [])
        self.assertEqual(confirm['capabilities'], {})

        # Other In-Use: uuid
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              uuid=uuidutils.generate_uuid(),
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('\'/uuid\' is an internal attribute and can not be updated"',
                      patch_response.json['error_message'])

        # Other In-Use: name
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              name='newname',
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('Storage Tier platinum cannot be renamed. It is in-use',
                      patch_response.json['error_message'])

        # Other In-Use: type
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              type='lvm',
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn("Cannot modify 'type' with this operation.",
                      patch_response.json['error_message'])

        # Other In-Use: status
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              status=constants.SB_TIER_STATUS_DEFINED,
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn("Cannot modify 'status' with this operation.",
                      patch_response.json['error_message'])

        # Other In-Use: capabilities
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              capabilities=jsonutils.dumps({'test_param': 'foo'}),
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('The capabilities of storage tier platinum cannot be changed.',
                      patch_response.json['error_message'])

        # Other In-Use: backend_uuid
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              backend_uuid=uuidutils.generate_uuid(),
                                              expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])
        self.assertIn('No entry found for storage backend',
                      patch_response.json['error_message'])

        # Other In-Use: cluster_uuid
        patch_response = self.patch_dict_json('/storage_tiers/%s' % confirm['uuid'],
                                              headers={'User-Agent': 'sysinv'},
                                              cluster_uuid=uuidutils.generate_uuid(),
                                              expect_errors=True)
        self.assertEqual(http_client.NOT_FOUND, patch_response.status_int)
        self.assertEqual('application/json', patch_response.content_type)
        self.assertTrue(patch_response.json['error_message'])

    def test_tier_delete(self):
        self.test_tier_post_no_name_and_second()

        values = {'cluster_uuid': self.cluster.uuid,
                  'name': 'platinum',
                  'status': constants.SB_TIER_STATUS_IN_USE}

        with mock.patch.object(ceph_utils.CephApiOperator, 'crushmap_tiers_add') as mock_tiers_add:
            response = self.post_json('/storage_tiers', values, expect_errors=True)
        self.assertEqual(http_client.OK, response.status_int)

        tier_list = self.get_json('/storage_tiers')
        uuid_map = {}
        for tier in tier_list['storage_tiers']:
            uuid_map.update({tier['name']: tier['uuid']})

        response = self.delete('/storage_tiers/%s' % uuid_map[
            constants.SB_TIER_DEFAULT_NAMES[constants.SB_TIER_TYPE_CEPH]],
                               expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Storage Tier %s cannot be deleted.' %
                      constants.SB_TIER_DEFAULT_NAMES[constants.SB_TIER_TYPE_CEPH],
                      response.json['error_message'])

        response = self.delete('/storage_tiers/%s' % uuid_map['platinum'], expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Storage Tier platinum cannot be deleted. It is in-use',
                      response.json['error_message'])

        with mock.patch.object(ceph_utils.CephApiOperator, 'crushmap_tier_delete') as mock_tier_delete:
            response = self.delete('/storage_tiers/%s' % uuid_map['gold'], expect_errors=False)
        self.assertEqual(http_client.NO_CONTENT, response.status_int)

        tier_list = self.get_json('/storage_tiers')
        tier_names = [t['name'] for t in tier_list['storage_tiers']]
        self.assertEqual([constants.SB_TIER_DEFAULT_NAMES[constants.SB_TIER_TYPE_CEPH],
                          'platinum'],
                         tier_names)
        self.assertEquals(2, len(tier_list['storage_tiers']))


class StorageTierDependentTCs(base.FunctionalTest):

    def setUp(self):
        super(StorageTierDependentTCs, self).setUp()
        self.service = manager.ConductorManager('test-host', 'test-topic')
        self.service.dbapi = dbapi.get_instance()
        self.context = context.get_admin_context()
        self.dbapi = dbapi.get_instance()
        self.system = dbutils.create_test_isystem()
        self.load = dbutils.create_test_load()
        self.host_index = -1

    def assertDeleted(self, fullPath):
        self.get_json(fullPath, expect_errors=True)  # Make sure this line raises an error

    def _create_storage_ihost(self, hostname, pers_subtype=constants.PERSONALITY_SUBTYPE_CEPH_BACKING):
        self.host_index += 1
        ihost_dict = dbutils.get_test_ihost(
            id=self.host_index,
            forisystemid=self.system.id,
            hostname=hostname,
            uuid=uuidutils.generate_uuid(),
            mgmt_mac="{}-{}".format(hostname, self.host_index),
            mgmt_ip="{}-{}".format(hostname, self.host_index),
            personality='storage',
            administrative='locked',
            operational='disabled',
            availability='online',
            invprovision='unprovisioned',
            capabilities={
                'pers_subtype': pers_subtype,
            })
        return self.dbapi.ihost_create(ihost_dict)

    #
    # StorageTier with stors
    #

    def test_cluster_tier_host_osd(self):
        storage_0 = self._create_storage_ihost('storage-0', pers_subtype=constants.PERSONALITY_SUBTYPE_CEPH_BACKING)
        disk_0 = dbutils.create_test_idisk(device_node='/dev/sda',
                                           device_path='/dev/disk/by-path/pci-0000:00:0d.0-ata-1.0',
                                           forihostid=storage_0.id)
        disk_1 = dbutils.create_test_idisk(device_node='/dev/sdb',
                                           device_path='/dev/disk/by-path/pci-0000:00:0d.0-ata-2.0',
                                           forihostid=storage_0.id)

        # Mock the fsid call so that we don't have to wait for the timeout
        with mock.patch.object(ceph.CephWrapper, 'fsid') as mock_fsid:
            mock_fsid.return_value = (mock.MagicMock(ok=False), None)
            self.service.start()
            mock_fsid.assert_called()
        self.assertIsNone(self.service._ceph.cluster_ceph_uuid)
        self.assertIsNotNone(self.service._ceph.cluster_db_uuid)

        # Make sure default storage tier is present
        tier_list = self.get_json('/storage_tiers', expect_errors=False)
        self.assertEqual(constants.SB_TIER_DEFAULT_NAMES[
            constants.SB_TIER_TYPE_CEPH],
                         tier_list['storage_tiers'][0]['name'])
        self.assertEqual(constants.SB_TIER_STATUS_DEFINED,
                         tier_list['storage_tiers'][0]['status'])

        # save the current values
        saved_cluster_db_uuid = self.service._ceph.cluster_db_uuid

        # Add host
        cluster_uuid = uuidutils.generate_uuid()
        with mock.patch.object(ceph.CephWrapper, 'fsid') as mock_fsid:
            mock_fsid.return_value = (mock.MagicMock(ok=True), cluster_uuid)
            self.service._ceph.update_ceph_cluster(storage_0)
        self.assertIsNotNone(self.service._ceph.cluster_ceph_uuid)
        self.assertIsNotNone(self.service._ceph.cluster_db_uuid)
        self.assertEqual(saved_cluster_db_uuid, self.service._ceph.cluster_db_uuid)
        # self.assertEqual(self.service._ceph._cluster_ceph_uuid, self.service._ceph._cluster_db_uuid)

        # make sure the host addition produces the correct peer
        ihost_0 = self.dbapi.ihost_get(storage_0.id)
        self.assertEqual(storage_0.id, ihost_0.id)
        peer = self.dbapi.peer_get(ihost_0.peer_id)
        self.assertEqual(peer.name, 'group-0')
        self.assertEqual(peer.hosts, [storage_0.hostname])

        # Add the default ceph backend
        values = {
            'backend': constants.SB_TYPE_CEPH,
            'capabilities': {'test_bparam3': 'one',
                             'test_cparam3': 'two',
                             'test_gparam3': 'three',
                             'test_sparam1': 'four'},
            'services': "%s,%s" % (constants.SB_SVC_CINDER, constants.SB_SVC_GLANCE),
            'confirmed': True
        }
        with nested(mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses'),
                    mock.patch.object(StorageBackendConfig, 'set_img_conversions_defaults')) as (
                                          mock_ceph_mon, mock_conv):
            response = self.post_json('/storage_backend', values, expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual('ceph',  # Expected
                         self.get_json('/storage_backend/%s/' % response.json['uuid'])['backend'])  # Result

        # update the DB to make sure that the backend set to be configured
        self.dbapi.storage_backend_update(response.json['uuid'], {'state': constants.SB_STATE_CONFIGURED})

        # Make sure default storage tier is in use
        tier_list = self.get_json('/storage_tiers', expect_errors=False)
        self.assertEqual(constants.SB_TIER_DEFAULT_NAMES[
            constants.SB_TIER_TYPE_CEPH],
                         tier_list['storage_tiers'][0]['name'])
        self.assertEqual(constants.SB_TIER_STATUS_IN_USE,
                         tier_list['storage_tiers'][0]['status'])
        default_tier_uuid = tier_list['storage_tiers'][0]['uuid']

        # add a stor
        values = {'ihost_uuid': storage_0.uuid,
                  'idisk_uuid': disk_0.uuid}

        with nested(mock.patch.object(ceph_utils.CephApiOperator, 'get_monitors_status'),
                    mock.patch.object(StorageBackendConfig, 'has_backend_configured'),
                    mock.patch.object(rpcapi.ConductorAPI,'configure_osd_istor')) as (
                        mock_mon_status, mock_backend_configured, mock_osd):

            def fake_configure_osd_istor(context, istor_obj):
                istor_obj['osdid'] = 0
                return istor_obj

            mock_mon_status.return_value = [3, 2, ['controller-0', 'controller-1', 'storage-0']]
            mock_osd.side_effect = fake_configure_osd_istor

            response = self.post_json('/istors', values, expect_errors=True)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(default_tier_uuid,
                         self.get_json('/istors/%s/' % response.json['uuid'])['tier_uuid'])  # Result

        # Verify the tier state is still in-use
        tier_list = self.get_json('/storage_tiers', expect_errors=False)
        self.assertEqual(constants.SB_TIER_DEFAULT_NAMES[
            constants.SB_TIER_TYPE_CEPH],
                         tier_list['storage_tiers'][0]['name'])
        self.assertEqual(constants.SB_TIER_STATUS_IN_USE,
                         tier_list['storage_tiers'][0]['status'])

        # Create a second storage tier without a cluster
        values = {}
        response = self.post_json('/storage_tiers', values, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('No cluster information was provided for tier creation.',
                      response.json['error_message'])

        # Create a second storage tier without a name
        values = {'cluster_uuid': saved_cluster_db_uuid}
        response = self.post_json('/storage_tiers', values, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Storage tier (%s) already present' % constants.SB_TIER_DEFAULT_NAMES[
            constants.SB_TIER_TYPE_CEPH],
                      response.json['error_message'])

        # Create a second storage tier
        values = {'cluster_uuid': saved_cluster_db_uuid,
                  'name': 'gold'}
        with mock.patch.object(ceph_utils.CephApiOperator, 'crushmap_tiers_add') as mock_tiers_add:
            response = self.post_json('/storage_tiers', values, expect_errors=True)
        self.assertEqual(http_client.OK, response.status_int)

        confirm = self.get_json('/storage_tiers/%s/' % response.json['uuid'])
        self.assertEqual(confirm['uuid'], response.json['uuid'])
        self.assertEqual(confirm['name'], 'gold')
        self.assertEqual(confirm['type'], constants.SB_TIER_TYPE_CEPH)
        self.assertEqual(confirm['status'], constants.SB_TIER_STATUS_DEFINED)
        self.assertEqual(confirm['backend_uuid'], None)
        self.assertEqual(confirm['cluster_uuid'], saved_cluster_db_uuid)
        self.assertEqual(confirm['stors'], [])
        self.assertEqual(confirm['capabilities'], {})
        saved_tier_uuid = response.json['uuid']

        # add a stor without specifying a tier
        values = {'ihost_uuid': storage_0.uuid,
                  'idisk_uuid': disk_1.uuid}

        with nested(mock.patch.object(ceph_utils.CephApiOperator, 'get_monitors_status'),
                    mock.patch.object(StorageBackendConfig, 'has_backend_configured'),
                    mock.patch.object(rpcapi.ConductorAPI,'configure_osd_istor')) as (
                        mock_mon_status, mock_backend_configured, mock_osd):

            def fake_configure_osd_istor(context, istor_obj):
                istor_obj['osdid'] = 1
                return istor_obj

            mock_mon_status.return_value = [3, 2, ['controller-0', 'controller-1', 'storage-0']]
            mock_osd.side_effect = fake_configure_osd_istor

            response = self.post_json('/istors', values, expect_errors=True)
        self.assertEqual(http_client.BAD_REQUEST, response.status_int)
        self.assertEqual('application/json', response.content_type)
        self.assertTrue(response.json['error_message'])
        self.assertIn('Multiple storage tiers are present. A tier is required for stor creation.',
                      response.json['error_message'])

        # add a stor without specifying a tier
        values = {'ihost_uuid': storage_0.uuid,
                  'idisk_uuid': disk_1.uuid,
                  'tier_uuid': saved_tier_uuid}

        with nested(mock.patch.object(ceph_utils.CephApiOperator, 'get_monitors_status'),
                    mock.patch.object(StorageBackendConfig, 'has_backend_configured'),
                    mock.patch.object(rpcapi.ConductorAPI,'configure_osd_istor')) as (
                        mock_mon_status, mock_backend_configured, mock_osd):

            def fake_configure_osd_istor(context, istor_obj):
                istor_obj['osdid'] = 1
                return istor_obj

            mock_mon_status.return_value = [3, 2, ['controller-0', 'controller-1', 'storage-0']]
            mock_osd.side_effect = fake_configure_osd_istor

            response = self.post_json('/istors', values, expect_errors=True)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(saved_tier_uuid,
                         self.get_json('/istors/%s/' % response.json['uuid'])['tier_uuid'])  # Result

        # Verify the tier state has changed
        tier_list = self.get_json('/storage_tiers', expect_errors=False)
        self.assertEqual('gold', tier_list['storage_tiers'][1]['name'])
        self.assertEqual(constants.SB_TIER_STATUS_IN_USE,
                         tier_list['storage_tiers'][1]['status'])

        # validate the cluster view
        cluster_list = self.get_json('/clusters', expect_errors=False)
        self.assertEqual('ceph_cluster', cluster_list['clusters'][0]['name'])

        response = self.get_json('/clusters/%s' % cluster_list['clusters'][0]['uuid'],
                                 expect_errors=False)
        self.assertEqual(constants.SB_TIER_DEFAULT_NAMES[
            constants.SB_TIER_TYPE_CEPH],
                         response['tiers'][0]['name'])
        self.assertEqual('gold', response['tiers'][1]['name'])

        # validate the tier view
        tier_list = self.get_json('/storage_tiers', expect_errors=False)
        self.assertEqual(constants.SB_TIER_DEFAULT_NAMES[
            constants.SB_TIER_TYPE_CEPH],
                         tier_list['storage_tiers'][0]['name'])
        self.assertEqual('gold', tier_list['storage_tiers'][1]['name'])

        response = self.get_json('/storage_tiers/%s' % tier_list['storage_tiers'][0]['uuid'],
                                 expect_errors=False)
        self.assertEqual(constants.SB_TIER_DEFAULT_NAMES[
            constants.SB_TIER_TYPE_CEPH],
                         response['name'])
        self.assertEqual([0], response['stors'])

        response = self.get_json('/storage_tiers/%s' % tier_list['storage_tiers'][1]['uuid'],
                                 expect_errors=False)
        self.assertEqual('gold', response['name'])
        self.assertEqual([1], response['stors'])

        # Add the ceph backend for the new tier without specifying a backend name
        values = {
            'backend': constants.SB_TYPE_CEPH,
            'capabilities': {'test_bparam3': 'foo'},
            'confirmed': True
        }
        with nested(mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses'),
                    mock.patch.object(StorageBackendConfig, 'set_img_conversions_defaults')) as (
                        mock_ceph_mon, mock_conv):
            response = self.post_json('/storage_ceph', values, expect_errors=True)
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            self.assertTrue(response.json['error_message'])
            self.assertIn('Initial (%s) backend was previously created. Use '
                          'the modify API for further provisioning' % constants.SB_DEFAULT_NAMES[
                              constants.SB_TIER_TYPE_CEPH],
                          response.json['error_message'])

        # Add the ceph backend for the new tier without specifying the tier
        values = {
            'backend': constants.SB_TYPE_CEPH,
            'capabilities': {'test_bparam3': 'foo'},
            'name':'ceph-gold',
            'confirmed': True
        }
        with nested(mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses'),
                    mock.patch.object(StorageBackendConfig, 'set_img_conversions_defaults')) as (
                        mock_ceph_mon, mock_conv):
            response = self.post_json('/storage_ceph', values, expect_errors=True)
            self.assertEqual(http_client.BAD_REQUEST, response.status_int)
            self.assertEqual('application/json', response.content_type)
            self.assertTrue(response.json['error_message'])
            self.assertIn('No tier specified for this backend.',
                          response.json['error_message'])

        # Add the ceph backend for the new tier
        values = {
            'backend': constants.SB_TYPE_CEPH,
            'capabilities': {'test_bparam3': 'one',
                             'test_cparam3': 'two'},
            'services': constants.SB_SVC_CINDER,
            'name':'ceph-gold',
            'tier_uuid': saved_tier_uuid,
            'confirmed': True
        }
        with nested(mock.patch.object(StorageBackendConfig, 'get_ceph_mon_ip_addresses'),
                    mock.patch.object(StorageBackendConfig, 'set_img_conversions_defaults'),
                    mock.patch.object(StorageBackendConfig, 'get_ceph_tier_size')) as (
                        mock_ceph_mon, mock_conv, mock_space):
            mock_space.return_value = 0

            response = self.post_json('/storage_ceph', values, expect_errors=True)
            self.assertEqual(http_client.OK, response.status_int)
            self.assertEqual('ceph-gold',
                             self.get_json('/storage_backend/%s/' % response.json['uuid'])['name'])  # Result

        # validate the backend view
        backend_list = self.get_json('/storage_backend', expect_errors=False)
        self.assertEqual(http_client.OK, response.status_int)
        self.assertEqual(constants.SB_DEFAULT_NAMES[
            constants.SB_TIER_TYPE_CEPH],
                         backend_list['storage_backends'][0]['name'])
        self.assertEqual('ceph-gold', backend_list['storage_backends'][1]['name'])
