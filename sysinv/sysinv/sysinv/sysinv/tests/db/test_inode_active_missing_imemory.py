# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

"""Tests for inode_active_get_by_missing_imemory DB API"""

from oslo_utils import uuidutils

from sysinv.common import constants
from sysinv.db import api as dbapi
from sysinv.tests.db import base
from sysinv.tests.db import utils


class TestInodeActiveGetByMissingImemory(base.DbTestCase):

    def setUp(self):
        super(TestInodeActiveGetByMissingImemory, self).setUp()
        self.dbapi = dbapi.get_instance()
        self.system = utils.create_test_isystem()

    def _create_host(self, availability=constants.AVAILABILITY_AVAILABLE, **kwargs):
        kwargs['forisystemid'] = self.system['id']
        kwargs.setdefault('uuid', uuidutils.generate_uuid())
        kwargs.setdefault('hostname', 'host-' + uuidutils.generate_uuid()[:8])
        kwargs.setdefault('mgmt_mac', uuidutils.generate_uuid()[:17])
        kwargs['availability'] = availability
        return utils.create_test_ihost(**kwargs)

    def _create_inode(self, host, numa_node=0, is_active=True):
        capabilities = {'is_active': is_active}
        return self.dbapi.inode_create(host['id'], {
            'forihostid': host['id'],
            'numa_node': numa_node,
            'capabilities': capabilities,
        })

    def _create_imemory(self, host, inode):
        return self.dbapi.imemory_create(host['id'],
            utils.get_test_imemory(forihostid=host['id'],
                                   forinodeid=inode['id']))

    def test_returns_inode_with_missing_imemory(self):
        host = self._create_host()
        inode = self._create_inode(host)

        result = self.dbapi.inode_active_get_by_missing_imemory()

        self.assertEqual(1, len(result))
        self.assertEqual(inode['id'], result[0]['id'])

    def test_excludes_inode_with_existing_imemory(self):
        host = self._create_host()
        inode = self._create_inode(host)
        self._create_imemory(host, inode)

        result = self.dbapi.inode_active_get_by_missing_imemory()

        self.assertEqual(0, len(result))

    def test_excludes_inactive_inode(self):
        host = self._create_host()
        self._create_inode(host, is_active=False)

        result = self.dbapi.inode_active_get_by_missing_imemory()

        self.assertEqual(0, len(result))

    def test_legacy_inode_without_is_active_treated_as_active(self):
        host = self._create_host()
        # capabilities without 'is_active' key — legacy row
        self.dbapi.inode_create(host['id'], {
            'forihostid': host['id'],
            'numa_node': 0,
            'capabilities': {},
        })

        result = self.dbapi.inode_active_get_by_missing_imemory()

        self.assertEqual(1, len(result))

    def test_excludes_offline_host_by_default(self):
        offline_host = self._create_host(availability=constants.AVAILABILITY_OFFLINE)
        self._create_inode(offline_host)

        result = self.dbapi.inode_active_get_by_missing_imemory()

        self.assertEqual(0, len(result))

    def test_includes_offline_host_when_exclude_offline_false(self):
        offline_host = self._create_host(availability=constants.AVAILABILITY_OFFLINE)
        self._create_inode(offline_host)

        result = self.dbapi.inode_active_get_by_missing_imemory(exclude_offline=False)

        self.assertEqual(1, len(result))

    def test_mixed_nodes_only_missing_returned(self):
        host = self._create_host()
        inode0 = self._create_inode(host, numa_node=0)
        inode1 = self._create_inode(host, numa_node=1)
        self._create_imemory(host, inode0)  # inode0 has imemory, inode1 does not

        result = self.dbapi.inode_active_get_by_missing_imemory()

        self.assertEqual(1, len(result))
        self.assertEqual(inode1['id'], result[0]['id'])

    def test_multiple_hosts_only_missing_returned(self):
        host1 = self._create_host()
        host2 = self._create_host(hostname='host2')
        inode1 = self._create_inode(host1)
        inode2 = self._create_inode(host2)
        self._create_imemory(host1, inode1)  # host1 covered, host2 not

        result = self.dbapi.inode_active_get_by_missing_imemory()

        self.assertEqual(1, len(result))
        self.assertEqual(inode2['id'], result[0]['id'])
