#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants
from sysinv.puppet import ovs
from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils
from sysinv.tests.puppet import base


class OVSPuppetSocketMemTestCase(base.PuppetTestCaseMixin,
                                 dbbase.BaseHostTestCase):
    """Validate the positional vswitch::dpdk::socket_mem ordering."""

    def setUp(self):
        super(OVSPuppetSocketMemTestCase, self).setUp()
        # numa_nodes=0: the test creates its own inode/imemory rows so it
        # controls the primary-key order of the imemory table.
        self.host = self._create_test_host(constants.WORKER, numa_nodes=0)
        self.ovs_puppet = ovs.OVSPuppet(self.operator)

    def _create_node_memory(self, numa_node, size_mib, pages):
        node = self.dbapi.inode_create(
            self.host.id,
            dbutils.get_test_node(numa_node=numa_node,
                                  forihostid=self.host.id))
        self.dbapi.imemory_create(
            self.host.id,
            dbutils.get_test_imemory(forinodeid=node.id,
                                     vswitch_hugepages_size_mib=size_mib,
                                     vswitch_hugepages_reqd=None,
                                     vswitch_hugepages_nr=pages))

    def test_socket_mem_follows_numa_node_order(self):
        """Entry i of socket_mem carries NUMA node i's size_mib x pages.

        The NUMA node 1 row is created before the NUMA node 0 row, so the
        primary-key order of the imemory rows is the reverse of the node
        order. The per-node products differ so a wrong order is visible.
        """
        # id order: node 1 first, node 0 second
        self._create_node_memory(numa_node=1, size_mib=2, pages=256)  # 512
        self._create_node_memory(numa_node=0, size_mib=2, pages=512)  # 1024

        config = self.ovs_puppet._get_memory_config(self.host)

        socket_mem = str(config['vswitch::dpdk::socket_mem']).split(',')
        self.assertEqual(2, len(socket_mem))
        self.assertEqual(['1024', '512'], socket_mem)
