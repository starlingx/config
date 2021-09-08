# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Test class for Sysinv subcloud_audit

"""

import time
from sysinv.cert_mon.subcloud_audit_queue import SubcloudAuditData
from sysinv.cert_mon.subcloud_audit_queue import SubcloudAuditException
from sysinv.cert_mon.subcloud_audit_queue import SubcloudAuditPriorityQueue
from sysinv.tests.db import base


class SubcloudAuditTestCase(base.DbTestCase):
    """Test cases for subcloud_audit.py classes"""

    def setUp(self):
        super(SubcloudAuditTestCase, self).setUp()
        # Set up objects for testing
        self.sc_audit_queue = SubcloudAuditPriorityQueue()

    def tearDown(self):
        super(SubcloudAuditTestCase, self).tearDown()

    def test_audit_item(self):
        print("Running test_audit_item")
        item1 = SubcloudAuditData("item1")
        self.assertEqual(item1.name, "item1")
        self.assertEqual(item1.audit_count, 0)
        self.assertEqual(item1, SubcloudAuditData("item1", 0))
        self.assertEqual(item1, SubcloudAuditData("item1", 1))

    def test_subcloud_audit_queue_single(self):
        sc_name = "subcloud1"
        subcloud = SubcloudAuditData(sc_name)
        self.sc_audit_queue.enqueue(subcloud)
        assert self.sc_audit_queue.contains(sc_name)
        assert self.sc_audit_queue.qsize() == 1
        # peek using the underlying queue
        _, sc_audit_item1 = self.sc_audit_queue.queue[0]
        assert sc_audit_item1.name == sc_name
        assert sc_audit_item1.audit_count == 1

    def test_subcloud_audit_queue_multiple(self):
        subclouds = [SubcloudAuditData("subcloud%s" % i) for i in range(20)]
        delay = 0
        for i in range(20):
            self.sc_audit_queue.enqueue(subclouds[i], delay)
            delay += 10
        assert self.sc_audit_queue.qsize() == 20

        _, first = self.sc_audit_queue.get()
        assert first.name == subclouds[0].name
        assert not self.sc_audit_queue.contains(subclouds[0].name)
        assert self.sc_audit_queue.qsize() == 19

        # re-enqueue with no delay; it should come out first again
        self.sc_audit_queue.enqueue(first, 0)
        _, first = self.sc_audit_queue.get()
        assert first.name == subclouds[0].name

        timestamp, second = self.sc_audit_queue.get()
        assert second.name == subclouds[1].name
        # The time now should be well under the timestamp for this item
        assert int(time.time()) < timestamp

    def test_subcloud_audit_queue_custom_timestamp(self):
        subclouds = [SubcloudAuditData("subcloud%s" % i) for i in range(20)]
        timestamp = 0
        for i in range(20):
            self.sc_audit_queue.enqueue(subclouds[i], timestamp=timestamp)
            timestamp += 10
        assert self.sc_audit_queue.qsize() == 20

        _, first = self.sc_audit_queue.get()
        assert first.name == subclouds[0].name
        assert not self.sc_audit_queue.contains(subclouds[0].name)
        assert self.sc_audit_queue.qsize() == 19

        # re-enqueue with no delay; it should come out first again
        self.sc_audit_queue.enqueue(first, timestamp=0)
        _, first = self.sc_audit_queue.get()
        assert first.name == subclouds[0].name
        assert first == subclouds[0]

        self.sc_audit_queue.enqueue(subclouds[0], timestamp=10000)
        prev_timestamp = 0
        for i in range(19):
            next_timestamp, next_item = self.sc_audit_queue.get()
            assert next_timestamp > prev_timestamp
            assert next_item.name != subclouds[0].name
            prev_timestamp = next_timestamp

        next_timestamp, next_item = self.sc_audit_queue.get()
        assert next_timestamp == 10000
        assert next_item.name == subclouds[0].name

    def test_subcloud_audit_requeue(self):
        subclouds = [SubcloudAuditData("subcloud%s" % i, 0) for i in range(20)]
        timestamp = 0
        for i in range(20):
            self.sc_audit_queue.enqueue(subclouds[i], timestamp=timestamp)
            timestamp += 10
        assert self.sc_audit_queue.qsize() == 20

        assert self.sc_audit_queue.contains(subclouds[0].name)

        got_exception = False
        try:
            self.sc_audit_queue.enqueue(subclouds[0], timestamp=timestamp)
        except SubcloudAuditException:
            got_exception = True
        assert got_exception

        got_exception = False
        try:
            self.sc_audit_queue.enqueue(
                subclouds[0], timestamp=timestamp, allow_requeue=True
            )
        except SubcloudAuditException:
            got_exception = True
        assert not got_exception
        count = 0
        for name in self.sc_audit_queue.enqueued_subcloud_names:
            if name == subclouds[0].name:
                count += 1
        assert count == 2
