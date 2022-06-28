# Copyright (c) 2021-2022 Wind River Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0

import heapq
import time
from eventlet.queue import PriorityQueue
from oslo_log import log

LOG = log.getLogger(__name__)


class SubcloudAuditData(object):
    """Representation of a subcloud under audit.
    The 'name' field is used for all comparisons.
    """
    def __init__(self, name, audit_count=0):
        self.name = name
        self.audit_count = audit_count

    def __eq__(self, other):
        return self.name == other.name

    def __hash__(self):
        return hash(self.name)

    def __str__(self):
        return "SubcloudAuditData: {name: %s, audit_count: %s}" % (
            self.name, self.audit_count)


class SubcloudAuditException(Exception):
    """Indicates subcloud audit issue"""
    pass


class SubcloudAuditPriorityQueue(PriorityQueue):
    """A subclass of PriorityQueue which tracks enqueued subclouds"""
    def _init(self, maxsize=None):
        self.enqueued_subcloud_names = list()
        PriorityQueue._init(self, maxsize)

    @staticmethod
    def __get_next_audit_timestamp(delay_secs):
        next_audit_timestamp = int(time.time())
        if delay_secs > 0:
            next_audit_timestamp += delay_secs
        return next_audit_timestamp

    def contains(self, subcloud_name):
        """Check if subcloud is under audit"""
        return subcloud_name in self.enqueued_subcloud_names

    def enqueue(self, sc_audit_item, delay_secs=0,
                timestamp=None, allow_requeue=False):
        """Custom top-level method to enqueue a subcloud in the audit
           - convert delay to timestamp
           - increment audit_count
        """
        if (sc_audit_item.name in self.enqueued_subcloud_names
                and not allow_requeue):
            raise SubcloudAuditException("Subcloud already enqueued: %s"
                                         % sc_audit_item.name)
        if timestamp is None:
            timestamp = self.__get_next_audit_timestamp(delay_secs)
        else:
            timestamp += delay_secs

        # this PriorityQueue is ordered by the next timestamp:
        sc_audit_item.audit_count += 1
        self.put(
            (timestamp, sc_audit_item)
        )

    def _get(self, heappop=heapq.heappop):
        """Modifies PriorityQueue.get() to track audited subcloud names"""
        item = PriorityQueue._get(self, heappop)
        self.enqueued_subcloud_names.remove(item[1].name)
        return item

    def _put(self, item, heappush=heapq.heappush):
        """Modifies PriorityQueue.put() to track audited subcloud names"""
        subcloud_audit = item[1]
        self.enqueued_subcloud_names.append(subcloud_audit.name)
        LOG.info("Enqueued: %s" % str(subcloud_audit))
        PriorityQueue._put(self, item, heappush)
