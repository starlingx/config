#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
Tests for the generic utils.
"""

from sysinv.common import utils
from sysinv.tests import base


class TestCommonUtils(base.TestCase):
    def test_parse_range_set(self):
        # Empty string
        self.assertEqual(utils.parse_range_set(""), [])
        # Single item
        self.assertEqual(utils.parse_range_set("11"), [11])
        # Multi non-consecutive items
        self.assertEqual(set(utils.parse_range_set("1,3,5")), set([1, 3, 5]))
        # Multi consecutive items
        self.assertEqual(set(utils.parse_range_set("1,2,3")), set([1, 2, 3]))
        # Out of order
        self.assertEqual(set(utils.parse_range_set("1,3,2")), set([1, 2, 3]))
        # Single range
        self.assertEqual(set(utils.parse_range_set("7-10")),
                         set([7, 8, 9, 10]))
        # Mix of single items and range
        self.assertEqual(set(utils.parse_range_set("1,3-7,11,2")),
                         set([1, 2, 3, 4, 5, 6, 7, 11]))
        # Duplicates
        self.assertEqual(set(utils.parse_range_set("1,2,3,2,1")),
                         set([1, 2, 3]))
        # Single items overlapping with range
        self.assertEqual(set(utils.parse_range_set("1-3,2,1")),
                         set([1, 2, 3]))
