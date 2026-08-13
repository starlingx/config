#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for sysinv.api.controllers.v1.link module."""
import unittest
from sysinv.api.controllers.v1.link import Link


class TestLink(unittest.TestCase):
    def test_make_link_basic(self):
        lnk = Link.make_link(
            'self',
            'http://host',
            'resource',
            'uuid-1'
        )
        self.assertIn('http://host', lnk.href)
        self.assertEqual(lnk.rel, 'self')

    def test_make_link_bookmark(self):
        lnk = Link.make_link(
            'bookmark',
            'http://host',
            'resource',
            'uuid-1',
            bookmark=True
        )
        self.assertNotIn('/v1/', lnk.href)

    def test_make_link_query_args(self):
        lnk = Link.make_link(
            'self',
            'http://host',
            'resource',
            '?key=val'
        )
        self.assertIn('?key=val', lnk.href)


if __name__ == "__main__":
    unittest.main()
