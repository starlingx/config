#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for sysinv.common.context module."""

import unittest
from sysinv.common import context


def _get_tenant(ctx):
    """Get tenant value compatible with both oslo.context < 5.x and >= 5.x."""
    if hasattr(ctx, 'tenant'):
        return ctx.tenant
    return ctx.project_id


class TestRequestContext(unittest.TestCase):
    def test_create_context(self):
        ctx = context.RequestContext(user='admin', tenant='tenant1')
        self.assertEqual(ctx.user, 'admin')
        self.assertEqual(_get_tenant(ctx), 'tenant1')

    def test_create_context_defaults(self):
        ctx = context.RequestContext()
        self.assertIsNone(ctx.user)
        self.assertIsNone(_get_tenant(ctx))
        self.assertFalse(ctx.is_admin)

    def test_admin_context(self):
        ctx = context.RequestContext(
            user='admin',
            tenant='t',
            is_admin=True
        )
        self.assertTrue(ctx.is_admin)

    def test_to_dict(self):
        ctx = context.RequestContext(user='admin', tenant='t')
        d = ctx.to_dict()
        self.assertIsInstance(d, dict)
        self.assertIn('user', d)

    def test_from_dict(self):
        d = {'user': 'admin', 'tenant': 'tenant1', 'is_admin': False}
        ctx = context.RequestContext.from_dict(d)
        self.assertEqual(ctx.user, 'admin')


if __name__ == "__main__":
    unittest.main()
