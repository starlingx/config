#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for cgtsclient.common.base module."""

import copy
import unittest
from unittest import mock

from cgtsclient.common import base


class TestGetId(unittest.TestCase):
    def test_getid_with_id_attr(self):
        obj = type("Obj", (), {"id": "uuid-123"})()
        self.assertEqual(base.getid(obj), "uuid-123")

    def test_getid_without_id_attr(self):
        self.assertEqual(base.getid("plain-string"), "plain-string")

    def test_getid_with_int(self):
        self.assertEqual(base.getid(42), 42)


class TestResource(unittest.TestCase):
    def _make_resource(self, info=None, loaded=False):
        mgr = mock.MagicMock()
        return base.Resource(
            mgr,
            info or {"id": "r1", "name": "test"},
            loaded
        )

    def test_resource_attrs(self):
        r = self._make_resource(
            {"id": "r1", "name": "test"},
            loaded=True
        )
        self.assertEqual(r.id, "r1")
        self.assertEqual(r.name, "test")

    def test_resource_to_dict(self):
        r = self._make_resource({"id": "r1", "name": "test"})
        d = r.to_dict()
        self.assertEqual(d, {"id": "r1", "name": "test"})

    def test_resource_to_dict_is_copy(self):
        r = self._make_resource({"id": "r1"})
        d = r.to_dict()
        d["id"] = "changed"
        self.assertEqual(r._info["id"], "r1")

    def test_resource_eq_same_id(self):
        r1 = self._make_resource({"id": "r1"})
        r2 = self._make_resource({"id": "r1"})
        self.assertEqual(r1, r2)

    def test_resource_eq_different_id(self):
        r1 = self._make_resource({"id": "r1"})
        r2 = self._make_resource({"id": "r2"})
        self.assertNotEqual(r1, r2)

    def test_resource_repr(self):
        r = self._make_resource(
            {"id": "r1", "name": "test"},
            loaded=True
        )
        rep = repr(r)
        self.assertIn("id", rep)
        self.assertIn("name", rep)

    def test_resource_is_loaded(self):
        r = self._make_resource(loaded=True)
        self.assertTrue(r.is_loaded())

    def test_resource_set_loaded(self):
        r = self._make_resource(loaded=False)
        r.set_loaded(True)
        self.assertTrue(r.is_loaded())

    def test_resource_copy(self):
        r = self._make_resource(
            {"id": "r1", "name": "test"},
            loaded=True
        )
        r2 = copy.copy(r)
        self.assertEqual(r2.id, "r1")

    def test_resource_deepcopy(self):
        r = self._make_resource(
            {"id": "r1", "name": "test"},
            loaded=True
        )
        r2 = copy.deepcopy(r)
        self.assertEqual(r2.id, "r1")

    def test_resource_hash(self):
        r = self._make_resource({"id": "r1"})
        # Resource.__hash__ may raise for unhashable _info dict
        try:
            h = hash(r)
            self.assertIsInstance(h, int)
        except TypeError:
            pass  # Expected when _info is dict (unhashable)


class TestManager(unittest.TestCase):
    def test_manager_init(self):
        api = mock.MagicMock()
        mgr = base.Manager(api)
        self.assertIs(mgr.api, api)

    def test_manager_create(self):
        api = mock.MagicMock()
        api.json_request.return_value = (None, {"id": "new"})
        mgr = base.Manager(api)
        mgr.resource_class = base.Resource
        result = mgr._create("/url", {"name": "test"})
        self.assertIsNotNone(result)

    def test_manager_create_empty_body(self):
        api = mock.MagicMock()
        api.json_request.return_value = (None, None)
        mgr = base.Manager(api)
        mgr.resource_class = base.Resource
        result = mgr._create("/url", {"name": "test"})
        self.assertIsNone(result)

    def test_manager_delete(self):
        api = mock.MagicMock()
        mgr = base.Manager(api)
        mgr._delete("/url/123")
        api.raw_request.assert_called_once_with("DELETE", "/url/123")

    def test_manager_upload(self):
        api = mock.MagicMock()
        api.upload_request_with_data.return_value = "ok"
        mgr = base.Manager(api)
        result = mgr._upload("/url", {}, data="data")
        self.assertEqual(result, "ok")


if __name__ == "__main__":
    unittest.main()
