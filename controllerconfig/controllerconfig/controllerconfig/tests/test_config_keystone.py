#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Unit tests for controllerconfig.common.keystone module."""

import datetime
import unittest

from controllerconfig.common.exceptions import KeystoneFail
from controllerconfig.common.keystone import Domain
from controllerconfig.common.keystone import DomainList
from controllerconfig.common.keystone import Endpoint
from controllerconfig.common.keystone import EndpointList
from controllerconfig.common.keystone import Project
from controllerconfig.common.keystone import ProjectList
from controllerconfig.common.keystone import Role
from controllerconfig.common.keystone import RoleList
from controllerconfig.common.keystone import Service
from controllerconfig.common.keystone import ServiceList
from controllerconfig.common.keystone import Token
from controllerconfig.common.keystone import User
from controllerconfig.common.keystone import UserList


class TestToken(unittest.TestCase):
    """Tests for Token class."""

    def _make_token(self, expires_at=None, token_id="tok-123"):
        if expires_at is None:
            future = (
                datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            )
            expires_at = future.isoformat() + "Z"
        data = {
            "token": {
                "expires_at": expires_at,
                "catalog": [],
            }
        }
        return Token(data, token_id)

    def test_get_id(self):
        """get_id returns the token id."""
        tok = self._make_token(token_id="abc")
        self.assertEqual(tok.get_id(), "abc")

    def test_is_expired_false_for_fresh_token(self):
        """A fresh token is not expired."""
        tok = self._make_token()
        self.assertFalse(tok.is_expired())

    def test_set_expired(self):
        """set_expired marks the token as expired."""
        tok = self._make_token()
        tok.set_expired()
        self.assertTrue(tok.is_expired())

    def test_is_expired_within_seconds(self):
        """Token expiring within threshold is considered expired."""
        soon = (
            datetime.datetime.utcnow() + datetime.timedelta(seconds=10)
        )
        tok = self._make_token(expires_at=soon.isoformat() + "Z")
        self.assertTrue(tok.is_expired(within_seconds=300))

    def test_get_service_url_found(self):
        """get_service_url returns URL when match found."""
        data = {
            "token": {
                "expires_at": (
                    datetime.datetime.utcnow() +
                    datetime.timedelta(hours=1)
                ).isoformat() + "Z",
                "catalog": [
                    {
                        "type": "identity",
                        "name": "keystone",
                        "endpoints": [
                            {
                                "region": "RegionOne",
                                "interface": "admin",
                                "url": "http://keystone:5000/v3",
                            }
                        ],
                    }
                ],
            }
        }
        tok = Token(data, "t1")
        url = tok.get_service_url(
            "RegionOne",
            "keystone",
            "identity",
            "admin"
        )
        self.assertEqual(url, "http://keystone:5000/v3")

    def test_get_service_url_not_found(self):
        """get_service_url raises KeystoneFail when not found."""
        data = {
            "token": {
                "expires_at": (
                    datetime.datetime.utcnow() +
                    datetime.timedelta(hours=1)
                ).isoformat() + "Z",
                "catalog": [],
            }
        }
        tok = Token(data, "t1")
        self.assertRaises(
            KeystoneFail,
            tok.get_service_url,
            "RegionOne", "keystone", "identity", "admin",
        )

    def test_get_service_admin_url(self):
        """get_service_admin_url delegates to get_service_url."""
        data = {
            "token": {
                "expires_at": (
                    datetime.datetime.utcnow() +
                    datetime.timedelta(hours=1)
                ).isoformat() + "Z",
                "catalog": [
                    {
                        "type": "identity",
                        "name": "keystone",
                        "endpoints": [
                            {
                                "region": "R1",
                                "interface": "admin",
                                "url": "http://admin:5000",
                            }
                        ],
                    }
                ],
            }
        }
        tok = Token(data, "t1")
        url = tok.get_service_admin_url("identity", "keystone", "R1")
        self.assertEqual(url, "http://admin:5000")


class TestService(unittest.TestCase):
    """Tests for Service class."""

    def test_get_id_present(self):
        """get_id returns service id when present."""
        svc = Service({"service": {"id": "svc-1"}})
        self.assertEqual(svc.get_id(), "svc-1")

    def test_get_id_missing(self):
        """get_id returns None when id is missing."""
        svc = Service({"service": {}})
        self.assertIsNone(svc.get_id())


class TestServiceList(unittest.TestCase):
    """Tests for ServiceList class."""

    def test_get_service_id_found(self):
        """get_service_id returns id when service found."""
        data = {
            "services": [
                {"name": "keystone", "type": "identity", "id": "s1"},
            ]
        }
        sl = ServiceList(data)
        self.assertEqual(sl.get_service_id("keystone", "identity"),
                         "s1")

    def test_get_service_id_not_found(self):
        """get_service_id raises KeystoneFail when not found."""
        sl = ServiceList({"services": []})
        self.assertRaises(
            KeystoneFail, sl.get_service_id, "missing", "type"
        )


class TestProject(unittest.TestCase):
    """Tests for Project class."""

    def test_get_id_present(self):
        """get_id returns project id."""
        proj = Project({"project": {"id": "p1"}})
        self.assertEqual(proj.get_id(), "p1")

    def test_get_id_missing(self):
        """get_id returns None when id missing."""
        proj = Project({"project": {}})
        self.assertIsNone(proj.get_id())


class TestProjectList(unittest.TestCase):
    """Tests for ProjectList class."""

    def test_get_project_id_found(self):
        """get_project_id returns id when found."""
        data = {"projects": [{"name": "admin", "id": "p1"}]}
        pl = ProjectList(data)
        self.assertEqual(pl.get_project_id("admin"), "p1")

    def test_get_project_id_not_found(self):
        """get_project_id returns None when not found."""
        pl = ProjectList({"projects": []})
        self.assertIsNone(pl.get_project_id("missing"))


class TestEndpoint(unittest.TestCase):
    """Tests for Endpoint class."""

    def test_get_id_present(self):
        """get_id returns endpoint id."""
        ep = Endpoint({"endpoint": {"id": "e1"}})
        self.assertEqual(ep.get_id(), "e1")

    def test_get_id_missing(self):
        """get_id returns None when id missing."""
        ep = Endpoint({"endpoint": {}})
        self.assertIsNone(ep.get_id())


class TestEndpointList(unittest.TestCase):
    """Tests for EndpointList class."""

    def test_get_service_url_found(self):
        """get_service_url returns url when found."""
        data = {
            "endpoints": [
                {
                    "service_id": "s1",
                    "region": "R1",
                    "interface": "public",
                    "url": "http://public:8080",
                }
            ]
        }
        el = EndpointList(data)
        self.assertEqual(el.get_service_url("R1", "s1", "public"),
                         "http://public:8080")

    def test_get_service_url_not_found(self):
        """get_service_url raises KeystoneFail when not found."""
        el = EndpointList({"endpoints": []})
        self.assertRaises(
            KeystoneFail, el.get_service_url, "R1", "s1", "public"
        )


class TestUser(unittest.TestCase):
    """Tests for User class."""

    def test_get_user_id(self):
        """get_user_id returns user id."""
        user = User({"user": {"id": "u1"}})
        self.assertEqual(user.get_user_id(), "u1")


class TestUserList(unittest.TestCase):
    """Tests for UserList class."""

    def test_get_user_id_found(self):
        """get_user_id returns id when found."""
        data = {"users": [{"name": "admin", "id": "u1"}]}
        ul = UserList(data)
        self.assertEqual(ul.get_user_id("admin"), "u1")

    def test_get_user_id_not_found(self):
        """get_user_id returns None when not found."""
        ul = UserList({"users": []})
        self.assertIsNone(ul.get_user_id("missing"))


class TestRole(unittest.TestCase):
    """Tests for Role class."""

    def test_role_stores_data(self):
        """Role stores its data."""
        role = Role({"role": {"id": "r1"}})
        self.assertEqual(role._data["role"]["id"], "r1")


class TestRoleList(unittest.TestCase):
    """Tests for RoleList class."""

    def test_get_role_id_found(self):
        """get_role_id returns id when found."""
        data = {"roles": [{"name": "admin", "id": "r1"}]}
        rl = RoleList(data)
        self.assertEqual(rl.get_role_id("admin"), "r1")

    def test_get_role_id_not_found(self):
        """get_role_id returns None when not found."""
        rl = RoleList({"roles": []})
        self.assertIsNone(rl.get_role_id("missing"))


class TestDomain(unittest.TestCase):
    """Tests for Domain class."""

    def test_get_domain_id(self):
        """get_domain_id returns domain id."""
        dom = Domain({"domain": {"id": "d1"}})
        self.assertEqual(dom.get_domain_id(), "d1")


class TestDomainList(unittest.TestCase):
    """Tests for DomainList class."""

    def test_get_domain_id_found(self):
        """get_domain_id returns id when found."""
        data = {"domains": [{"name": "default", "id": "d1"}]}
        dl = DomainList(data)
        self.assertEqual(dl.get_domain_id("default"), "d1")

    def test_get_domain_id_not_found(self):
        """get_domain_id returns None when not found."""
        dl = DomainList({"domains": []})
        self.assertIsNone(dl.get_domain_id("missing"))


if __name__ == "__main__":
    unittest.main()
