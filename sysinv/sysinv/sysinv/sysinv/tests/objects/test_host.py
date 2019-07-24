# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#
#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#

from sysinv.db import api as db_api
from sysinv.db.sqlalchemy import models
from sysinv import objects
from sysinv.tests.db import base
from sysinv.tests.db import utils


class TestHostObject(base.DbTestCase):

    def setUp(self):
        super(TestHostObject, self).setUp()
        self.fake_node = utils.get_test_ihost()
        self.obj_node = objects.host.from_db_object(
            self._get_db_node(self.fake_node))
        self.dbapi = db_api.get_instance()

    def test_load(self):
        uuid = self.fake_node['uuid']
        self.mox.StubOutWithMock(self.dbapi, 'ihost_get')

        self.dbapi.ihost_get(uuid).AndReturn(self.obj_node)
        self.mox.ReplayAll()

        objects.host.get_by_uuid(self.admin_context, uuid)
        self.mox.VerifyAll()
        # TODO(deva): add tests for load-on-demand info, eg. ports,
        #             once Port objects are created

    def test_save(self):
        uuid = self.fake_node['uuid']
        self.mox.StubOutWithMock(self.dbapi, 'ihost_get')
        self.mox.StubOutWithMock(self.dbapi, 'ihost_update')

        self.dbapi.ihost_get(uuid).AndReturn(self.obj_node)
        self.dbapi.ihost_update(uuid, {'location': {"City": "property"}})
        self.mox.ReplayAll()

        n = objects.host.get_by_uuid(self.admin_context, uuid)
        n.location = {"City": "property"}
        n.save()
        self.mox.VerifyAll()

    def test_refresh(self):
        uuid = self.fake_node['uuid']
        self.mox.StubOutWithMock(self.dbapi, 'ihost_get')

        first_obj = objects.host.from_db_object(self._get_db_node(
            dict(self.fake_node, location={"City": "first"})))
        second_obj = objects.host.from_db_object(self._get_db_node(
            dict(self.fake_node, location={"City": "second"})))

        self.dbapi.ihost_get(uuid).AndReturn(first_obj)
        self.dbapi.ihost_get(uuid).AndReturn(second_obj)
        self.mox.ReplayAll()

        n = objects.host.get_by_uuid(self.admin_context, uuid)
        self.assertEqual(n.location, {"City": "first"})
        n.refresh()
        self.assertEqual(n.location, {"City": "second"})
        self.mox.VerifyAll()

    def test_objectify(self):

        @objects.objectify(objects.host)
        def _convert_db_node():
            return self._get_db_node(self.fake_node)

        self.assertIsInstance(self._get_db_node(self.fake_node), models.ihost)
        self.assertIsInstance(_convert_db_node(), objects.host)

    def test_objectify_many(self):
        def _get_db_nodes():
            nodes = []
            for i in range(5):
                nodes.append(self._get_db_node(self.fake_node))
            return nodes

        @objects.objectify(objects.host)
        def _convert_db_nodes():
            return _get_db_nodes()

        for n in _get_db_nodes():
            self.assertIsInstance(n, models.ihost)
        for n in _convert_db_nodes():
            self.assertIsInstance(n, objects.host)

    def _get_db_node(self, fake_node):
        n = models.ihost()
        n.update(fake_node)
        return n
