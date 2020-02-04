# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#
#
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#
import mock

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
        with mock.patch.object(self.dbapi, "ihost_get") as host_get_mock:
            host_get_mock.return_value = self.obj_node
            objects.host.get_by_uuid(self.admin_context, uuid)
            host_get_mock.assert_called_once_with(uuid)

    def test_save(self):
        uuid = self.fake_node['uuid']
        with mock.patch.object(self.dbapi, "ihost_get") as host_get_mock:
            host_get_mock.return_value = self.obj_node
            with mock.patch.object(self.dbapi, "ihost_update") as host_update_mock:
                # These next 3 lines are the unit test
                n = objects.host.get_by_uuid(self.admin_context, uuid)
                n.location = {"City": "property"}
                n.save()
                # verify the routines were called as expected
                host_get_mock.assert_called_once_with(uuid)
                host_update_mock.assert_called_once_with(uuid,
                    {'location': {"City": "property"}})

    def test_refresh(self):
        uuid = self.fake_node['uuid']
        first_obj = objects.host.from_db_object(self._get_db_node(
            dict(self.fake_node, location={"City": "first"})))
        second_obj = objects.host.from_db_object(self._get_db_node(
            dict(self.fake_node, location={"City": "second"})))
        with mock.patch.object(self.dbapi, "ihost_get") as host_get_mock:
            host_get_mock.side_effect = iter([first_obj, second_obj])
            n = objects.host.get_by_uuid(self.admin_context, uuid)
            self.assertEqual(n.location, {"City": "first"})
            n.refresh()
            self.assertEqual(n.location, {"City": "second"})

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
