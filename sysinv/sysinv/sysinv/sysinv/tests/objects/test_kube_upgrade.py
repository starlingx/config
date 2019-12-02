# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#
#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
#

from sysinv.db import api as db_api
from sysinv.db.sqlalchemy import models
from sysinv import objects
from sysinv.tests.db import base
from sysinv.tests.db import utils


class TestKubeUpgradesObject(base.DbTestCase):

    def setUp(self):
        super(TestKubeUpgradesObject, self).setUp()
        self.fake_upgrade_data = utils.get_test_kube_upgrade()
        self.obj_data = objects.kube_upgrade.from_db_object(
            self._get_db_data(self.fake_upgrade_data))
        self.dbapi = db_api.get_instance()

    def test_load(self):
        uuid = self.fake_upgrade_data['uuid']
        self.mox.StubOutWithMock(self.dbapi, 'kube_upgrade_get')

        self.dbapi.kube_upgrade_get(uuid).AndReturn(self.obj_data)
        self.mox.ReplayAll()

        objects.kube_upgrade.get_by_uuid(self.admin_context, uuid)
        self.mox.VerifyAll()

    def test_save(self):
        uuid = self.fake_upgrade_data['uuid']
        self.mox.StubOutWithMock(self.dbapi, 'kube_upgrade_get')
        self.mox.StubOutWithMock(self.dbapi, 'kube_upgrade_update')

        self.dbapi.kube_upgrade_get(uuid).AndReturn(self.obj_data)
        self.dbapi.kube_upgrade_update(uuid, {'state': "upgrading"})
        self.mox.ReplayAll()

        n = objects.kube_upgrade.get_by_uuid(self.admin_context, uuid)
        n.state = "upgrading"
        n.save()
        self.mox.VerifyAll()

    def test_refresh(self):
        uuid = self.fake_upgrade_data['uuid']
        self.mox.StubOutWithMock(self.dbapi, 'kube_upgrade_get')

        first_obj = objects.kube_upgrade.from_db_object(self._get_db_data(
            dict(self.fake_upgrade_data, to_version='v1.42.1')))
        second_obj = objects.kube_upgrade.from_db_object(self._get_db_data(
            dict(self.fake_upgrade_data, to_version='v1.42.2')))

        self.dbapi.kube_upgrade_get(uuid).AndReturn(first_obj)
        self.dbapi.kube_upgrade_get(uuid).AndReturn(second_obj)
        self.mox.ReplayAll()

        n = objects.kube_upgrade.get_by_uuid(self.admin_context, uuid)
        self.assertEqual(n.to_version, 'v1.42.1')
        n.refresh()
        self.assertEqual(n.to_version, 'v1.42.2')
        self.mox.VerifyAll()

    def test_objectify(self):

        @objects.objectify(objects.kube_upgrade)
        def _convert_db_data():
            return self._get_db_data(self.fake_upgrade_data)

        self.assertIsInstance(self._get_db_data(self.fake_upgrade_data),
                              models.KubeUpgrade)
        self.assertIsInstance(_convert_db_data(), objects.kube_upgrade)

    def test_objectify_many(self):
        def _get_db_data_many():
            data = []
            for i in range(5):
                data.append(self._get_db_data(self.fake_upgrade_data))
            return data

        @objects.objectify(objects.kube_upgrade)
        def _convert_db_data_many():
            return _get_db_data_many()

        for n in _get_db_data_many():
            self.assertIsInstance(n, models.KubeUpgrade)
        for n in _convert_db_data_many():
            self.assertIsInstance(n, objects.kube_upgrade)

    def _get_db_data(self, fake_upgrade_data):
        n = models.KubeUpgrade()
        n.update(fake_upgrade_data)
        return n
