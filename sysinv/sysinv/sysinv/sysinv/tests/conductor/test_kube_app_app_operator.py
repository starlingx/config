#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2020 Intel Corporation
#

"""Test class for Sysinv kube_app AppOperator."""

import fixtures

from oslo_context import context

from sysinv.common import constants
from sysinv.conductor import kube_app
from sysinv.conductor import manager
from sysinv.db import api as dbapi
from sysinv.helm import helm
from sysinv.objects import kube_app as obj_app

from sysinv.tests.db import base
from sysinv.tests.db import utils as dbutils


class AppOperatorTestCase(base.DbTestCase):

    def setUp(self):
        super(AppOperatorTestCase, self).setUp()

        # Manager holds apps_metadata dict
        self.service = manager.ConductorManager('test-host', 'test-topic')

        # Set up objects for testing
        self.helm_operator = helm.HelmOperator(dbapi.get_instance())
        self.app_operator = kube_app.AppOperator(dbapi.get_instance(),
                                                 self.helm_operator,
                                                 self.service.apps_metadata)
        self.context = context.get_admin_context()
        self.dbapi = dbapi.get_instance()
        self.temp_dir = self.useFixture(fixtures.TempDir())

    def test_activate(self):
        # Create kubernetes apps
        dbutils.create_test_app(name='test-app-1',
                                active=True)
        test_app_1 = obj_app.get_by_name(self.context, 'test-app-1')
        self.assertEqual(test_app_1.active, True)
        res = self.app_operator.activate(test_app_1)
        # check was_active
        self.assertEqual(res, True)
        # check current active
        self.assertEqual(test_app_1.active, True)

        dbutils.create_test_app(name='test-app-2',
                                active=False)
        test_app_2 = obj_app.get_by_name(self.context, 'test-app-2')
        self.assertEqual(test_app_2.active, False)
        res = self.app_operator.activate(test_app_2)
        # check was_active
        self.assertEqual(res, False)
        # check current active
        self.assertEqual(test_app_2.active, True)

    def test_deactivate(self):
        # Create kubernetes apps
        dbutils.create_test_app(name='test-app-1',
                                active=True)
        test_app_1 = obj_app.get_by_name(self.context, 'test-app-1')
        self.assertEqual(test_app_1.active, True)
        res = self.app_operator.deactivate(test_app_1)
        # check was_active
        self.assertEqual(res, True)
        # check current active
        self.assertEqual(test_app_1.active, False)

        dbutils.create_test_app(name='test-app-2',
                                active=False)
        test_app_2 = obj_app.get_by_name(self.context, 'test-app-2')
        self.assertEqual(test_app_2.active, False)
        res = self.app_operator.deactivate(test_app_2)
        # check was_active
        self.assertEqual(res, False)
        # check current active
        self.assertEqual(test_app_2.active, False)

    def test_get_appname(self):
        test_app_name = 'test-app-1'
        dbutils.create_test_app(name=test_app_name,
                                status=constants.APP_APPLY_SUCCESS)
        test_app_1 = obj_app.get_by_name(self.context, 'test-app-1')
        app_name = self.app_operator.get_appname(test_app_1)
        self.assertEqual(test_app_name, app_name)

    def test_is_app_active(self):
        dbutils.create_test_app(name='test-app-1',
                                active=True)
        test_app_1 = obj_app.get_by_name(self.context, 'test-app-1')
        self.app_operator.activate(test_app_1)
        is_active = self.app_operator.is_app_active(test_app_1)
        self.assertEqual(is_active, True)
        self.app_operator.deactivate(test_app_1)
        is_active = self.app_operator.is_app_active(test_app_1)
        self.assertEqual(is_active, False)

    def test_reapply(self):
        dbutils.create_test_app(name='test-app-1',
                                active=True)
        constants.APP_PENDING_REAPPLY_FLAG = self.temp_dir.path + "/.app_reapply"
        self.app_operator.set_reapply('test-app-1')
        result = self.app_operator.needs_reapply('test-app-1')
        self.assertEqual(result, True)
        self.app_operator.clear_reapply('test-app-1')
        result = self.app_operator.needs_reapply('test-app-1')
        self.assertEqual(result, False)

    def test_is_app_aborted(self):
        self.app_operator.abort_requested["test_app"] = True
        res = self.app_operator.is_app_aborted("test_app")
        self.assertEqual(res, True)
        res = self.app_operator.is_app_aborted("test_app_123")
        self.assertEqual(res, False)
