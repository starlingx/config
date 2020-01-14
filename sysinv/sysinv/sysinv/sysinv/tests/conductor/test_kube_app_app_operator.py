#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2020 Intel Corporation
#

"""Test class for Sysinv kube_app AppOperator."""

from sysinv.conductor import kube_app
from sysinv.db import api as dbapi
from sysinv.openstack.common import context
from sysinv.objects import kube_app as obj_app

from sysinv.tests.db import base
from sysinv.tests.db import utils as dbutils


class AppOperatorTestCase(base.DbTestCase):

    def setUp(self):
        super(AppOperatorTestCase, self).setUp()

        # Set up objects for testing
        self.app_operator = kube_app.AppOperator(dbapi.get_instance())
        self.context = context.get_admin_context()
        self.dbapi = dbapi.get_instance()

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
