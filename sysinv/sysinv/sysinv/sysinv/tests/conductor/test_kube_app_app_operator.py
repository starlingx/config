#
# SPDX-License-Identifier: Apache-2.0
#
# Copyright (C) 2020 Intel Corporation
#

"""Test class for Sysinv kube_app AppOperator."""

from sysinv.conductor import kube_app
from sysinv.db import api as dbapi
from sysinv.openstack.common import context

from sysinv.tests.db import base


class AppOperatorTestCase(base.DbTestCase):

    def setUp(self):
        super(AppOperatorTestCase, self).setUp()

        # Set up objects for testing
        self.app_operator = kube_app.AppOperator(dbapi.get_instance())
        self.context = context.get_admin_context()
        self.dbapi = dbapi.get_instance()
