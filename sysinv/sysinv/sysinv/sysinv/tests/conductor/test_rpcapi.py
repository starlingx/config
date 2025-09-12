# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8

# Copyright 2013 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
# Copyright (c) 2013-2023 Wind River Systems, Inc.
#

"""
Unit Tests for :py:class:`sysinv.conductor.rpcapi.ConductorAPI`.
"""
import mock

from oslo_config import cfg
from oslo_context import context
from oslo_serialization import jsonutils as json

from sysinv.conductor import rpcapi as conductor_rpcapi
from sysinv.db import api as dbapi
from sysinv.openstack.common import rpc
from sysinv.tests.db import base
from sysinv.tests.db import utils as dbutils
from sysinv.common import constants

CONF = cfg.CONF


class RPCAPITestCase(base.DbTestCase):

    def setUp(self):
        super(RPCAPITestCase, self).setUp()
        self.context = context.get_admin_context()
        self.dbapi = dbapi.get_instance()
        self.fake_ihost = json.to_primitive(dbutils.get_test_ihost())

    def test_serialized_instance_has_uuid(self):
        self.assertTrue('uuid' in self.fake_ihost)

    def _test_rpcapi(self, method, rpc_method, **kwargs):
        ctxt = context.get_admin_context()
        rpcapi = conductor_rpcapi.ConductorAPI(topic='fake-topic')

        default_rpc_api_version = '1.0'
        expected_retval = 'hello world' if method == 'call' else None
        expected_version = kwargs.pop('version', default_rpc_api_version)
        expected_msg = rpcapi.make_msg(method, **kwargs)

        expected_msg['version'] = expected_version

        expected_topic = 'fake-topic'

        self.fake_args = None
        self.fake_kwargs = None

        def _fake_rpc_method(*args, **kwargs):
            self.fake_args = args
            self.fake_kwargs = kwargs
            if expected_retval:
                return expected_retval

        with mock.patch.object(rpc, rpc_method) as mock_method:
            mock_method.side_effect = _fake_rpc_method
            retval = getattr(rpcapi, method)(ctxt, **kwargs)
            self.assertEqual(retval, expected_retval)
            expected_args = [ctxt, expected_topic, expected_msg]
            for arg, expected_arg in zip(self.fake_args, expected_args):
                self.assertEqual(arg, expected_arg)

    def test_create_ihost(self):
        ihost_dict = {'mgmt_mac': '00:11:22:33:44:55',
                      'mgmt_ip': '1.2.3.4'}
        self._test_rpcapi('create_ihost',
                          'call',
                          values=ihost_dict)

    def test_update_ihost(self):
        self._test_rpcapi('update_ihost',
                          'call',
                          ihost_obj=self.fake_ihost)

    def test_configure_ihost(self):
        self._test_rpcapi('configure_ihost',
                          'call',
                          host=self.fake_ihost,
                          do_worker_apply=False)

    def test_update_ldap_client_config(self):
        self._test_rpcapi('update_ldap_client_config', 'call')

    def test_update_ldap_nat_config(self):
        self._test_rpcapi('update_ldap_nat_config', 'call')

    def test_kernel_runtime_manifests(self):
        self._test_rpcapi('kernel_runtime_manifests',
                          'call',
                          ihost_uuid=self.fake_ihost['uuid'])

    def test_report_kernel_running(self):
        self._test_rpcapi('report_kernel_running',
                          'cast',
                          ihost_uuid=self.fake_ihost['uuid'],
                          kernel_running=constants.KERNEL_LOWLATENCY)

    def test_configure_stalld(self):
        self._test_rpcapi('configure_stalld',
                          'call',
                          host_uuid=self.fake_ihost['uuid'])
