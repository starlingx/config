# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
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

from oslo_config import cfg
from oslo_config import fixture as config_fixture

from sysinv.common import config

CONF = cfg.CONF
CONF.import_opt('use_ipv6', 'sysinv.netconf')
CONF.import_opt('host', 'sysinv.common.service')


class ConfFixture(config_fixture.Config):
    """Fixture to manage global conf settings."""

    def __init__(self, conf):
        self.conf = conf

    def setUp(self):
        super(ConfFixture, self).setUp()

        self.conf.set_default('host', 'fake-mini')
        # TODO(RemoveOpenstackRPCBackend): The openstack.common.rpc backend
        # is not used anymore. The unit tests use a fake implementation of
        # this backend. This needs to be adjusted to use a mockable/fake
        # version zeromq rpc backend. Then remove the openstack.common.rpc code
        # from source tree.
        self.conf.set_default('rpc_backend',
                              'sysinv.openstack.common.rpc.impl_fake')
        self.conf.set_default('rpc_backend_zeromq', False)
        self.conf.set_default('rpc_cast_timeout', 5)
        self.conf.set_default('rpc_response_timeout', 5)
        self.conf.set_default('connection', "sqlite://", group='database')
        self.conf.set_default('sqlite_synchronous', False, group='database')
        self.conf.set_default('use_ipv6', True)
        config.parse_args([], default_config_files=[])
        self.addCleanup(self.conf.reset)
