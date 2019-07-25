# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.tests.db import base as dbbase
from sysinv.tests.puppet import base


class PlatformIPv4WorkerHostTestCase(base.PuppetTestCaseMixin,
                                     dbbase.WorkerHostTestCase):

    def test_nfs_proto_version(self):
        self.operator.update_host_config(self.host)
        self.assertConfigParameters(self.mock_write_config, {
            'platform::params::nfs_proto': 'udp'
        })


class PlatformIPv6WorkerHostTestCase(base.PuppetTestCaseMixin,
                                     dbbase.BaseIPv6Mixin,
                                     dbbase.WorkerHostTestCase):

    def test_nfs_proto_version(self):
        self.operator.update_host_config(self.host)
        self.assertConfigParameters(self.mock_write_config, {
            'platform::params::nfs_proto': 'udp6'
        })
