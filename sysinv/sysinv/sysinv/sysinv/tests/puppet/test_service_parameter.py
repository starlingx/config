# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import json

from sysinv.tests.db import base as dbbase
from sysinv.tests.db import utils as dbutils
from sysinv.tests.puppet import base
from sysinv.common import constants


class ServiceParameterTestCaseSysctl(base.PuppetTestCaseMixin,
                                     dbbase.AIODuplexSystemTestCase):

    def setUp(self):
        super(ServiceParameterTestCaseSysctl, self).setUp()

    def test_valid_sysctl_service_parameters(self):
        sysctl_kernel_parameters = {
            "abi.vsyscall32": "1",
            "debug.exception-trace": "1",
            "fs.epoll.max_user_watches": "29259397",
            "kernel.bpf_stats_enabled": "0",
            "kernel.panic_on_rcu_stall": "0",
            "kernel.sched_rt_period_us": " 1000000",
            "kernel.sched_rt_runtime_us": "950000",
            "net.core.bpf_jit_enable": "1",
            "net.ipv4.conf.all.forwarding": "1",
            "user.max_inotify_instances": "128",
            "vm.dirty_ratio": "20",
            "vm.swappiness": "60",
        }
        json_str = json.dumps(sysctl_kernel_parameters)
        for parm, value in sysctl_kernel_parameters.items():
            service_parameter = \
                {
                    'service': constants.SERVICE_TYPE_PLATFORM,
                    'section': constants.SERVICE_PARAM_SECTION_PLATFORM_SYSCTL,
                    'name': parm,
                    'value': value
                }
            dbutils.create_test_service_parameter(**service_parameter)
        self.operator.update_system_config()
        self.assertConfigParameters(
            self.mock_write_config,
            {
                "platform::sysctl::params::json_string": json_str
            }
        )
