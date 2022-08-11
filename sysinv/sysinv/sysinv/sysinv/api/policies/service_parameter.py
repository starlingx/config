# Copyright (c) 2022 Wind River Systems, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# SPDX-License-Identifier: Apache-2.0

from oslo_policy import policy
from sysinv.api.policies import base

POLICY_ROOT = 'config_api:service_parameter:%s'


service_parameter_rules = [
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'add',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Add a Service Parameter.",
        operations=[
            {
                'method': 'POST',
                'path': '/v1/service_parameter'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'apply',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Apply Service Parameters.",
        operations=[
            {
                'method': 'POST',
                'path': '/v1/service_parameter/apply'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'delete',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Delete a Service Parameter.",
        operations=[
            {
                'method': 'DELETE',
                'path': '/v1/service_parameter/{parameter_id}'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'get',
        check_str='rule:' + base.READER_IN_SYSTEM_PROJECTS,
        description="Get Service Parameters.",
        operations=[
            {
                'method': 'GET',
                'path': '/v1/service_parameter'
            },
            {
                'method': 'GET',
                'path': '/v1/service_parameter/{parameter_id}'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'modify',
        check_str='rule:' + base.ADMIN_IN_SYSTEM_PROJECTS,
        description="Modify Service Parameter value.",
        operations=[
            {
                'method': 'PATCH',
                'path': '/v1/service_parameter/{parameter_id}'
            }
        ]
    )
]


def list_rules():
    return service_parameter_rules
