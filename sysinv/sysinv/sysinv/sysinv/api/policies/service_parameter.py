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

from sysinv.api.policies import base

POLICY_ROOT = 'config_api:service_parameter:%s'


service_parameter_rules = [
    base.RuleDefault(
        name=POLICY_ROOT % 'add',
        check_str=base.ADMIN_IN_SPECIFIC_PROJECT,
        description="Add a Service Parameter.",
    ),
    base.RuleDefault(
        name=POLICY_ROOT % 'apply',
        check_str=base.ADMIN_IN_SPECIFIC_PROJECT,
        description="Apply Service Parameters.",
    ),
    base.RuleDefault(
        name=POLICY_ROOT % 'delete',
        check_str=base.ADMIN_IN_SPECIFIC_PROJECT,
        description="Delete a Service Parameter.",
    ),
    base.RuleDefault(
        name=POLICY_ROOT % 'get',
        check_str=base.READER_IN_SPECIFIC_PROJECT,
        description="Get Service Parameters.",
    ),
    base.RuleDefault(
        name=POLICY_ROOT % 'modify',
        check_str=base.ADMIN_IN_SPECIFIC_PROJECT,
        description="Modify Service Parameter value.",
    )
]


def list_rules():
    return service_parameter_rules
