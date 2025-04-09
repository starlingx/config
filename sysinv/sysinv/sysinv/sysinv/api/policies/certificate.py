# Copyright (c) 2025 Wind River Systems, Inc.
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

POLICY_ROOT = 'config_api:certificate:%s'


certificate_rules = [
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'get',
        check_str='rule:' + base.READER_OR_OPERATOR_OR_CONFIGURATOR,
        description="Get certificate",
        operations=[
            {
                'method': 'GET',
                'path': '/v1/certificate'
            },
            {
                'method': 'GET',
                'path': '/v1/certificate/{parameter_id}'
            },
            {
                'method': 'GET',
                'path': '/v1/certificate/get_all_certs'
            },
            {
                'method': 'GET',
                'path': '/v1/certificate/get_all_k8s_certs'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'delete',
        check_str='rule:' + base.ADMIN,
        description="Delete certificate",
        operations=[
            {
                'method': 'DELETE',
                'path': '/v1/certificate/{parameter_id}'
            }
        ]
    ),
    policy.DocumentedRuleDefault(
        name=POLICY_ROOT % 'post',
        check_str='rule:' + base.ADMIN,
        description="install/renew certificate",
        operations=[
            {
                'method': 'POST',
                'path': '/v1/certificate/certificate_install'
            },
            {
                'method': 'POST',
                'path': '/v1/certificate/certificate_renew'
            },
        ]
    ),
]


def list_rules():
    return certificate_rules
