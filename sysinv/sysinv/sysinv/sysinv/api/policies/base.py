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

ADMIN = 'admin'
ADMIN_OR_CONFIGURATOR = 'admin_or_configurator'
READER_OR_OPERATOR_OR_CONFIGURATOR = 'reader_or_operator_or_configurator'
ADMIN_OR_OPERATOR_OR_CONFIGURATOR = 'admin_or_operator_or_configurator'

base_rules = [
    policy.RuleDefault(
        name=ADMIN,
        check_str='role:admin and (project_name:admin or ' +
                  'project_name:services)',
        description='admin role of admin,services projects',
    ),
    policy.RuleDefault(
        name=ADMIN_OR_CONFIGURATOR,
        check_str='(role:admin or role:configurator) and ' +
                  '(project_name:admin or project_name:services)',
        description='admin,configurator roles of admin,services ' +
                    'projects',
    ),
    policy.RuleDefault(
        name=ADMIN_OR_OPERATOR_OR_CONFIGURATOR,
        check_str='(role:admin or role:operator or role:configurator) and ' +
                  '(project_name:admin or project_name:services)',
        description='admin,operator,configurator roles of admin,services ' +
                    'projects',
    ),
    policy.RuleDefault(
        name=READER_OR_OPERATOR_OR_CONFIGURATOR,
        check_str='(role:reader or role:operator or role:configurator) and ' +
                  '(project_name:admin or project_name:services)',
        description='reader,operator,configurator roles of admin,services ' +
                    'projects',
    )
]


def list_rules():
    return base_rules
