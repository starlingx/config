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

ADMIN_PROJECT_NAME = 'admin'
ADMIN_IN_SPECIFIC_PROJECT = 'rule:admin_in_specific_project'
READER_IN_SPECIFIC_PROJECT = 'rule:reader_in_specific_project'


class RuleDefault(object):
    """Class used to represent a policy rule.

    :param name: The name of the policy.
    :param check_str: The string that represents the policy.
    :param description: A brief description of the policy.
    """
    def __init__(self, name, check_str, description):
        self.name = name
        self.check_str = check_str
        self.description = description


base_rules = [
    RuleDefault(
        name='admin',
        check_str='role:admin or role:administrator',
        description="Base rule.",
    ),
    RuleDefault(
        name='admin_api',
        check_str='is_admin:True',
        description="Base rule.",
    ),
    RuleDefault(
        name='default',
        check_str='rule:admin_api',
        description="Base rule.",
    ),
    RuleDefault(
        name='admin_in_specific_project',
        check_str='role:admin and project_name:%(project_name)s',
        description="Base rule.",
    ),
    RuleDefault(
        name='reader_in_specific_project',
        check_str='role:reader and project_name:%(project_name)s',
        description="Base rule.",
    )
]


def list_rules():
    return base_rules
