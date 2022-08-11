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

ADMIN_IN_SYSTEM_PROJECTS = 'admin_in_system_projects'
READER_IN_SYSTEM_PROJECTS = 'reader_in_system_projects'


base_rules = [
    policy.RuleDefault(
        name=ADMIN_IN_SYSTEM_PROJECTS,
        check_str='role:admin and (project_name:admin or ' +
                  'project_name:services)',
        description="Base rule.",
    ),
    policy.RuleDefault(
        name=READER_IN_SYSTEM_PROJECTS,
        check_str='role:reader and (project_name:admin or ' +
                  'project_name:services)',
        description="Base rule."
    )
]


def list_rules():
    return base_rules
