# -*- encoding: utf-8 -*-
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from sysinv.common.fm import get_fm_region
from sysinv.db import api as dbapi
from sysinv.openstack.common import context

FAULT_MANAGEMENT = 'faultmanagement'
REQUIRED_SERVICE_TYPES = (FAULT_MANAGEMENT,)


class RequestContext(context.RequestContext):
    """Extends security contexts from the OpenStack common library."""

    def __init__(self, auth_token=None, domain_id=None, domain_name=None,
                 user=None, tenant=None, is_admin=False, is_public_api=False,
                 project_name=None, read_only=False, show_deleted=False,
                 request_id=None, roles=None, service_catalog=None):
        """Stores several additional request parameters:

        :param domain_id: The ID of the domain.
        :param domain_name: The name of the domain.
        :param is_public_api: Specifies whether the request should be processed
                              without authentication.
        :param project_name: The name of the project.
        :param roles: The list of roles.
        :param service_catalog: Specifies the service_catalog
        """
        self.is_public_api = is_public_api
        self.domain_id = domain_id
        self.domain_name = domain_name
        self.project_name = project_name
        self.roles = roles
        self._session = None

        super(RequestContext, self).__init__(auth_token=auth_token,
                                             user=user, tenant=tenant,
                                             is_admin=is_admin,
                                             read_only=read_only,
                                             show_deleted=show_deleted,
                                             request_id=request_id)
        if service_catalog:
            # Only include required parts of service_catalog
            self.service_catalog = [s for s in service_catalog
                                    if s.get('type', '')
                                    in REQUIRED_SERVICE_TYPES]
            for service in self.service_catalog:
                if service.get('type') == FAULT_MANAGEMENT:
                    if 'endpoints' in service:
                        fm_region = get_fm_region()
                        fm_endpoints = []
                        for endpoint in service['endpoints']:
                            if endpoint.get('region', '') == fm_region:
                                fm_endpoints.append(endpoint)
                        service['endpoints'] = fm_endpoints
        else:
            # if list is empty or none
            self.service_catalog = []

    @property
    def session(self):
        if self._session is None:
            self._session = dbapi.get_instance().get_session(autocommit=True)

        return self._session

    def to_dict(self):
        result = {'domain_id': self.domain_id,
                  'domain_name': self.domain_name,
                  'is_public_api': self.is_public_api,
                  'project_name': self.project_name,
                  'roles': self.roles,
                  'service_catalog': self.service_catalog}

        result.update(super(RequestContext, self).to_dict())

        return result

    @classmethod
    def from_dict(cls, values):
        return cls(**values)
