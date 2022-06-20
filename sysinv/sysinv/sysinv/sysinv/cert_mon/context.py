# Copyright (c) 2020, 2022 Wind River Systems, Inc.
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

import pecan
from pecan import hooks

from oslo_context import context as base_context
from oslo_utils import encodeutils

from sysinv.common import policy

ALLOWED_WITHOUT_AUTH = '/'


class RequestContext(base_context.RequestContext):
    """Stores information about the security context.

    The context encapsulates information related to the user accessing the
    the system, as well as additional request information.
    """

    def __init__(self, auth_token=None, user=None, project=None,
                 domain=None, user_domain=None, project_domain=None,
                 is_admin=None, read_only=False, show_deleted=False,
                 request_id=None, auth_url=None, trusts=None,
                 user_name=None, project_name=None, domain_name=None,
                 user_domain_name=None, project_domain_name=None,
                 auth_token_info=None, region_name=None, roles=None,
                 password=None, **kwargs):

        """Initializer of request context."""
        # We still have 'tenant' param because oslo_context still use it.
        super(RequestContext, self).__init__(
            auth_token=auth_token, user=user, tenant=project,
            domain=domain, user_domain=user_domain,
            project_domain=project_domain, roles=roles,
            read_only=read_only, show_deleted=show_deleted,
            request_id=request_id)

        # request_id might be a byte array
        self.request_id = encodeutils.safe_decode(self.request_id)

        # we save an additional 'project' internally for use
        self.project = project

        # Session for DB access
        self._session = None

        self.auth_url = auth_url
        self.trusts = trusts

        self.user_name = user_name
        self.project_name = project_name
        self.domain_name = domain_name
        self.user_domain_name = user_domain_name
        self.project_domain_name = project_domain_name

        self.auth_token_info = auth_token_info
        self.region_name = region_name
        self.roles = roles or []
        self.password = password

        # Check user is admin or not
        if is_admin is None:
            self.is_admin = policy.enforce(self, 'context_is_admin',
                                           target={'project': self.project},
                                           do_raise=False)
        else:
            self.is_admin = is_admin

    def to_dict(self):
        return {
            'auth_url': self.auth_url,
            'auth_token': self.auth_token,
            'auth_token_info': self.auth_token_info,
            'user': self.user,
            'user_name': self.user_name,
            'user_domain': self.user_domain,
            'user_domain_name': self.user_domain_name,
            'project': self.project,
            'project_name': self.project_name,
            'project_domain': self.project_domain,
            'project_domain_name': self.project_domain_name,
            'domain': self.domain,
            'domain_name': self.domain_name,
            'trusts': self.trusts,
            'region_name': self.region_name,
            'roles': self.roles,
            'show_deleted': self.show_deleted,
            'is_admin': self.is_admin,
            'request_id': self.request_id,
            'password': self.password,
        }

    @classmethod
    def from_dict(cls, values):
        return cls(**values)


def get_admin_context(show_deleted=False):
    return RequestContext(is_admin=True, show_deleted=show_deleted)


def get_service_context(**args):
    """An abstraction layer for getting service context.

    There could be multiple cloud backends for cert-mon to use. This
    abstraction layer provides an indirection for cert-mon to get the
    credentials of 'dcmanager' user on the specific cloud. By default,
    this credential refers to the credentials built for dcmanager middleware
    in an OpenStack cloud.
    """
    pass


class AuthHook(hooks.PecanHook):
    def before(self, state):
        if state.request.path == ALLOWED_WITHOUT_AUTH:
            return
        req = state.request
        identity_status = req.headers.get('X-Identity-Status')
        service_identity_status = req.headers.get('X-Service-Identity-Status')
        if (identity_status == 'Confirmed' or
                service_identity_status == 'Confirmed'):
            return
        if req.headers.get('X-Auth-Token'):
            msg = 'Auth token is invalid: %s' % req.headers['X-Auth-Token']
        else:
            msg = 'Authentication required'
        msg = "Failed to validate access token: %s" % str(msg)
        pecan.abort(status_code=401, detail=msg)
