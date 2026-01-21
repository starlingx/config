# vim: tabstop=4 shiftwidth=4 softtabstop=4
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

import json
import re

from keystonemiddleware import auth_token
from oslo_log import log

from platform_util.oidc import oidc_utils
from sysinv._i18n import _
from sysinv.common import utils
from sysinv.common import exception

LOG = log.getLogger(__name__)


class OIDCMiddleware(object):
    """A wrapper on Keystone auth_token middleware to support OIDC tokens.

    This middleware performs OIDC token validation and maps OIDC tokens
    to Keystone roles for authorization.

    """
    def __init__(self, app, conf):
        self._sysinv_app = app

        # Initialize OIDC token cache and defaults
        self._oidc_token_cache = {}
        self.default_domain = conf.get('oidc_default_domain', 'Default')
        self.default_project = conf.get('oidc_default_project', 'admin')

    def __call__(self, env, start_response):
        try:
            headers_dict = dict(env.get("headers_raw", []))
        except (TypeError, ValueError):
            headers_dict = {}
        oidc_token = env.get("HTTP_OIDC_TOKEN") or headers_dict.get("OIDC-Token")
        try:
            claims = self._oidc_auth(oidc_token)
            self._inject_oidc_claims(env, claims)
        except exception.NotAuthorized as e:
            msg = _("OIDC Authorization failed: %s") % str(e)
            LOG.error(msg)
            error = {
                "faultcode": "Client",
                "faultstring": msg,
                "debuginfo": None
            }
            response_body = json.dumps({'error_message': json.dumps(error)})
            response_headers = [
                ('Content-Type', 'application/json; charset=utf-8'),
                ('Content-Length', str(len(response_body)))
            ]
            start_response('401 Unauthorized', response_headers)
            return [response_body.encode('utf-8')]

        # call downstream WSGI app
        return self._sysinv_app(env, start_response)

    def _inject_oidc_claims(self, env, claims):
        """Inject OIDC claims into request environment."""
        env['HTTP_X_ROLES'] = ','.join(claims.get('roles', []))
        env['HTTP_X_USER_NAME'] = claims.get('username', '')
        env['HTTP_X_PROJECT_NAME'] = self.default_project

    def _oidc_auth(self, oidc_token):
        """Perform OIDC authentication and return claims."""
        if not oidc_token:
            msg = _('Missing OIDC token in the request')
            raise exception.NotAuthorized(message=msg)

        try:
            oidc_claims = oidc_utils.get_oidc_token_claims(
                oidc_token, self._oidc_token_cache)

            return oidc_utils.parse_oidc_token_claims(
                oidc_claims, self.default_domain, self.default_project)
        except Exception as e:
            raise exception.NotAuthorized(message=str(e))


class AuthTokenMiddleware(auth_token.AuthProtocol):
    """A wrapper on Keystone auth_token middleware.

    Does not perform verification of authentication tokens
    for public routes in the API.

    """
    def __init__(self, app, conf, public_api_routes=None):
        self._sysinv_app = app
        route_pattern_tpl = '%s(\.json|\.xml)?$'
        if public_api_routes is None:
            public_api_routes = []

        try:
            self.public_api_routes = [re.compile(route_pattern_tpl % route_tpl)
                                      for route_tpl in public_api_routes]
        except re.error as e:
            msg = _('Cannot compile public API routes: %s') % e

            LOG.error(msg)
            raise exception.ConfigInvalid(error_msg=msg)

        self.oidc_middleware = OIDCMiddleware(app, conf)
        super(AuthTokenMiddleware, self).__init__(app, conf)

    def __call__(self, env, start_response):
        path = utils.safe_rstrip(env.get('PATH_INFO'), '/')

        # The information whether the API call is being performed against the
        # public API is required for some other components. Saving it to the
        # WSGI environment is reasonable thereby.
        env['is_public_api'] = any([re.match(pattern, path) for pattern in self.public_api_routes])

        if env['is_public_api']:
            LOG.debug("Found match request")
            return self._sysinv_app(env, start_response)

        try:
            headers_dict = dict(env.get("headers_raw", []))
        except (TypeError, ValueError):
            headers_dict = {}
        keystone_token = env.get("HTTP_X_AUTH_TOKEN") or headers_dict.get("X-Auth-Token")
        if not keystone_token:
            LOG.debug("No Keystone token in request, using OIDC for authorization")
            return self.oidc_middleware(env, start_response)

        return super(AuthTokenMiddleware, self).__call__(env, start_response)  # pylint: disable=too-many-function-args
