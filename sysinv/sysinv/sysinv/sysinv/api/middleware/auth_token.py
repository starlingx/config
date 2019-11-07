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
from sysinv._i18n import _
from sysinv.common import utils
from sysinv.common import exception

LOG = log.getLogger(__name__)


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

        response = super(AuthTokenMiddleware, self).__call__(env, start_response)

        # The response could have error code 401 (unauthorized) for two cases:
        # First case is that the token (user token) of the request is invalid.
        # Second case is that sysinv's own token is invalid for reason such as
        # its user ID or project ID or assignment changed, where keystone will
        # return 404 but keystonemiddleware converts it into 401 as well. There
        # is no obvious way to distinguish these two cases outside of
        # keystonemiddleware, so here we setup sysinv to re-authenticate against
        # keystone to get a new token for its own and retry the request as long
        # as the response is errored with 401.
        try:
            resp_m = json.loads(response[0])
        except Exception as e:
            LOG.debug("Request response is not in json format: %s" % e)
            pass
        else:
            k_error = 'error'
            k_code = 'code'
            if (k_error in resp_m) and (k_code in resp_m[k_error]) and \
                    (resp_m[k_error][k_code] == 401) and \
                            'HTTP_X_AUTH_TOKEN' in env:
                # Need to clear the cached value for this token since it
                # is marked as invalid in the cache in the previous process.
                user_token = env['HTTP_X_AUTH_TOKEN']
                token_hashes = self._token_hashes(user_token)
                self._token_cache.set(token_hashes[0], None)

                # Sysinv re-authenticate against keystone to get a new token
                # for itself.
                self._auth = self._create_auth_plugin()
                self._session = self._create_session()
                self._identity_server = self._create_identity_server()

                # Retry and retry only once of the request from client.
                response = super(AuthTokenMiddleware, self).__call__(env, start_response)
        return response
