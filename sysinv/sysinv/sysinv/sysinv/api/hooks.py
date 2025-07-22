# -*- encoding: utf-8 -*-
#
# Copyright © 2012 New Dream Network, LLC (DreamHost)
#
# Author: Doug Hellmann <doug.hellmann@dreamhost.com>
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
#
# Copyright (c) 2013-2023 Wind River Systems, Inc.
#

import re
import time
from six.moves.urllib.parse import urlparse
import webob

import numpy as np
from oslo_config import cfg
from oslo_serialization import jsonutils
from oslo_log import log
from oslo_utils import uuidutils
from pecan import hooks

from sysinv._i18n import _
from sysinv.api.policies import base as base_policy
from sysinv.common import context
from sysinv.common import utils
from sysinv.conductor import rpcapiproxy as rpcapi
from sysinv.db import api as dbapi
from sysinv.common import policy
from webob import exc

LOG = log.getLogger(__name__)
NO_SPACE_MSG = "Insufficient space"

audit_log_name = "{}.{}".format(__name__, "auditor")
auditLOG = log.getLogger(audit_log_name)

# Set numpy format for printing bins
np.set_printoptions(formatter={'int': '{: 5d}'.format})


def generate_request_id():
    return 'req-%s' % uuidutils.generate_uuid()


def is_load_import(content_type, url_path):
    if (content_type == "multipart/form-data" and
            url_path == "/v1/loads/import_load"):
        return True
    else:
        return False


class MultiFormDataHook(hooks.PecanHook):
    """For multipart form-data, check disk space available before
    proceeding.

    Currently, it is only applying to import_load request, but
    it can be extended to cover other multipart form-data requests
    """

    def on_route(self, state):
        content_type = state.request.content_type
        url_path = state.request.path
        if is_load_import(content_type, url_path):
            content_length = int(state.request.headers.get('Content-Length'))
            # Currently, the restriction is 2x the file size:
            # 1x from internal webob copy (see before override below)
            # 1x from sysinv temporary copy
            if not utils.is_space_available("/scratch", 2 * content_length):
                msg = _(
                    "%s on /scratch for request %s, "
                    "/scratch must have at least %d bytes of free space! "
                    "You can delete unused files from /scratch or increase the size of it "
                    "with: 'system host-fs-modify <hostname> scratch=<new_size_in_GiB>'"
                ) % (NO_SPACE_MSG, url_path, 2 * content_length)
                raise webob.exc.HTTPInternalServerError(explanation=msg)

    # Note: webob, for the multipart form-data request, creates 2 internal
    # temporary copies, using the before override we can close the second
    # temporary request before request goes to sysinv, this saves 1x file
    # size required
    def before(self, state):
        content_type = state.request.content_type
        url_path = state.request.path
        if is_load_import(content_type, url_path):
            state.request.body_file.close()


class ConfigHook(hooks.PecanHook):
    """Attach the config object to the request so controllers can get to it."""

    def before(self, state):
        state.request.cfg = cfg.CONF


class DBHook(hooks.PecanHook):
    """Attach the dbapi object to the request so controllers can get to it."""

    def before(self, state):
        state.request.dbapi = dbapi.get_instance()


class ContextHook(hooks.PecanHook):
    """Configures a request context and attaches it to the request.

    priority = 120

    The following HTTP request headers are used:

    X-User-Id or X-User:
        Used for context.user_id.

    X-Tenant-Id or X-Tenant:
        Used for context.tenant.

    X-Auth-Token:
        Used for context.auth_token.

    X-Roles:
        Used for setting context.is_admin flag to either True or False.
        The flag is set to True, if X-Roles contains either an administrator
        or admin substring. Otherwise it is set to False.

    X-Service_Catalog:
        Used for context.service_catalog.

    """
    def __init__(self, public_api_routes):
        self.public_api_routes = public_api_routes
        super(ContextHook, self).__init__()

    def before(self, state):
        user_id = state.request.headers.get('X-User-Id')
        user_id = state.request.headers.get('X-User', user_id)
        tenant = state.request.headers.get('X-Tenant-Id')
        tenant = state.request.headers.get('X-Tenant', tenant)
        project_name = state.request.headers.get('X-Project-Name')
        domain_id = state.request.headers.get('X-User-Domain-Id')
        domain_name = state.request.headers.get('X-User-Domain-Name')
        auth_token = state.request.headers.get('X-Auth-Token', None)
        roles = state.request.headers.get('X-Roles', '').split(',')
        catalog_header = state.request.headers.get('X-Service-Catalog')
        service_catalog = None
        if catalog_header:
            try:
                service_catalog = jsonutils.loads(catalog_header)
            except ValueError:
                raise webob.exc.HTTPInternalServerError(
                    _('Invalid service catalog json.'))

        credentials = {
            'project_name': project_name,
            'roles': roles
        }
        is_admin = policy.authorize(base_policy.ADMIN_OR_CONFIGURATOR, {},
            credentials, do_raise=False)

        utils.safe_rstrip(state.request.path, '/')
        is_public_api = state.request.environ.get('is_public_api', False)

        state.request.context = context.RequestContext(
            auth_token=auth_token,
            user=user_id,
            tenant=tenant,
            domain_id=domain_id,
            domain_name=domain_name,
            is_admin=is_admin,
            is_public_api=is_public_api,
            project_name=project_name,
            roles=roles,
            service_catalog=service_catalog
        )


class RPCHook(hooks.PecanHook):
    """Attach the rpcapi object to the request so controllers can get to it."""

    def before(self, state):
        state.request.rpcapi = rpcapi.ConductorAPI()


class AccessPolicyHook(hooks.PecanHook):
    """Verify that the user has the needed credentials to execute the action."""
    def before(self, state):
        context = state.request.context
        if not context.is_public_api:
            controller = state.controller.__self__
            if hasattr(controller, 'enforce_policy'):
                try:
                    controller_method = state.controller.__name__
                    controller.enforce_policy(controller_method, state.request)
                except Exception:
                    raise exc.HTTPForbidden("The requested action is not authorized")
            else:
                method = state.request.method
                if method == 'GET':
                    has_api_access = policy.authorize(
                        base_policy.READER_OR_OPERATOR_OR_CONFIGURATOR, {},
                        context.to_dict(), do_raise=False)
                else:
                    has_api_access = policy.authorize(
                        base_policy.ADMIN_OR_CONFIGURATOR, {},
                        context.to_dict(), do_raise=False)
                if not has_api_access:
                    raise exc.HTTPForbidden("The requested action is not authorized")


class NoExceptionTracebackHook(hooks.PecanHook):
    """Workaround rpc.common: deserialize_remote_exception.

    deserialize_remote_exception builds rpc exception traceback into error
    message which is then sent to the client. Such behavior is a security
    concern so this hook is aimed to cut-off traceback from the error message.

    """
    # NOTE(max_lobur): 'after' hook used instead of 'on_error' because
    # 'on_error' never fired for wsme+pecan pair. wsme @wsexpose decorator
    # catches and handles all the errors, so 'on_error' dedicated for unhandled
    # exceptions never fired.
    def after(self, state):
        # Omit empty body. Some errors may not have body at this level yet.
        if not state.response.body:
            return

        # Do nothing if there is no error.
        if 200 <= state.response.status_int < 400:
            return

        json_body = state.response.json
        # Do not remove traceback when server in debug mode (except 'Server'
        # errors when 'debuginfo' will be used for traces).
        if cfg.CONF.debug and json_body.get('faultcode') != 'Server':
            return

        faultsting = json_body.get('faultstring')
        traceback_marker = 'Traceback (most recent call last):'
        if faultsting and (traceback_marker in faultsting):
            # Cut-off traceback.
            faultsting = faultsting.split(traceback_marker, 1)[0]
            # Remove trailing newlines and spaces if any.
            json_body['faultstring'] = faultsting.rstrip()
            # Replace the whole json. Cannot change original one beacause it's
            # generated on the fly.
            state.response.json = json_body


class AuditLogging(hooks.PecanHook):
    """Performs audit logging of all sysinv ["POST", "PUT","PATCH","DELETE"] REST requests"""

    def __init__(self):
        self.log_methods = ["POST", "PUT", "PATCH", "DELETE"]
        self.histogram_method = {}  # histogram bin counts per method
        self.histogram_url = {}     # histogram bin counts per method/url
        self.histogram_time = time.time()
        self.bin_edges = np.array(
            [0, 5, 25, 50, 100, 200, 400, 600, 800, 1000, 1250, 1500,
             2000, 3000, 4000, 5000, 6000, 8000, 10000, 15000, 20000,
             30000, 45000, 60000],
            dtype=np.float64)

    def before(self, state):
        state.request.start_time = time.time()

    def __after(self, state):

        method = state.request.method
        url_path = urlparse(state.request.path_qs).path
        method_url = str(method) + ' ' + str(url_path)

        now = time.time()
        try:
            elapsed = now - state.request.start_time
        except AttributeError:
            LOG.info("Start time is not in request, setting it to 0.")
            elapsed = 0
        elapsed_ms = 1000.0 * elapsed

        # Print histograms every 5 minutes
        if now - self.histogram_time >= 300:
            print_histogram = True
        else:
            print_histogram = False

        # Cumulate histogram counts all methods combined
        key = 'overall'
        if key not in self.histogram_method:
            self.histogram_method[key] = np.array([], dtype=np.float64)
        self.histogram_method[key] = np.append(
            self.histogram_method[key], elapsed_ms)

        # Cumulate histogram counts per method
        if method not in self.histogram_method:
            self.histogram_method[method] = np.array([], dtype=np.float64)
        self.histogram_method[method] = np.append(
            self.histogram_method[method], elapsed_ms)

        # Cumulate histogram counts per method/url
        if method_url not in self.histogram_url:
            self.histogram_url[method_url] = np.array([], dtype=np.float64)
        self.histogram_url[method_url] = np.append(
                self.histogram_url[method_url], elapsed_ms)

        if print_histogram:
            # Calculate histograms and statistics for each key measurement
            M = {}
            for k, v in self.histogram_method.items():
                M[k] = {}
                M[k]['count'] = self.histogram_method[k].size
                if M[k]['count'] > 0:
                    M[k]['mean'] = np.mean(self.histogram_method[k])
                    M[k]['p95'] = np.percentile(self.histogram_method[k], 95)
                    M[k]['pmax'] = np.max(self.histogram_method[k])
                    M[k]['hist'], _ = np.histogram(
                            self.histogram_method[k], bins=self.bin_edges)
                else:
                    M[k]['mean'] = 0
                    M[k]['p95'] = 0.0
                    M[k]['pmax'] = 0.0
                    M[k]['hist'] = []

            U = {}
            for k, v in self.histogram_url.items():
                U[k] = {}
                U[k]['count'] = self.histogram_url[k].size
                if U[k]['count'] > 0:
                    U[k]['mean'] = np.mean(self.histogram_url[k])
                    U[k]['p95'] = np.percentile(self.histogram_url[k], 95)
                    U[k]['pmax'] = np.max(self.histogram_url[k])
                    U[k]['hist'], _ = np.histogram(
                            self.histogram_url[k], bins=self.bin_edges)
                else:
                    U[k]['mean'] = 0
                    U[k]['p95'] = 0.0
                    U[k]['pmax'] = 0.0
                    U[k]['hist'] = []

            # Print out each histogram sorted by counts
            auditLOG.info("Summary per API Method:")
            bins = ' '.join('{:5d}'.format(int(x)) for x in self.bin_edges[1:])
            auditLOG.info('bins=[%s]' % (bins))
            for k, v in sorted(M.items(), key=lambda t: -float(t[1]['count'])):
                auditLOG.info('hist=%s : cnt: %3d, mean: %5.1f ms, '
                              'p95: %5.1f ms, max: %5.1f ms %s'
                               % (v['hist'], v['count'], v['mean'],
                                  v['p95'], v['pmax'], k))

            auditLOG.info("Summary per API Method/URL:")
            for k, v in sorted(U.items(), key=lambda t: -float(t[1]['count'])):
                auditLOG.info('hist=%s : cnt: %3d, mean: %5.1f ms, '
                              'p95: %5.1f ms, max: %5.1f ms %s'
                              % (v['hist'], v['count'], v['mean'],
                                 v['p95'], v['pmax'], k))

            # Clear histogram for next interval
            self.histogram_method = {}
            self.histogram_url = {}
            self.histogram_time = now

        if method not in self.log_methods:
            return

        environ = state.request.environ
        server_protocol = environ["SERVER_PROTOCOL"]

        response_content_length = state.response.content_length

        user_id = state.request.headers.get('X-User-Id')
        user_name = state.request.headers.get('X-User', user_id)
        tenant_id = state.request.headers.get('X-Tenant-Id')
        tenant = state.request.headers.get('X-Tenant', tenant_id)
        domain_name = state.request.headers.get('X-User-Domain-Name')
        try:
            request_id = state.request.context.request_id
        except AttributeError:
            LOG.info("Request id is not in request, setting it to an "
                     "auto generated id.")
            request_id = generate_request_id()

        def json_post_data(rest_state):
            if 'form-data' in rest_state.request.headers.get('Content-Type'):
                # rest_state.request.params causes an internal webob copy,
                # prevent its call if there is no space available
                size = int(rest_state.request.headers.get('Content-Length'))
                if utils.is_space_available("/scratch", 2 * size):
                    return " POST: {}".format(rest_state.request.params)
                else:
                    return " POST: " + NO_SPACE_MSG + " for processing"
            try:
                if not hasattr(rest_state.request, 'json'):
                    return ""
            except Exception:
                return ""
            return " POST: {}".format(rest_state.request.json)

        # Filter password from log
        filtered_json = re.sub(r'{[^{}]*(passwd_hash|community|password)[^{}]*},*',
                               '',
                               json_post_data(state))

        log_data = "{} \"{} {} {}\" status: {} len: {} time: {}{} host:{}" \
                   " agent:{} user: {} tenant: {} domain: {}".format(
                                                      state.request.remote_addr,
                                                      state.request.method,
                                                      url_path,
                                                      server_protocol,
                                                      state.response.status_int,
                                                      response_content_length,
                                                      elapsed,
                                                      filtered_json,
                                                      state.request.host,
                                                      state.request.user_agent,
                                                      user_name,
                                                      tenant,
                                                      domain_name)

        def cleanup(environ):
            post_vars, body_file = environ['webob._parsed_post_vars']
            # for large post request, the body is also copied to a tempfile by webob
            if not isinstance(body_file, bytes):
                body_file.close()
            for f in post_vars.keys():
                item = post_vars[f]
                if hasattr(item, 'file'):
                    item.file.close()

        if 'webob._parsed_post_vars' in state.request.environ:
            cleanup(state.request.environ)

        # The following ctx object will be output in the logger as
        # something like this:
        # [req-088ed3b6-a2c9-483e-b2ad-f1b2d03e06e6 3d76d3c1376744e8ad9916a6c3be3e5f ca53e70c76d847fd860693f8eb301546]
        # When the ctx is defined, the formatter (defined in common/log.py) requires that keys
        # request_id, user, tenant be defined within the ctx
        ctx = {'request_id': request_id,
               'user': user_id,
               'tenant': tenant_id}

        auditLOG.info("{}".format(log_data), context=ctx)

    def after(self, state):
        # noinspection PyBroadException
        try:
            self.__after(state)
        except Exception:
            # Logging and then swallowing exception to ensure
            # rest service does not fail even if audit logging fails
            auditLOG.exception("Exception in AuditLogging on event 'after'")

    def on_error(self, state, e):
        auditLOG.exception("Exception in AuditLogging passed to event 'on_error': " + str(e))


class DBTransactionHook(hooks.PecanHook):
    """Custom hook for SysInv database transactions.
    """

    priority = 150

    def __init__(self):
        self.transactional_methods = ["POST", "PUT", "PATCH", "DELETE"]
        LOG.info("DBTransactionHook")

    def _cfg(self, f):
        if not hasattr(f, '_pecan'):
            f._pecan = {}
        return f._pecan

    def is_transactional(self, state):
        '''
        Decide if a request should be wrapped in a transaction, based
        upon the state of the request. By default, wraps all but ``GET``
        and ``HEAD`` requests in a transaction, along with respecting
        the ``transactional`` decorator from :mod:pecan.decorators.

        :param state: The Pecan state object for the current request.
        '''

        controller = getattr(state, 'controller', None)
        if controller:
            force_transactional = self._cfg(controller).get('transactional', False)
        else:
            force_transactional = False

        if state.request.method not in ('GET', 'HEAD') or force_transactional:
            return True
        return False

    def on_route(self, state):
        state.request.error = False
        if self.is_transactional(state):
            state.request.transactional = True
            self.start_transaction(state)
        else:
            state.request.transactional = False
            self.start_ro(state)

    def on_error(self, state, e):
        #
        # If we should ignore redirects,
        # (e.g., shouldn't consider them rollback-worthy)
        # don't set `state.request.error = True`.
        #

        LOG.error("DBTransaction on_error state=%s e=%s" % (state, e))
        trans_ignore_redirects = (
            state.request.method not in ('GET', 'HEAD')
        )
        if state.controller is not None:
            trans_ignore_redirects = (
                self._cfg(state.controller).get(
                    'transactional_ignore_redirects',
                    trans_ignore_redirects
                )
            )
        if type(e) is exc.HTTPFound and trans_ignore_redirects is True:
            return
        state.request.error = True

    def before(self, state):
        if self.is_transactional(state) \
                and not getattr(state.request, 'transactional', False):
            self.clear(state)
            state.request.transactional = True
            self.start_transaction(state)

    # NOTE(max_lobur): 'after' hook used instead of 'on_error' because
    # 'on_error' never fired for wsme+pecan pair. wsme @wsexpose decorator
    # catches and handles all the errors, so 'on_error' dedicated for unhandled
    # exceptions never fired.
    def after(self, state):
        # Omit empty body. Some errors may not have body at this level yet.
        method = state.request.method
        if not state.response.body:
            if method in self.transactional_methods:
                self.commit_transaction(state)
            self.clear(state)
            return

        # Do nothing if there is no error.
        if 200 <= state.response.status_int < 400:
            if method in self.transactional_methods:
                self.commit_transaction(state)
            self.clear(state)
            return

        LOG.warn("ROLLBACK after state.response.status=%s " %
                 (state.response.status_int))
        try:
            self.rollback_transaction(state)
        except AttributeError:
            LOG.error("rollback_transaction Attribute error")

        self.clear(state)

    def start_transaction(self, state):
        # session is attached by context when needed
        return

    def start_ro(self, state):
        # session is attached by context when needed
        return

    def commit_transaction(self, state):
        # The autocommit handles the commit
        return

    def rollback_transaction(self, state):
        if (hasattr(state.request.context, 'session') and
           state.request.context.session):
            session = state.request.context.session
            session.rollback()
            LOG.info("rollback_transaction %s" % session)
        return

    def clear(self, state):
        if (hasattr(state.request.context, 'session') and
           state.request.context.session):
            session = state.request.context.session
            session.remove()
        return
