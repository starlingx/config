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
# Copyright (c) 2013-2014 Wind River Systems, Inc.
#

import time
import urlparse

from oslo_config import cfg
from pecan import hooks

from sysinv.common import context
from sysinv.common import utils
from sysinv.conductor import rpcapi
from sysinv.db import api as dbapi
from sysinv.openstack.common import policy
from webob import exc

from sysinv.openstack.common import log
import eventlet.semaphore

import re

LOG = log.getLogger(__name__)

audit_log_name = "{}.{}".format(__name__, "auditor")
auditLOG = log.getLogger(audit_log_name)


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

    """
    def __init__(self, public_api_routes):
        self.public_api_routes = public_api_routes
        super(ContextHook, self).__init__()

    def before(self, state):
        user_id = state.request.headers.get('X-User-Id')
        user_id = state.request.headers.get('X-User', user_id)
        tenant = state.request.headers.get('X-Tenant-Id')
        tenant = state.request.headers.get('X-Tenant', tenant)
        domain_id = state.request.headers.get('X-User-Domain-Id')
        domain_name = state.request.headers.get('X-User-Domain-Name')
        auth_token = state.request.headers.get('X-Auth-Token', None)
        creds = {'roles': state.request.headers.get('X-Roles', '').split(',')}

        is_admin = policy.check('admin', state.request.headers, creds)

        utils.safe_rstrip(state.request.path, '/')
        is_public_api = state.request.environ.get('is_public_api', False)

        state.request.context = context.RequestContext(
            auth_token=auth_token,
            user=user_id,
            tenant=tenant,
            domain_id=domain_id,
            domain_name=domain_name,
            is_admin=is_admin,
            is_public_api=is_public_api)


class RPCHook(hooks.PecanHook):
    """Attach the rpcapi object to the request so controllers can get to it."""

    def before(self, state):
        state.request.rpcapi = rpcapi.ConductorAPI()


class AdminAuthHook(hooks.PecanHook):
    """Verify that the user has admin rights.

    Checks whether the request context is an admin context and
    rejects the request otherwise.

    """
    def before(self, state):
        ctx = state.request.context
        is_admin_api = policy.check('admin_api', {}, ctx.to_dict())

        if not is_admin_api and not ctx.is_public_api:
            raise exc.HTTPForbidden()


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


class MutexTransactionHook(hooks.TransactionHook):
    """Custom hook for SysInv transactions.
       Until transaction based database is enabled, this allows setting mutex
       on sysinv REST API update operations.
    """

    SYSINV_API_SEMAPHORE_TIMEOUT = 30

    def __init__(self):
        super(MutexTransactionHook, self).__init__(
            start=self.lock,
            start_ro=self.start_ro,
            commit=self.unlock,
            rollback=self.unlock,
            clear=self.clear)

        self._sysinv_semaphore = eventlet.semaphore.Semaphore(1)
        LOG.info("_sysinv_semaphore %s" % self._sysinv_semaphore)

    def lock(self):
        if not self._sysinv_semaphore.acquire(
           timeout=self.SYSINV_API_SEMAPHORE_TIMEOUT):
            LOG.warn("WAIT Time initial expire SYSINV sema %s" %
                     self.SYSINV_API_SEMAPHORE_TIMEOUT)
            if not self._sysinv_semaphore.acquire(
               timeout=self.SYSINV_API_SEMAPHORE_TIMEOUT):
                LOG.error("WAIT Time expired SYSINV sema %s" %
                          self.SYSINV_API_SEMAPHORE_TIMEOUT)
                raise exc.HTTPConflict()

    def start_ro(self):
        return

    def unlock(self):
        self._sysinv_semaphore.release()
        LOG.debug("unlock SYSINV sema %s" % self._sysinv_semaphore)

    def clear(self):
        return


class AuditLogging(hooks.PecanHook):
    """Performs audit logging of all sysinv ["POST", "PUT","PATCH","DELETE"] REST requests"""

    def __init__(self):
        self.log_methods = ["POST", "PUT", "PATCH", "DELETE"]

    def before(self, state):
        state.request.start_time = time.time()

    def __after(self, state):

        method = state.request.method
        if method not in self.log_methods:
            return

        now = time.time()
        elapsed = now - state.request.start_time

        environ = state.request.environ
        server_protocol = environ["SERVER_PROTOCOL"]

        response_content_length = state.response.content_length

        user_id = state.request.headers.get('X-User-Id')
        user_name = state.request.headers.get('X-User', user_id)
        tenant_id = state.request.headers.get('X-Tenant-Id')
        tenant = state.request.headers.get('X-Tenant', tenant_id)
        domain_name = state.request.headers.get('X-User-Domain-Name')
        request_id = state.request.context.request_id

        url_path = urlparse.urlparse(state.request.path_qs).path

        def json_post_data(rest_state):
            if not hasattr(rest_state.request, 'json'):
                return ""
            return " POST: {}".format(rest_state.request.json)

        # Filter password from log
        filtered_json = re.sub(r'{[^{}]*(passwd_hash|community|password)[^{}]*},*',
                               '',
                               json_post_data(state))

        log_data = "{} \"{} {} {}\" status: {} len: {} time: {}{} host:{} agent:{} user: {} tenant: {} domain: {}".format(
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
