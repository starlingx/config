#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""Session leak checks for every method of the SQLAlchemy Connection class.

A connection leaks when a query runs on a session that was already closed.
That happens when a nested Connection method call runs its
db_session_cleanup and closes the thread-local session that the outer
method is still using. SQLAlchemy lets a closed session start a new
transaction, which checks out a pool connection that no cleanup ever
returns. Enough of them exhaust the pool with:

    QueuePool limit of size 1 overflow 5 reached, connection timed out

Every Connection method is called with int, string and UUID arguments.
Query execution and session writes are mocked, so no SQL runs and no
data is needed. The test fails if a method:
  - runs a query, flush or session write on a session that is no longer
    in a transaction (closed session reused), or
  - returns with a session still open or with thread-local session
    state left behind.

Detection is deterministic on the first call, so each combination of
arguments is executed once.
"""

import ast
import inspect

import eventlet
from oslo_db.sqlalchemy import enginefacade
from sqlalchemy.orm import Query
from sqlalchemy.orm import Session
from unittest import mock

from sysinv.db.sqlalchemy import api as sa_api
from sysinv.db.sqlalchemy import models
from sysinv.objects import base as objects_base
from sysinv.tests.db import base

TEST_UUID = '1be26c0b-03f2-4d2e-ae87-c02d7f33c123'
TEST_INT = 1
TEST_STR = 'test-name'

# Argument styles, chosen to reach the different branches of
# add_identity_filter() and similar helpers.
ARG_STYLES = {
    'int': TEST_INT,
    'str': TEST_STR,
    'uuid': TEST_UUID,
}

PAGINATION_PARAMS = ('limit', 'marker', 'sort_key', 'sort_dir')
DICT_PARAMS = ('values', 'filters', 'updates')

QUERY_TERMINALS = ('all', 'one', 'first', 'one_or_none', 'count',
                   'delete', 'update', 'get', '__iter__')
# flush is not mocked: SQLAlchemy calls it internally while a session
# autobegins (before in_transaction() is True), and with add/merge/delete
# mocked there is never anything to flush.
SESSION_WRITES = ('add', 'delete', 'merge', 'execute')

CALL_TIMEOUT = 5


class FakeRow(object):
    """Fake query result that never touches the database.

    id-like attributes are ints, uuid-like attributes are UUIDs and every
    other attribute is a MagicMock.
    """

    def __getattr__(self, name):
        if name.startswith('_sa_') or name.startswith('__'):
            raise AttributeError(name)
        if name == 'id' or name.endswith('_id') or name.endswith('id'):
            value = TEST_INT
        elif name == 'uuid' or name.endswith('_uuid'):
            value = TEST_UUID
        else:
            value = mock.MagicMock()
        setattr(self, name, value)
        return value

    def __getitem__(self, key):
        return getattr(self, key)


class StyledDict(dict):
    """Empty dict whose missing keys return the argument style value."""

    def __init__(self, value):
        super(StyledDict, self).__init__()
        self._value = value

    def __missing__(self, key):
        return self._value

    def get(self, key, default=None):
        if key in self:
            return super(StyledDict, self).get(key)
        return self._value


def _model_args_from_callers():
    """Map private helpers taking 'cls'/'obj' to a model their callers use.

    e.g. self._interface_get(models.SriovVFInterfaces, ...) gives
    {'_interface_get': {'cls': models.SriovVFInterfaces}}.
    """
    tree = ast.parse(inspect.getsource(sa_api))
    conn = next(n for n in tree.body
                if isinstance(n, ast.ClassDef) and n.name == 'Connection')
    result = {}
    for caller in conn.body:
        if not isinstance(caller, ast.FunctionDef):
            continue
        assigned = {}
        for node in ast.walk(caller):
            if (isinstance(node, ast.Assign) and
                    isinstance(node.value, ast.Call) and
                    isinstance(node.value.func, ast.Attribute) and
                    isinstance(node.value.func.value, ast.Name) and
                    node.value.func.value.id == 'models'):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        assigned[target.id] = node.value.func.attr
        for node in ast.walk(caller):
            if not (isinstance(node, ast.Call) and
                    isinstance(node.func, ast.Attribute) and
                    isinstance(node.func.value, ast.Name) and
                    node.func.value.id == 'self' and node.args):
                continue
            first = node.args[0]
            if (isinstance(first, ast.Attribute) and
                    isinstance(first.value, ast.Name) and
                    first.value.id == 'models'):
                result.setdefault(node.func.attr, {}).setdefault(
                    'cls', getattr(models, first.attr))
            elif isinstance(first, ast.Name) and first.id in assigned:
                result.setdefault(node.func.attr, {}).setdefault(
                    'obj', getattr(models, assigned[first.id]))
    return result


def _connection_method_names(cls):
    return sorted(name for name in dir(cls)
                  if not name.startswith('__') and
                  callable(getattr(cls, name)) and
                  name != 'get_session')


class SessionLeakTestMixin(object):
    """Mocks DB execution and records session misuse."""

    def setUp(self):
        super(SessionLeakTestMixin, self).setUp()
        self.violations = []
        self.sessions = []

        for name in QUERY_TERMINALS:
            self._patch(Query, name, self._fake_query_terminal(name))
        for name in SESSION_WRITES:
            self._patch(Session, name, self._fake_session_write(name))

        # objectify() converts results into sysinv objects; the fake rows
        # are returned unchanged.
        self._patch(objects_base.SysinvObject, 'from_db_object',
                    classmethod(lambda cls, db_obj: db_obj))

        real_create_session = enginefacade._TransactionFactory._create_session
        test = self

        def create_session(factory, *args, **kwargs):
            session = real_create_session(factory, *args, **kwargs)
            test.sessions.append(session)
            return session

        self._patch(enginefacade._TransactionFactory, '_create_session',
                    create_session)
        self.addCleanup(self._reset_thread_state)

    def _patch(self, target, name, new):
        patcher = mock.patch.object(target, name, new)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _check_session(self, session, operation):
        if not session.in_transaction():
            self.violations.append(
                "%s() executed on a closed session" % operation)

    def _fake_query_terminal(self, name):
        test = self

        def fake(query, *args, **kwargs):
            test._check_session(query.session, 'Query.%s' % name)
            if name == 'all':
                return [FakeRow()]
            if name == '__iter__':
                return iter([FakeRow()])
            if name in ('count', 'delete', 'update'):
                return 1
            return FakeRow()
        return fake

    def _fake_session_write(self, name):
        test = self

        def fake(session, *args, **kwargs):
            test._check_session(session, 'Session.%s' % name)
            if name == 'merge':
                return args[0] if args else FakeRow()
            if name == 'execute':
                return mock.MagicMock()
            return None
        return fake

    def _leftover_state(self):
        problems = []
        context = eventlet.greenthread.getcurrent()
        if getattr(context, '_db_session', None) is not None:
            problems.append("thread-local _db_session left set")
        if getattr(context, '_db_session_context', None) is not None:
            problems.append("thread-local _db_session_context left set")
        tlocal = getattr(context, '_enginefacade_context', None)
        if getattr(tlocal, 'current', None) is not None:
            problems.append("enginefacade transaction context left open")
        open_sessions = [s for s in self.sessions if s.in_transaction()]
        if open_sessions:
            problems.append("%d session(s) left open" % len(open_sessions))
        return problems

    def _reset_thread_state(self):
        context = eventlet.greenthread.getcurrent()
        session_context = getattr(context, '_db_session_context', None)
        if session_context is not None:
            try:
                session_context.__exit__(None, None, None)
            except Exception:
                pass
        context._db_session = None
        context._db_session_context = None
        tlocal = getattr(context, '_enginefacade_context', None)
        if tlocal is not None and getattr(tlocal, 'current', None):
            del tlocal.current
        for session in self.sessions:
            session.close()
        self.sessions = []

    def run_and_check(self, func, kwargs, session_arg=None):
        """Call func once and return a list of session problems."""
        self.violations = []
        self.sessions = []
        try:
            with eventlet.Timeout(CALL_TIMEOUT):
                if session_arg:
                    with sa_api._session_for_write() as session:
                        kwargs[session_arg] = session
                        func(**kwargs)
                else:
                    func(**kwargs)
        except eventlet.Timeout:
            pass
        except Exception:
            # Fake arguments make many calls fail. Exception paths must
            # not leak sessions either, so they are checked the same way.
            pass
        problems = list(self.violations) + self._leftover_state()
        self._reset_thread_state()
        return problems


class TestConnectionSessionLeaks(SessionLeakTestMixin, base.DbTestCase):
    """One generated test per Connection method (see _add_method_tests)."""

    MODEL_ARGS = _model_args_from_callers()

    def _build_kwargs(self, method_name, func, style_value, fill_optional):
        kwargs = {}
        session_arg = None
        model_args = self.MODEL_ARGS.get(method_name, {})
        for param in inspect.signature(func).parameters.values():
            if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
                continue
            required = param.default is param.empty
            if param.name == 'session':
                # Methods with a required session receive the caller's
                # session; optional ones use the thread-local session.
                if required:
                    session_arg = param.name
                continue
            if param.name in PAGINATION_PARAMS:
                kwargs[param.name] = None
            elif not required and not fill_optional:
                continue
            elif param.name == 'cls' and 'cls' in model_args:
                kwargs[param.name] = model_args['cls']
            elif param.name == 'obj' and 'obj' in model_args:
                kwargs[param.name] = model_args['obj']()
            elif param.name in DICT_PARAMS:
                kwargs[param.name] = StyledDict(style_value)
            else:
                kwargs[param.name] = style_value
        return kwargs, session_arg

    def check_method(self, method_name):
        conn = sa_api.Connection()
        func = getattr(conn, method_name)
        failures = []
        for style, style_value in sorted(ARG_STYLES.items()):
            for fill_optional in (False, True):
                kwargs, session_arg = self._build_kwargs(
                    method_name, func, style_value, fill_optional)
                problems = self.run_and_check(func, kwargs, session_arg)
                if problems:
                    failures.append(
                        "args=%s, optional args %s: %s" % (
                            style,
                            'filled' if fill_optional else 'default',
                            '; '.join(sorted(set(problems)))))
        if failures:
            self.fail("Connection.%s mishandles DB sessions:\n  %s" %
                      (method_name, '\n  '.join(failures)))


def _add_method_tests(test_class):
    # This is where every method of the Connection class gets tested:
    # one test_<method> is generated for each method returned by
    # _connection_method_names(), so new methods are covered automatically.
    for method_name in _connection_method_names(sa_api.Connection):
        def test(self, _name=method_name):
            self.check_method(_name)
        test.__name__ = 'test_%s' % method_name
        test.__doc__ = 'Session handling of Connection.%s' % method_name
        setattr(test_class, test.__name__, test)


# Generate the per-method tests for all Connection methods.
_add_method_tests(TestConnectionSessionLeaks)


@sa_api.db_session_cleanup
class _LeakingConnection(sa_api.Connection):
    """Generic examples of session misuse, used to validate the checks."""

    def query_after_nested_call(self, host):
        # The nested Connection call closes the thread-local session that
        # the query built before it depends on.
        query = sa_api.model_query(models.ihost)
        host_obj = self.ihost_get(host)
        query = query.filter_by(id=host_obj.id)
        return query.all()

    def stale_session_after_with_block(self, host):
        with sa_api._session_for_read():
            sa_api.model_query(models.ihost).first()
        return self.ihost_get(host)

    def session_left_open(self, holder):
        # Keep a reference: if the context manager is garbage collected
        # its generator is closed, which closes the session.
        session_context = sa_api._session_for_read()
        session_context.__enter__()
        holder.append(session_context)

    def correct_explicit_session(self, host):
        with sa_api._session_for_read() as session:
            query = sa_api.model_query(models.ihost, session=session)
            host_obj = query.filter_by(uuid=host).one()
            query = sa_api.model_query(models.ihost, session=session)
            return query.filter_by(id=host_obj.id).all()


class TestSessionLeakDetection(SessionLeakTestMixin, base.DbTestCase):
    """Make sure the checks above detect known leak patterns."""

    def setUp(self):
        super(TestSessionLeakDetection, self).setUp()
        self.conn = _LeakingConnection()

    def _problems(self, method_name, **kwargs):
        return self.run_and_check(getattr(self.conn, method_name), kwargs)

    def test_detects_query_after_nested_call(self):
        problems = self._problems('query_after_nested_call', host=TEST_UUID)
        self.assertIn("Query.all() executed on a closed session", problems)

    def test_detects_stale_session_after_with_block(self):
        problems = self._problems('stale_session_after_with_block',
                                  host=TEST_UUID)
        self.assertIn("Query.one() executed on a closed session", problems)

    def test_detects_session_left_open(self):
        holder = []
        problems = self._problems('session_left_open', holder=holder)
        self.assertIn("enginefacade transaction context left open", problems)
        self.assertIn("1 session(s) left open", problems)

    def test_explicit_session_is_clean(self):
        self.assertEqual(
            [], self._problems('correct_explicit_session', host=TEST_UUID))
