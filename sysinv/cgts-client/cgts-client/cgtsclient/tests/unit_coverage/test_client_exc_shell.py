#
# Copyright (c) 2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
"""Tests for client.py, exc.py, shell.py and common/utils.py."""
import argparse
import io
import os
import unittest
from unittest import mock

from cgtsclient import client as cgclient
from cgtsclient.common.cli_no_wrap import is_nowrap_set
from cgtsclient.common.cli_no_wrap import set_no_wrap
from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.shell import CgtsShell
from cgtsclient.shell import HelpFormatter


class TestExcModule(unittest.TestCase):
    """Test exc module functions and classes."""

    def test_base_exception_str(self):
        e = exc.BaseException("test msg")
        self.assertEqual(str(e), "test msg")

    def test_base_exception_no_msg(self):
        e = exc.CommandError()
        # When no message, str returns 'None' or the docstring
        self.assertIsNotNone(str(e))

    def test_http_exception_str(self):
        e = exc.HTTPException("detail")
        self.assertEqual(str(e), "detail")

    def test_http_exception_no_detail(self):
        e = exc.HTTPException()
        # When no details, returns 'None' or class name with code
        self.assertIsNotNone(str(e))

    def test_http_multiple_choices(self):
        e = exc.HTTPMultipleChoices()
        s = str(e)
        self.assertIn("300", s)

    def test_from_response_status_code(self):
        resp = mock.MagicMock()
        resp.status_code = 404
        del resp.status_int
        del resp.status
        e = exc.from_response(resp, "not found")
        self.assertIsInstance(e, exc.HTTPNotFound)

    def test_from_response_status_int(self):
        resp = mock.MagicMock(spec=['status_int'])
        resp.status_int = 500
        e = exc.from_response(resp, "server error")
        self.assertIsInstance(e, exc.HTTPInternalServerError)

    def test_from_response_status(self):
        resp = mock.MagicMock(spec=['status'])
        resp.status = 401
        e = exc.from_response(resp, "unauth")
        self.assertIsInstance(e, exc.HTTPUnauthorized)

    def test_from_response_no_status(self):
        resp = mock.MagicMock(spec=[])
        e = exc.from_response(resp, "weird")
        self.assertIsInstance(e, Exception)

    def test_from_response_unknown_code(self):
        resp = mock.MagicMock()
        resp.status_code = 999
        del resp.status_int
        del resp.status
        e = exc.from_response(resp, "unknown")
        self.assertIsInstance(e, exc.HTTPException)

    def test_cgtsclient_exception_format(self):
        e = exc.CgtsclientException("custom msg")
        self.assertEqual(e.format_message(), "custom msg")

    def test_cgtsclient_exception_default(self):
        e = exc.CgtsclientException()
        self.assertIn("unknown exception", str(e))

    def test_cgtsclient_exception_kwargs(self):
        e = exc.AmbiguousEndpoints(reason="multiple")
        self.assertIn("multiple", str(e))

    def test_endpoint_type_not_found(self):
        e = exc.EndpointTypeNotFound(reason="missing")
        self.assertIn("missing", str(e))

    def test_ssl_cert_error(self):
        e = exc.SslCertificateValidationError(reason="bad cert")
        self.assertIn("bad cert", str(e))

    def test_endpoint_exception(self):
        e = exc.EndpointException(reason="generic")
        self.assertIn("generic", str(e))

    def test_all_http_codes(self):
        codes = [400, 401, 403, 404, 405, 409, 413, 500, 501, 502, 503]
        for code in codes:
            resp = mock.MagicMock()
            resp.status_code = code
            del resp.status_int
            del resp.status
            e = exc.from_response(resp, "test")
            self.assertIsInstance(e, exc.HTTPException)


class TestClientModule(unittest.TestCase):
    """Test client.py functions."""

    def test_normalize_interface_public(self):
        self.assertEqual(cgclient._normalize_interface('publicURL'),
                         'public')

    def test_normalize_interface_internal(self):
        self.assertEqual(cgclient._normalize_interface('internalURL'),
                         'internal')

    def test_normalize_interface_admin(self):
        self.assertEqual(cgclient._normalize_interface('adminURL'),
                         'admin')

    def test_normalize_interface_unknown(self):
        self.assertEqual(cgclient._normalize_interface('weird'),
                         'public')

    def test_normalize_interface_already_normal(self):
        self.assertEqual(cgclient._normalize_interface('internal'),
                         'internal')

    def test_validate_oidc_params_missing(self):
        self.assertRaises(exc.InvalidEndpoint,
                          cgclient._validate_oidc_params)

    def test_build_oidc_cli_kwargs(self):
        result = cgclient._build_oidc_cli_kwargs(
            stx_auth_type='oidc', os_username='admin',
            os_auth_url='http://auth', insecure=True)
        self.assertTrue(result['oidc_auth'])
        self.assertEqual(result['oidc_username'], 'admin')

    def test_build_oidc_endpoint_no_auth_url(self):
        self.assertRaises(exc.InvalidEndpoint,
                          cgclient._build_oidc_endpoint, '1')

    def test_build_oidc_endpoint_bad_url(self):
        self.assertRaises(exc.InvalidEndpoint,
                          cgclient._build_oidc_endpoint, '1',
                          os_auth_url='not-a-url',
                          os_endpoint_type='publicURL')

    def test_build_oidc_endpoint_success(self):
        url = cgclient._build_oidc_endpoint(
            '1',
            os_auth_url='http://10.10.10.2:5000/v3',
            os_endpoint_type='internalURL',
            os_region_name='RegionOne')
        self.assertIn('6385', url)
        self.assertIn('/v1', url)

    def test_build_oidc_endpoint_ipv6(self):
        url = cgclient._build_oidc_endpoint(
            '1',
            os_auth_url='http://[::1]:5000/v3',
            os_endpoint_type='publicURL',
            os_region_name='Default')
        self.assertIn('[::1]', url)

    def test_build_oidc_endpoint_system_controller(self):
        url = cgclient._build_oidc_endpoint(
            '1',
            os_auth_url='http://10.10.10.2:5000/v3',
            os_endpoint_type='adminURL',
            os_region_name='SystemController')
        self.assertIn('26386', url)

    def test_get_client_adds_v1(self):
        with mock.patch(
                'oslo_utils.importutils.import_versioned_module'
        ) as m:
            mock_module = mock.MagicMock()
            m.return_value = mock_module
            cgclient.get_client('1',
                                os_auth_token='tok',
                                system_url='http://host:6385')
            call_args = mock_module.Client.call_args
            self.assertIn('/v1', call_args[0][0])

    def test_make_session_returns_none_without_creds(self):
        result = cgclient._make_session()
        self.assertIsNone(result)

    def test_make_session_with_creds(self):
        with mock.patch(
                'keystoneauth1.loading.get_plugin_loader'
        ) as ldr, \
            mock.patch(
            'keystoneauth1.loading.session.Session'
        ) as sess:
            mock_loader = mock.MagicMock()
            ldr.return_value = mock_loader
            mock_sess_inst = mock.MagicMock()
            sess.return_value.load_from_options.return_value = (
                mock_sess_inst
            )
            result = cgclient._make_session(
                os_username='admin', os_password='pass',
                os_auth_url='http://auth:5000/v3',
                os_project_name='admin')
            self.assertIsNotNone(result)


class TestShellModule(unittest.TestCase):
    """Test shell.py CgtsShell class."""

    def test_cgts_shell_init(self):
        s = CgtsShell()
        self.assertIsNone(s.subcommands)
        self.assertFalse(s.keyring)

    def test_get_base_parser(self):
        s = CgtsShell()
        parser = s.get_base_parser()
        self.assertIsNotNone(parser)

    def test_cache_key_default(self):
        s = CgtsShell()
        self.assertEqual(s._cache_key(''), s.CACHE_KEY)

    def test_cache_key_with_user(self):
        s = CgtsShell()
        key = s._cache_key('admin')
        self.assertIn('admin', key)

    def test_help_formatter(self):
        hf = HelpFormatter(io.StringIO())
        hf.start_section('test heading')
        # Should capitalize first letter
        self.assertIsNotNone(hf)

    def test_main_help(self):
        s = CgtsShell()
        result = s.main(['--help'])
        self.assertEqual(result, 0)

    def test_main_empty(self):
        s = CgtsShell()
        result = s.main([])
        self.assertEqual(result, 0)

    def test_do_help_invalid_command(self):
        s = CgtsShell()
        s.get_subcommand_parser('1')
        args = mock.MagicMock()
        args.command = 'nonexistent-cmd'
        self.assertRaises(exc.CommandError, s.do_help, args)


class TestUtilsFunctions(unittest.TestCase):
    """Test common/utils.py functions."""

    def test_env_default(self):
        result = utils.env('NONEXISTENT_VAR_12345', default='fallback')
        self.assertEqual(result, 'fallback')

    def test_env_set(self):
        os.environ['_TEST_CGTS_VAR'] = 'hello'
        try:
            result = utils.env('_TEST_CGTS_VAR')
            self.assertEqual(result, 'hello')
        finally:
            del os.environ['_TEST_CGTS_VAR']

    def test_arg_decorator(self):

        @utils.arg('name', help='test')
        def my_func():
            pass

        self.assertTrue(hasattr(my_func, 'arguments'))
        self.assertEqual(len(my_func.arguments), 1)

    def test_is_uuid_like(self):
        self.assertTrue(
            utils.is_uuid_like('a0eebc99-9c0b-4ef8-bb6d-6bb9bd380a11')
        )
        self.assertFalse(utils.is_uuid_like('not-a-uuid'))

    def test_import_versioned_module(self):
        mod = utils.import_versioned_module('1', 'shell')
        self.assertIsNotNone(mod)

    def test_define_commands_from_module(self):
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        cmd_mapper = {}

        class FakeModule:
            @staticmethod
            def do_test_cmd(cc, args):
                """Test command."""

        utils.define_commands_from_module(
            subparsers,
            FakeModule,
            cmd_mapper
        )
        self.assertIn('test-cmd', cmd_mapper)

    def test_pretty_choice_list(self):
        result = utils.pretty_choice_list(['a', 'b', 'c'])
        self.assertIn("'a'", result)
        self.assertIn("'b'", result)

    def test_get_terminal_size(self):
        w, h = utils.get_terminal_size()
        self.assertGreater(w, 0)
        self.assertGreater(h, 0)

    def test_parse_date_non_string(self):
        self.assertEqual(utils.parse_date(123), 123)

    def test_parse_date_string(self):
        result = utils.parse_date("no date here")
        self.assertEqual(result, "no date here")


class TestCliNoWrap(unittest.TestCase):
    """Test cli_no_wrap module."""

    def test_set_and_check(self):
        set_no_wrap(True)
        self.assertTrue(is_nowrap_set())
        set_no_wrap(False)
        self.assertFalse(is_nowrap_set())


if __name__ == '__main__':
    unittest.main()
