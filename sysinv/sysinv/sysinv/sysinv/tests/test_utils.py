

# Copyright 2011 Justin Santa Barbara
# Copyright 2012 Hewlett-Packard Development Company, L.P.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import errno
import mock
import os
import os.path
import tempfile
import wsme

import netaddr
from oslo_config import cfg

from mox3 import mox
from six.moves import builtins
from sysinv.common import exception
from sysinv.common import service_parameter
from sysinv.common import utils
from sysinv.tests import base

CONF = cfg.CONF


class BareMetalUtilsTestCase(base.TestCase):

    def test_random_alnum(self):
        s = utils.random_alnum(10)
        self.assertEqual(len(s), 10)
        s = utils.random_alnum(100)
        self.assertEqual(len(s), 100)

    def test_unlink(self):
        self.mox.StubOutWithMock(os, "unlink")
        os.unlink("/fake/path")

        self.mox.ReplayAll()
        utils.unlink_without_raise("/fake/path")
        self.mox.UnsetStubs()
        self.mox.VerifyAll()

    def test_unlink_ENOENT(self):
        self.mox.StubOutWithMock(os, "unlink")
        os.unlink("/fake/path").AndRaise(OSError(errno.ENOENT))

        self.mox.ReplayAll()
        utils.unlink_without_raise("/fake/path")
        self.mox.UnsetStubs()
        self.mox.VerifyAll()

    def test_create_link(self):
        self.mox.StubOutWithMock(os, "symlink")
        os.symlink("/fake/source", "/fake/link")

        self.mox.ReplayAll()
        utils.create_link_without_raise("/fake/source", "/fake/link")
        self.mox.VerifyAll()

    def test_create_link_EEXIST(self):
        self.mox.StubOutWithMock(os, "symlink")
        os.symlink("/fake/source", "/fake/link").AndRaise(
                OSError(errno.EEXIST))

        self.mox.ReplayAll()
        utils.create_link_without_raise("/fake/source", "/fake/link")
        self.mox.VerifyAll()


class ExecuteTestCase(base.TestCase):

    def test_retry_on_failure(self):
        fd, tmpfilename = tempfile.mkstemp()
        _, tmpfilename2 = tempfile.mkstemp()
        try:
            fp = os.fdopen(fd, 'w+')
            fp.write('''#!/bin/sh
# If stdin fails to get passed during one of the runs, make a note.
if ! grep -q foo
then
    echo 'failure' > "$1"
fi
# If stdin has failed to get passed during this or a previous run, exit early.
if grep failure "$1"
then
    exit 1
fi
runs="$(cat $1)"
if [ -z "$runs" ]
then
    runs=0
fi
runs=$(($runs + 1))
echo $runs > "$1"
exit 1
''')
            fp.close()
            os.chmod(tmpfilename, 0o755)
            self.assertRaises(exception.ProcessExecutionError,
                              utils.execute,
                              tmpfilename, tmpfilename2, attempts=10,
                              process_input='foo'.encode('utf-8'),
                              delay_on_retry=False)
            fp = open(tmpfilename2, 'r')
            runs = fp.read()
            fp.close()
            self.assertNotEqual(runs.strip(), 'failure', 'stdin did not '
                                                          'always get passed '
                                                          'correctly')
            runs = int(runs.strip())
            self.assertEqual(runs, 10,
                              'Ran %d times instead of 10.' % (runs,))
        finally:
            os.unlink(tmpfilename)
            os.unlink(tmpfilename2)

    def test_unknown_kwargs_raises_error(self):
        self.assertRaises(exception.SysinvException,
                          utils.execute,
                          '/usr/bin/env', 'true',
                          this_is_not_a_valid_kwarg=True)

    def test_check_exit_code_boolean(self):
        utils.execute('/usr/bin/env', 'false', check_exit_code=False)
        self.assertRaises(exception.ProcessExecutionError,
                          utils.execute,
                          '/usr/bin/env', 'false', check_exit_code=True)

    def test_no_retry_on_success(self):
        fd, tmpfilename = tempfile.mkstemp()
        _, tmpfilename2 = tempfile.mkstemp()
        try:
            fp = os.fdopen(fd, 'w+')
            fp.write('''#!/bin/sh
# If we've already run, bail out.
grep -q foo "$1" && exit 1
# Mark that we've run before.
echo foo > "$1"
# Check that stdin gets passed correctly.
grep foo
''')
            fp.close()
            os.chmod(tmpfilename, 0o755)
            utils.execute(tmpfilename,
                          tmpfilename2,
                          process_input='foo'.encode('utf-8'),
                          attempts=2)
        finally:
            os.unlink(tmpfilename)
            os.unlink(tmpfilename2)


class GenericUtilsTestCase(base.TestCase):
    def test_hostname_unicode_sanitization(self):
        hostname = u"\u7684.test.example.com"
        self.assertEqual("test.example.com",
                         utils.sanitize_hostname(hostname))

    def test_hostname_sanitize_periods(self):
        hostname = "....test.example.com..."
        self.assertEqual("test.example.com",
                         utils.sanitize_hostname(hostname))

    def test_hostname_sanitize_dashes(self):
        hostname = "----test.example.com---"
        self.assertEqual("test.example.com",
                         utils.sanitize_hostname(hostname))

    def test_hostname_sanitize_characters(self):
        hostname = "(#@&$!(@*--#&91)(__=+--test-host.example!!.com-0+"
        self.assertEqual("91----test-host.example.com-0",
                         utils.sanitize_hostname(hostname))

    def test_hostname_translate(self):
        hostname = "<}\x1fh\x10e\x08l\x02l\x05o\x12!{>"
        self.assertEqual("hello", utils.sanitize_hostname(hostname))

    def test_read_cached_file(self):
        self.mox.StubOutWithMock(os.path, "getmtime")
        os.path.getmtime(mox.IgnoreArg()).AndReturn(1)
        self.mox.ReplayAll()

        cache_data = {"data": 1123, "mtime": 1}
        data = utils.read_cached_file("/this/is/a/fake", cache_data)
        self.assertEqual(cache_data["data"], data)

    def test_read_modified_cached_file(self):
        self.mox.StubOutWithMock(os.path, "getmtime")
        self.mox.StubOutWithMock(builtins, 'open')
        os.path.getmtime(mox.IgnoreArg()).AndReturn(2)

        fake_contents = "lorem ipsum"
        fake_file = self.mox.CreateMockAnything()
        fake_file.read().AndReturn(fake_contents)
        fake_context_manager = mock.Mock()
        fake_context_manager.__enter__ = mock.Mock(return_value=fake_file)
        fake_context_manager.__exit__ = mock.Mock(return_value=False)
        builtins.open(mox.IgnoreArg()).AndReturn(fake_context_manager)

        self.mox.ReplayAll()
        cache_data = {"data": 1123, "mtime": 1}
        self.reload_called = False

        def test_reload(reloaded_data):
            self.assertEqual(reloaded_data, fake_contents)
            self.reload_called = True

        data = utils.read_cached_file("/this/is/a/fake", cache_data,
                                                reload_func=test_reload)
        self.assertEqual(data, fake_contents)
        self.assertTrue(self.reload_called)

    def test_is_valid_boolstr(self):
        self.assertTrue(utils.is_valid_boolstr('true'))
        self.assertTrue(utils.is_valid_boolstr('false'))
        self.assertTrue(utils.is_valid_boolstr('yes'))
        self.assertTrue(utils.is_valid_boolstr('no'))
        self.assertTrue(utils.is_valid_boolstr('y'))
        self.assertTrue(utils.is_valid_boolstr('n'))
        self.assertTrue(utils.is_valid_boolstr('1'))
        self.assertTrue(utils.is_valid_boolstr('0'))

        self.assertFalse(utils.is_valid_boolstr('maybe'))
        self.assertFalse(utils.is_valid_boolstr('only on tuesdays'))

    def test_is_valid_ipv4(self):
        self.assertTrue(utils.is_valid_ipv4('127.0.0.1'))
        self.assertFalse(utils.is_valid_ipv4('::1'))
        self.assertFalse(utils.is_valid_ipv4('bacon'))
        self.assertFalse(utils.is_valid_ipv4(""))
        self.assertFalse(utils.is_valid_ipv4(10))

    def test_is_valid_ipv6(self):
        self.assertTrue(utils.is_valid_ipv6("::1"))
        self.assertTrue(utils.is_valid_ipv6(
                            "abcd:ef01:2345:6789:abcd:ef01:192.168.254.254"))
        self.assertTrue(utils.is_valid_ipv6(
                                    "0000:0000:0000:0000:0000:0000:0000:0001"))
        self.assertFalse(utils.is_valid_ipv6("foo"))
        self.assertFalse(utils.is_valid_ipv6("127.0.0.1"))
        self.assertFalse(utils.is_valid_ipv6(""))
        self.assertFalse(utils.is_valid_ipv6(10))

    def test_is_valid_ipv6_cidr(self):
        self.assertTrue(utils.is_valid_ipv6_cidr("2600::/64"))
        self.assertTrue(utils.is_valid_ipv6_cidr(
                "abcd:ef01:2345:6789:abcd:ef01:192.168.254.254/48"))
        self.assertTrue(utils.is_valid_ipv6_cidr(
                "0000:0000:0000:0000:0000:0000:0000:0001/32"))
        self.assertTrue(utils.is_valid_ipv6_cidr(
                "0000:0000:0000:0000:0000:0000:0000:0001"))
        self.assertFalse(utils.is_valid_ipv6_cidr("foo"))
        self.assertFalse(utils.is_valid_ipv6_cidr("127.0.0.1"))

    def test_get_shortened_ipv6(self):
        self.assertEqual("abcd:ef01:2345:6789:abcd:ef01:c0a8:fefe",
                            utils.get_shortened_ipv6(
                                "abcd:ef01:2345:6789:abcd:ef01:192.168.254.254"))
        self.assertEqual("::1", utils.get_shortened_ipv6(
                                    "0000:0000:0000:0000:0000:0000:0000:0001"))
        self.assertEqual("caca::caca:0:babe:201:102",
                          utils.get_shortened_ipv6(
                                    "caca:0000:0000:caca:0000:babe:0201:0102"))
        self.assertRaises(netaddr.AddrFormatError, utils.get_shortened_ipv6,
                          "127.0.0.1")
        self.assertRaises(netaddr.AddrFormatError, utils.get_shortened_ipv6,
                          "failure")

    def test_get_shortened_ipv6_cidr(self):
        self.assertEqual("2600::/64", utils.get_shortened_ipv6_cidr(
                "2600:0000:0000:0000:0000:0000:0000:0000/64"))
        self.assertEqual("2600::/64", utils.get_shortened_ipv6_cidr(
                "2600::1/64"))
        self.assertRaises(netaddr.AddrFormatError,
                          utils.get_shortened_ipv6_cidr,
                          "127.0.0.1")
        self.assertRaises(netaddr.AddrFormatError,
                          utils.get_shortened_ipv6_cidr,
                          "failure")

    def test_is_valid_mac(self):
        self.assertTrue(utils.is_valid_mac("52:54:00:cf:2d:31"))
        self.assertTrue(utils.is_valid_mac(u"52:54:00:cf:2d:31"))
        self.assertFalse(utils.is_valid_mac("127.0.0.1"))
        self.assertFalse(utils.is_valid_mac("not:a:mac:address"))

    def test_safe_rstrip(self):
        value = '/test/'
        rstripped_value = '/test'
        not_rstripped = '/'

        self.assertEqual(utils.safe_rstrip(value, '/'), rstripped_value)
        self.assertEqual(utils.safe_rstrip(not_rstripped, '/'), not_rstripped)

    def test_safe_rstrip_not_raises_exceptions(self):
        # Supplying an integer should normally raise an exception because it
        # does not save the rstrip() method.
        value = 10

        # In the case of raising an exception safe_rstrip() should return the
        # original value.
        self.assertEqual(utils.safe_rstrip(value), value)


class MkfsTestCase(base.TestCase):

    def test_mkfs(self):
        self.mox.StubOutWithMock(utils, 'execute')
        utils.execute('mkfs', '-t', 'ext4', '-F', '/my/block/dev')
        utils.execute('mkfs', '-t', 'msdos', '/my/msdos/block/dev')
        utils.execute('mkswap', '/my/swap/block/dev')
        self.mox.ReplayAll()

        utils.mkfs('ext4', '/my/block/dev')
        utils.mkfs('msdos', '/my/msdos/block/dev')
        utils.mkfs('swap', '/my/swap/block/dev')

    def test_mkfs_with_label(self):
        self.mox.StubOutWithMock(utils, 'execute')
        utils.execute('mkfs', '-t', 'ext4', '-F',
                      '-L', 'ext4-vol', '/my/block/dev')
        utils.execute('mkfs', '-t', 'msdos',
                      '-n', 'msdos-vol', '/my/msdos/block/dev')
        utils.execute('mkswap', '-L', 'swap-vol', '/my/swap/block/dev')
        self.mox.ReplayAll()

        utils.mkfs('ext4', '/my/block/dev', 'ext4-vol')
        utils.mkfs('msdos', '/my/msdos/block/dev', 'msdos-vol')
        utils.mkfs('swap', '/my/swap/block/dev', 'swap-vol')


class IntLikeTestCase(base.TestCase):

    def test_is_int_like(self):
        self.assertTrue(utils.is_int_like(1))
        self.assertTrue(utils.is_int_like("1"))
        self.assertTrue(utils.is_int_like("514"))
        self.assertTrue(utils.is_int_like("0"))

        self.assertFalse(utils.is_int_like(1.1))
        self.assertFalse(utils.is_int_like("1.1"))
        self.assertFalse(utils.is_int_like("1.1.1"))
        self.assertFalse(utils.is_int_like(None))
        self.assertFalse(utils.is_int_like("0."))
        self.assertFalse(utils.is_int_like("aaaaaa"))
        self.assertFalse(utils.is_int_like("...."))
        self.assertFalse(utils.is_int_like("1g"))
        self.assertFalse(
            utils.is_int_like("0cc3346e-9fef-4445-abe6-5d2b2690ec64"))
        self.assertFalse(utils.is_int_like("a1"))


class LDAPTestCase(base.TestCase):

    def test_ldapurl(self):
        # Bad Network address is not acceptable as ldap url
        ldap_url = 'ldap://127'
        self.assertRaises(wsme.exc.ClientSideError,
                          service_parameter._validate_ldap_url,
                          'foo',
                          ldap_url)

        # loopback is not acceptable as ldap url
        ldap_url = 'ldap://127.0.0.1'
        self.assertRaises(wsme.exc.ClientSideError,
                          service_parameter._validate_ldap_url,
                          'foo',
                          ldap_url)

        # localhost is not acceptable as ldap url
        ldap_url = 'ldap://localhost:1234'
        self.assertRaises(wsme.exc.ClientSideError,
                          service_parameter._validate_ldap_url,
                          'foo',
                          ldap_url)

        # A valid ldap URL should not raise an exception
        ldap_url = 'ldap://dns.example.com:389'
        service_parameter._validate_ldap_url('foo', ldap_url)

    def test_ldap_dn(self):
        # A poorly formatted ldap DN will raise a ClientSideError
        ldap_dn = 'this is not a valid ldap dn'
        self.assertRaises(wsme.exc.ClientSideError,
                          service_parameter._validate_ldap_dn,
                          'foo',
                          ldap_dn)

        # A valid DN will not raise a ClientSideError
        ldap_dn = 'uid=john.doe,ou=People,dc=example,dc=com'
        service_parameter._validate_ldap_dn('foo', ldap_dn)
