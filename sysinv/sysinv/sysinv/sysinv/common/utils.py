# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2010 United States Government as represented by the
# Administrator of the National Aeronautics and Space Administration.
# Copyright 2011 Justin Santa Barbara
# Copyright (c) 2012 NTT DOCOMO, INC.
# All Rights Reserved.
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
#
# Copyright (c) 2013-2025 Wind River Systems, Inc.
#


"""Utilities and helper functions."""

from __future__ import division
import ast
import boto3
from botocore.config import Config
import collections
import contextlib
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from OpenSSL import crypto
import datetime
import errno
import functools
import fcntl
import glob
import grp
import hashlib
import io
import itertools as it
import json
import keyring
import math
import netaddr
import os
import pathlib
import psutil
import pyudev
import pwd
import random
import re
import threading
import rfc3986
import shutil
import signal
import six
from six.moves.urllib.parse import urlparse
import socket
import stat
import string
import sys
import tempfile
import time
import tsconfig.tsconfig as tsc
import types
import uuid
import wsme
import yaml

from eventlet.green import subprocess
from eventlet import greenthread
from fm_api import constants as fm_constants
from jinja2 import Environment
from jinja2 import FileSystemLoader
from oslo_concurrency import lockutils
from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import uuidutils
from oslo_serialization import base64
from six.moves import range
from sysinv._i18n import _
from sysinv.common import exception
from sysinv.common import constants
from sysinv.helm import common as helm_common
from sysinv.common import kubernetes
from sysinv.common import usm_service as usm_service


try:
    from tsconfig.tsconfig import SW_VERSION
except ImportError:
    SW_VERSION = "unknown"


if six.PY3:
    USE_IMPORTLIB_METADATA_STDLIB = False
    try:
        import importlib.metadata
        USE_IMPORTLIB_METADATA_STDLIB = True
    except ImportError:
        import importlib_metadata


utils_opts = [
    cfg.StrOpt('rootwrap_config',
               default="/etc/sysinv/rootwrap.conf",
               help='Path to the rootwrap configuration file to use for '
                    'running commands as root'),
    cfg.StrOpt('tempdir',
               default=None,
               help='Explicitly specify the temporary working directory'),
]
CONF = cfg.CONF
CONF.register_opts(utils_opts)

LOG = logging.getLogger(__name__)

# Used for looking up extensions of text
# to their 'multiplied' byte amount
BYTE_MULTIPLIERS = {
    '': 1,
    't': 1024 ** 4,
    'g': 1024 ** 3,
    'm': 1024 ** 2,
    'k': 1024,
}


class memoized(object):
    '''Decorator. Caches a function's return value each time it is called.
    If called later with the same arguments, the cached value is returned
    (not reevaluated).

    WARNING:  This function should not be used for class methods since it
    does not provide weak references; thus would prevent the instance from
    being garbage collected.
    '''

    def __init__(self, func):
        self.func = func
        self.cache = {}

    def __call__(self, *args):
        if not isinstance(args, collections.Hashable):
            # uncacheable. a list, for instance.
            # better to not cache than blow up.
            return self.func(*args)
        if args in self.cache:
            return self.cache[args]
        else:
            value = self.func(*args)
            self.cache[args] = value
            return value

    def __repr__(self):
        '''Return the function's docstring.'''
        return self.func.__doc__

    def __get__(self, obj, objtype):
        '''Support instance methods.'''
        return functools.partial(self.__call__, obj)


def _subprocess_setup():
    # Python installs a SIGPIPE handler by default. This is usually not what
    # non-Python subprocesses expect.
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)


def exception_msg(exception):
    """Helper method to extract exception message
       for both py2 and py3 exception types

       :param exception:    Exception object
       :returns:  string representing the exception message
    """
    if hasattr(exception, 'message'):
        return str(exception.message)
    return str(exception)


def subprocess_open(command, timeout=5):
    """
    Helper method to execute a shell command, capture output,
    and avoid zombie processes.

    :param command: The shell command to execute.
    :param timeout: Timeout in seconds for the command (default: 5).

    :returns: a tuple: (stdout, stderr) from the command, or ("", "")
    if an error occurs.
    """
    stdout, stderr = "", ""

    try:
        with subprocess.Popen(command,
                             stdout=subprocess.PIPE,
                             shell=True,
                             universal_newlines=True) as process:
            stdout, stderr = process.communicate(timeout=timeout)

    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()  # Reap the process to avoid zombie
        LOG.error("Command '%s' timed out", command)
        return ("", "")
    except Exception as e:
        LOG.error("Could not execute command '%s': %s", command, e)
        return ("", "")

    return (stdout, stderr)


def execute(*cmd, **kwargs):
    """Helper method to execute command with optional retry.

    If you add a run_as_root=True command, don't forget to add the
    corresponding filter to etc/sysinv/rootwrap.d !

    :param cmd:                Passed to subprocess.Popen.
    :param process_input:      Send to opened process.
    :param check_exit_code:    Single bool, int, or list of allowed exit
                               codes.  Defaults to [0].  Raise
                               exception.ProcessExecutionError unless
                               program exits with one of these code.
    :param delay_on_retry:     True | False. Defaults to True. If set to
                               True, wait a short amount of time
                               before retrying.
    :param attempts:           How many times to retry cmd.
    :param run_as_root:        True | False. Defaults to False. If set to True,
                               the command is run with rootwrap.
    :param timeout             Passed to subprocess.communicate.
                               timeout in seconds (integer value)
                               Defaults to None

    :raises exception.SysinvException: on receiving unknown arguments
    :raises exception.ProcessExecutionError:

    :returns: a tuple, (stdout, stderr) from the spawned process, or None if
             the command fails.
    """
    process_input = kwargs.pop('process_input', None)
    check_exit_code = kwargs.pop('check_exit_code', [0])
    ignore_exit_code = False
    if isinstance(check_exit_code, bool):
        ignore_exit_code = not check_exit_code
        check_exit_code = [0]
    elif isinstance(check_exit_code, int):
        check_exit_code = [check_exit_code]
    delay_on_retry = kwargs.pop('delay_on_retry', True)
    attempts = kwargs.pop('attempts', 1)
    run_as_root = kwargs.pop('run_as_root', False)
    shell = kwargs.pop('shell', False)
    timeout = kwargs.pop('timeout', None)
    if timeout:
        try:
            timeout = int(timeout)
        except Exception:
            raise exception.SysinvException("Invalid value for timeout: [%s]. "
                                            "Please use a valid integer." % (timeout))

    if len(kwargs):
        raise exception.SysinvException(_('Got unknown keyword args '
                                        'to utils.execute: %r') % kwargs)

    if run_as_root and os.geteuid() != 0:
        cmd = ['sudo', 'sysinv-rootwrap', CONF.rootwrap_config] + list(cmd)

    cmd = [str(c) for c in cmd]

    while attempts > 0:
        attempts -= 1
        try:
            LOG.debug(_('Running cmd (subprocess): %s'), ' '.join(cmd))
            _PIPE = subprocess.PIPE  # pylint: disable=E1101

            if os.name == 'nt':
                preexec_fn = None
                close_fds = False
            else:
                preexec_fn = _subprocess_setup
                close_fds = True

            obj = subprocess.Popen(cmd,
                                   stdin=_PIPE,
                                   stdout=_PIPE,
                                   stderr=_PIPE,
                                   close_fds=close_fds,
                                   preexec_fn=preexec_fn,
                                   shell=shell)
            result = None
            if process_input is not None:
                result = obj.communicate(process_input, timeout=timeout)
            else:
                result = obj.communicate(timeout=timeout)
            obj.stdin.close()  # pylint: disable=E1101
            _returncode = obj.returncode  # pylint: disable=E1101
            LOG.debug(_('Result was %s') % _returncode)
            if result is not None and six.PY3:
                (stdout, stderr) = result
                # Decode from the locale using using the surrogateescape error
                # handler (decoding cannot fail)
                stdout = os.fsdecode(stdout)
                stderr = os.fsdecode(stderr)
                result = (stdout, stderr)
            if not ignore_exit_code and _returncode not in check_exit_code:
                (stdout, stderr) = result
                raise exception.ProcessExecutionError(
                        exit_code=_returncode,
                        stdout=stdout,
                        stderr=stderr,
                        cmd=' '.join(cmd))
            return result
        except (exception.ProcessExecutionError, Exception):
            if not attempts:
                raise
            else:
                LOG.debug(_('%r failed. Retrying.'), cmd)
                if delay_on_retry:
                    greenthread.sleep(random.randint(20, 200) / 100.0)
        finally:
            # NOTE(termie): this appears to be necessary to let the subprocess
            #               call clean something up in between calls, without
            #               it two execute calls in a row hangs the second one
            greenthread.sleep(0)


def trycmd(*args, **kwargs):
    """A wrapper around execute() to more easily handle warnings and errors.

    Returns an (out, err) tuple of strings containing the output of
    the command's stdout and stderr.  If 'err' is not empty then the
    command can be considered to have failed.

    :discard_warnings   True | False. Defaults to False. If set to True,
                        then for succeeding commands, stderr is cleared

    """
    discard_warnings = kwargs.pop('discard_warnings', False)

    try:
        out, err = execute(*args, **kwargs)
        failed = False
    except exception.ProcessExecutionError as exn:
        out, err = '', str(exn)
        failed = True

    if not failed and discard_warnings and err:
        # Handle commands that output to stderr but otherwise succeed
        err = ''

    return out, err


def execute_and_watch(cmd, timeout=60, log_prefix=None):
    """Helper script to execute a command and scrape output while it executes

    Runs a command using subprocess Popen and scrapes its output by piping stdout.
    The method is most suitable for commands that takes longer to run and needs to be tuned to its
    output to track its progress. Hence, this requires a timeout to ensure that the comamnd is
    eventually terminated.

    :param: cmd: list. Command to be executed in the format acceptable by subprocess.Popen
                       e.g. ['ls', '-la']
    :param: timeout: Request timeout in seconds. Integer/String. Default value: 60
    :param: log_prefix: String prefix to be added to logs in case required

    :returns: integer. Return code of the command in case of successful execution of the command.
    :raises: SysinvException in case of an error.
    """
    try:
        process = None

        if not isinstance(timeout, int) or \
                (isinstance(timeout, str) and not timeout.isnumeric()) or isinstance(timeout, bool):
            raise exception.SysinvException("Invalid timeout type: %s" % (type(timeout)))

        timeout = int(timeout)

        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   text=True, bufsize=1)

        def _capture_output():
            for line in process.stdout:
                if log_prefix:
                    line = "[%s]: %s" % (log_prefix, line)
                LOG.info(line)
                # Ensure that the buffer is flushed
                sys.stdout.flush()

        t = threading.Thread(target=_capture_output)

        t.start()

        return_code = process.wait(timeout=timeout)

        t.join(timeout=timeout)

        if return_code == 0:
            LOG.info("Command %s execution successful" % (cmd))
        else:
            raise exception.ProcessExecutionError(
                cmd=cmd, exit_code=return_code, stderr=process.stderr.read())

    except exception.ProcessExecutionError as ex:
        if process:
            process.kill()
        raise exception.SysinvException("Command %s execution failed with error: [%s] and "
                                        "exit code: [%s]" % (cmd, ex.stderr, ex.exit_code))
    except Exception as ex:
        if process:
            process.kill()
        raise exception.SysinvException("Command %s execution failed with error: [%s] "
                                        % (cmd, ex))


def systemctl_is_active_service(service_name):
    """Check if a systemd service is active

    :param: service_name: string: Name of the service to be checked
    :raises: SysinvException
    """
    active = True
    try:
        cmd = [constants.SYSTEMCTL_PATH, constants.IS_ACTIVE_COMMAND, service_name]
        execute(*cmd, check_exit_code=0)
    except exception.ProcessExecutionError:
        active = False
    except Exception as ex:
        raise exception.SysinvException("Failed to check if the service [%s] is active or not. "
                                        "Error: [%s]" % (service_name, ex))
    return active


def systemctl_is_enabled_service(service_name):
    """Check if a systemd service is enabled

    :param: service_name: string: Name of the service to be checked
    :raises: SysinvException
    """
    enabled = True
    try:
        cmd = [constants.SYSTEMCTL_PATH, constants.IS_ENABLED_COMMAND, service_name]
        execute(*cmd, check_exit_code=0)
    except exception.ProcessExecutionError:
        enabled = False
    except Exception as ex:
        raise exception.SysinvException("Failed to check if the service [%s] is enabled or not. "
                                        "Error: [%s]" % (service_name, ex))
    return enabled


def systemctl_mask_service(service_name, runtime=False, now=False):
    """Mask a systemd service

    :param: service_name: string: Name of the service to be masked
    :raises: SysinvException
    """
    try:
        cmd = [constants.SYSTEMCTL_PATH, constants.MASK_COMMAND, service_name]
        if runtime:
            cmd.append(constants.SYSTEMCTL_RUNTIME_FLAG)
        if now:
            cmd.append(constants.SYSTEMCTL_NOW_FLAG)
        execute(*cmd, check_exit_code=0)
        LOG.info("Service %s masked successfully" % (service_name))
    except Exception as ex:
        raise exception.SysinvException("Failed to mask the service %s with error: [%s]"
                                        % (service_name, ex))


def systemctl_unmask_service(service_name, runtime=False, now=False):
    """Unmask a systemd service

    :param: service_name: string: Name of the service to be unmasked
    :raises: SysinvException
    """
    try:
        cmd = [constants.SYSTEMCTL_PATH, constants.UNMASK_COMMAND, service_name]
        if runtime:
            cmd.append(constants.SYSTEMCTL_RUNTIME_FLAG)
        if now:
            cmd.append(constants.SYSTEMCTL_NOW_FLAG)
        execute(*cmd, check_exit_code=0)
        LOG.info("Service %s unmasked successfully" % (service_name))
    except Exception as ex:
        raise exception.SysinvException("Failed to unmask the service %s with error: [%s]"
                                        % (service_name, ex))


def systemctl_restart_service(service_name):
    """Restart a service using systemctl

    :param: service_name: string: Name of the service to be restarted
    :raises: SysinvException upon failure
    """
    try:
        cmd = [constants.SYSTEMCTL_PATH, constants.RESTART_COMMAND, service_name]
        execute(*cmd, check_exit_code=0)
        LOG.info("Service %s restarted successfully" % (service_name))
    except Exception as ex:
        raise exception.SysinvException("Failed to restart the service %s with error: [%s]"
                                        % (service_name, ex))


def systemctl_start_service(service_name):
    """Start a service using systemctl

    :param: service_name: string: Name of the service to be started
    :raises: SysinvException upon failure
    """
    try:
        cmd = [constants.SYSTEMCTL_PATH, constants.START_COMMAND, service_name]
        execute(*cmd, check_exit_code=0)
        LOG.info("Service %s started successfully" % (service_name))
    except Exception as ex:
        raise exception.SysinvException("Failed to start the service %s with error: [%s]"
                                        % (service_name, ex))


def pmon_start_service(service_name):
    """Start a systemd service using pmon

    :param: service_name: string: Name of the service to be started
    :raises: SysinvException upon failure
    """
    try:
        cmd = [constants.PMON_START_FULL_PATH, service_name]
        execute(*cmd, check_exit_code=0)
        LOG.info("Service %s pmon-started successfully" % (service_name))
    except Exception as ex:
        raise exception.SysinvException("Failed to start the service %s with error: [%s]"
                                        % (service_name, ex))


def pmon_stop_service(service_name):
    """Stop a systemd service using pmon

    :param: service_name: string: Name of the service to be stopped
    :raises: SysinvException upon failure
    """
    try:
        cmd = [constants.PMON_STOP_FULL_PATH, service_name]
        execute(*cmd, check_exit_code=0)
        LOG.info("Service %s pmon-stopped successfully" % (service_name))
    except Exception as ex:
        raise exception.SysinvException("Failed to stop the service %s with error: [%s]"
                                        % (service_name, ex))


def sm_restart_service(service_name, safe=True):
    """Restart a service using sm-restart

    :param: service_name: string: Name of the service to be restarted
    :param: safe: If True, service will be restarted with command sm-restart-safe otherwise
                  with just sm-restart.
    :raises: SysinvException upon failure or service is not managed by sm
    """
    try:
        if safe:
            command = constants.SM_RESTART_SAFE
        else:
            command = constants.SM_RESTART

        cmd = [command, 'service', service_name]

        stdout, _ = execute(*cmd, check_exit_code=0)

        if "does not exist" in stdout:
            raise exception.SysinvException("service %s is not managed by the service-manager."
                                            % (service_name))

        LOG.info("Service %s restarted successfully" % (service_name))

    except Exception as ex:
        raise exception.SysinvException("Failed to restart the service %s with error: [%s]"
                                        % (service_name, ex))


# def ssh_connect(connection):
#    """Method to connect to a remote system using ssh protocol.
#
#    :param connection: a dict of connection parameters.
#    :returns: paramiko.SSHClient -- an active ssh connection.
#    :raises: SSHConnectFailed
#
#    """
#    try:
#        ssh = paramiko.SSHClient()
#        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
#        ssh.connect(connection.get('host'),
#                    username=connection.get('username'),
#                    password=connection.get('password', None),
#                    port=connection.get('port', 22),
#                    key_filename=connection.get('key_filename', None),
#                    timeout=connection.get('timeout', 10))
#
#        # send TCP keepalive packets every 20 seconds
#        ssh.get_transport().set_keepalive(20)
#    except Exception:
#        raise exception.SSHConnectFailed(host=connection.get('host'))
#
#    return ssh


def generate_uid(topic, size=8):
    characters = '01234567890abcdefghijklmnopqrstuvwxyz'
    choices = [random.choice(characters) for _x in range(size)]
    return '%s-%s' % (topic, ''.join(choices))


def random_alnum(size=32):
    characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(random.choice(characters) for _ in range(size))


class LazyPluggable(object):
    """A pluggable backend loaded lazily based on some value."""

    def __init__(self, pivot, config_group=None, **backends):
        self.__backends = backends
        self.__pivot = pivot
        self.__backend = None
        self.__config_group = config_group

    def __get_backend(self):
        if not self.__backend:
            if self.__config_group is None:
                backend_name = CONF[self.__pivot]
            else:
                backend_name = CONF[self.__config_group][self.__pivot]
            if backend_name not in self.__backends:
                msg = _('Invalid backend: %s') % backend_name
                raise exception.SysinvException(msg)

            backend = self.__backends[backend_name]
            if isinstance(backend, tuple):
                name = backend[0]
                fromlist = backend[1]
            else:
                name = backend
                fromlist = backend

            self.__backend = __import__(name, None, None, fromlist)
        return self.__backend

    def __getattr__(self, key):
        backend = self.__get_backend()
        return getattr(backend, key)


def delete_if_exists(pathname):
    """delete a file, but ignore file not found error."""

    try:
        os.unlink(pathname)
    except OSError as e:
        if e.errno == errno.ENOENT:
            return
        else:
            raise


def is_int_like(val):
    """Check if a value looks like an int."""
    try:
        return str(int(val)) == str(val)
    except Exception:
        return False


def is_float_like(val):
    """Check if a value looks like a float."""
    try:
        return str(float(val)) == str(val)
    except Exception:
        return False


def is_valid_boolstr(val):
    """Check if the provided string is a valid bool string or not."""
    boolstrs = ('true', 'false', 'yes', 'no', 'y', 'n', '1', '0')
    return str(val).lower() in boolstrs


def is_valid_mac(address):
    """Verify the format of a MAC address."""
    m = "[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$"
    if isinstance(address, six.string_types) and re.match(m, address.lower()):
        return True
    return False


def is_empty_value(value):
    """checks empty or nullish values

    :param value: value to be checked
    :return bool: True if value is empty or nullish
    """
    if not value:
        return True

    if isinstance(value, str):
        if len(value.strip()) == 0:
            return True
        if value.strip().lower() in ["none", "null"]:
            return True

    return False


def validate_and_normalize_mac(address):
    """Validate a MAC address and return normalized form.

    Checks whether the supplied MAC address is formally correct and
    normalize it to all lower case.

    :param address: MAC address to be validated and normalized.
    :returns: Normalized and validated MAC address.
    :raises: InvalidMAC If the MAC address is not valid.
    :raises: ClonedInterfaceNotFound If MAC address is not updated
             while installing a cloned image.

    """
    if not is_valid_mac(address):
        if constants.CLONE_ISO_MAC in address:
            # get interface name from the label
            intf_name = address.rsplit('-', 1)[1][1:]
            raise exception.ClonedInterfaceNotFound(intf=intf_name)
        else:
            raise exception.InvalidMAC(mac=address)
    return address.lower()


def is_valid_ipv4(address):
    """Verify that address represents a valid IPv4 address."""
    try:
        return netaddr.valid_ipv4(address)
    except Exception:
        return False


def is_valid_ipv6(address):
    try:
        return netaddr.valid_ipv6(address)
    except Exception:
        return False


def is_valid_ip(address):
    if not is_valid_ipv4(address):
        return is_valid_ipv6(address)
    return True


def is_valid_ipv6_cidr(address):
    try:
        str(netaddr.IPNetwork(address, version=6).cidr)
        return True
    except Exception:
        return False


def validate_ip_multicast_address(address, valid_values=None):
    """
    Validates that an IP address is a multicast address.
    """
    try:
        return netaddr.IPAddress(address).is_multicast()
    except Exception:
        msg = _("'%s' is not a valid multicast IP address") % address
        LOG.debug(msg)
        return False


def get_shortened_ipv6(address):
    addr = netaddr.IPAddress(address, version=6)
    return str(addr.ipv6())


def get_shortened_ipv6_cidr(address):
    net = netaddr.IPNetwork(address, version=6)
    return str(net.cidr)


def is_valid_cidr(address):
    """Check if the provided ipv4 or ipv6 address is a valid CIDR address."""
    try:
        # Validate the correct CIDR Address
        netaddr.IPNetwork(address)
    except netaddr.core.AddrFormatError:
        return False
    except UnboundLocalError:
        # NOTE(MotoKen): work around bug in netaddr 0.7.5 (see detail in
        # https://github.com/drkjam/netaddr/issues/2)
        return False

    # Prior validation partially verify /xx part
    # Verify it here
    ip_segment = address.split('/')

    if (len(ip_segment) <= 1 or ip_segment[1] == ''):
        return False

    return True


def is_valid_hex(num):
    try:
        int(num, 16)
    except ValueError:
        return False
    return True


def is_valid_pci_device_vendor_id(id):
    """Check if the provided id is a valid 16 bit hexadecimal."""
    val = id.replace('0x', '').strip()
    if not is_valid_hex(id):
        return False
    if (len(val) > 4):
        return False
    return True


def is_valid_pci_class_id(id):
    """Check if the provided id is a valid 16 bit hexadecimal."""
    val = id.replace('0x', '').strip()
    if not is_valid_hex(id):
        return False
    if (len(val) > 6):
        return False
    return True


def is_system_usable_block_device(pydev_device):
    """ Check if a block device is local and can be used for partitioning

    Example devices:
     o local block devices: local HDDs, SSDs, RAID arrays
     o remote devices: iscsi mounted, LIO, EMC
     o mpath partition and member devices
     o non permanent devices: USB stick
    :return bool: True if device can be used else False
    """
    if pydev_device.get("ID_BUS") == "usb":
        # Skip USB devices
        return False
    if pydev_device.get("DM_VG_NAME") or pydev_device.get("DM_LV_NAME"):
        # Skip LVM devices
        return False
    if constants.DEVICE_NAME_MPATH in pydev_device.get("DM_NAME", "") and pydev_device.get("DM_PART", ""):
        # Skip mpath partition devices
        return False
    if pydev_device.get("ID_FS_TYPE") == constants.DEVICE_FS_TYPE_MPATH:
        # Skip mpath member devices
        return False
    id_path = pydev_device.get("ID_PATH", "")
    if "iqn." in id_path or "eui." in id_path:
        # Skip all iSCSI devices, they are links for volume storage.
        # As per https://www.ietf.org/rfc/rfc3721.txt, "iqn." or "edu."
        # have to be present when constructing iSCSI names.
        return False
    if (("-fc-" in id_path or "-lun-" in id_path) and
            is_valid_multipath(pydev_device.get('DEVNAME'))):
        return False
    if pydev_device.get("ID_VENDOR") == constants.VENDOR_ID_LIO:
        # LIO devices are iSCSI, should be skipped above!
        LOG.error("Invalid id_path. Device %s (%s) is iSCSI!" %
                    (id_path, pydev_device.get('DEVNAME')))
        return False
    if pydev_device.get("VAULT_TYPE") == constants.LUKS_VAULT_TYPE_NAME:
        # Skip devices with the VAULT_TYPE for LUKS encryption
        return False
    return True


def is_valid_multipath(device_node):
    """ Check if a block device is a valid multipath device."""
    multipath_cmd = "multipath -c %s" % device_node
    try:
        LOG.debug("running multipath command: %s" %
                  multipath_cmd)
        multipath_output, _ = execute(multipath_cmd, check_exit_code=[0],
                                      run_as_root=True, attempts=2,
                                      shell=True)
    except exception.ProcessExecutionError as exn:
        LOG.debug(str(exn))
        return False
    else:
        LOG.debug(multipath_output)
        return True


def get_ip_version(network):
    """Returns the IP version of a network (IPv4 or IPv6).

    :raises: AddrFormatError if invalid network.
    """
    if netaddr.IPNetwork(network).version == 6:
        return "IPv6"
    elif netaddr.IPNetwork(network).version == 4:
        return "IPv4"


def format_url_address(address):
    """Format the URL address according to RFC 2732"""
    try:
        addr = netaddr.IPAddress(address)
        if addr.version == constants.IPV6_FAMILY:
            return "[%s]" % address
        else:
            return str(address)
    except netaddr.AddrFormatError:
        return address


def convert_to_list_dict(lst, label):
    """Convert a value or list into a list of dicts."""
    if not lst:
        return None
    if not isinstance(lst, list):
        lst = [lst]
    return [{label: x} for x in lst]


def sanitize_hostname(hostname):
    """Return a hostname which conforms to RFC-952 and RFC-1123 specs."""
    if isinstance(hostname, six.string_types):
        hostname = hostname.encode('latin-1', 'ignore')
    if six.PY3:
        hostname = hostname.decode()
    hostname = re.sub('[ _]', '-', hostname)
    hostname = re.sub('[^\w.-]+', '', hostname)
    hostname = hostname.lower()
    hostname = hostname.strip('.-')

    return hostname


def read_cached_file(filename, cache_info, reload_func=None):
    """Read from a file if it has been modified.

    :param cache_info: dictionary to hold opaque cache.
    :param reload_func: optional function to be called with data when
                        file is reloaded due to a modification.

    :returns: data from file

    """
    mtime = os.path.getmtime(filename)
    if not cache_info or mtime != cache_info.get('mtime'):
        LOG.debug(_("Reloading cached file %s") % filename)
        with open(filename) as fap:
            cache_info['data'] = fap.read()
        cache_info['mtime'] = mtime
        if reload_func:
            reload_func(cache_info['data'])
    return cache_info['data']


def file_open(*args, **kwargs):
    """Open file

    see built-in file() documentation for more details

    Note: The reason this is kept in a separate module is to easily
          be able to provide a stub module that doesn't alter system
          state at all (for unit tests)
    """
    return open(*args, **kwargs)


def get_file_content(filename):
    """Returns the contents of the specified file.

    :param filename: The full path/name of the file
    :return: The contents of the file
    """
    file_contents = ''
    with open(filename) as f:
        file_contents = f.read()
    return file_contents


def hash_file(file_like_object):
    """Generate a hash for the contents of a file."""
    checksum = hashlib.sha1()
    for chunk in iter(lambda: file_like_object.read(32768), b''):
        encoded_chunk = (chunk.encode(encoding='utf-8')
                        if isinstance(chunk, six.string_types) else chunk)
        checksum.update(encoded_chunk)
    return checksum.hexdigest()


@contextlib.contextmanager
def tempdir(**kwargs):
    tempfile.tempdir = CONF.tempdir
    tmpdir = tempfile.mkdtemp(**kwargs)
    try:
        yield tmpdir
    finally:
        try:
            shutil.rmtree(tmpdir)
        except OSError as e:
            LOG.error(_('Could not remove tmpdir: %s'), str(e))


def mkfs(fs, path, label=None):
    """Format a file or block device

    :param fs: Filesystem type (examples include 'swap', 'ext3', 'ext4'
               'btrfs', etc.)
    :param path: Path to file or block device to format
    :param label: Volume label to use
    """
    if fs == 'swap':
        args = ['mkswap']
    else:
        args = ['mkfs', '-t', fs]
    # add -F to force no interactive execute on non-block device.
    if fs in ('ext3', 'ext4'):
        args.extend(['-F'])
    if label:
        if fs in ('msdos', 'vfat'):
            label_opt = '-n'
        else:
            label_opt = '-L'
        args.extend([label_opt, label])
    args.append(path)
    execute(*args)


# TODO(deva): Make these work in Sysinv.
#             Either copy nova/virt/utils (bad),
#             or reimplement as a common lib,
#             or make a driver that doesn't need to do this.
#
# def cache_image(context, target, image_id, user_id, project_id):
#     if not os.path.exists(target):
#         libvirt_utils.fetch_image(context, target, image_id,
#                                   user_id, project_id)
#
#
# def inject_into_image(image, key, net, metadata, admin_password,
#         files, partition, use_cow=False):
#     try:
#         disk_api.inject_data(image, key, net, metadata, admin_password,
#                 files, partition, use_cow)
#     except Exception as e:
#         LOG.warn(_("Failed to inject data into image %(image)s. "
#                    "Error: %(e)s") % locals())


def unlink_without_raise(path):
    try:
        os.unlink(path)
    except OSError as e:
        if e.errno == errno.ENOENT:
            return
        else:
            LOG.warn(_("Failed to unlink %(path)s, error: %(e)s") %
                      {'path': path, 'e': e})


def rmtree_without_raise(path):
    try:
        if os.path.isdir(path):
            shutil.rmtree(path)
    except OSError as e:
        LOG.warn(_("Failed to remove dir %(path)s, error: %(e)s") %
                {'path': path, 'e': e})


def write_to_file(path, contents):
    with open(path, 'w') as f:
        f.write(contents)


def create_link_without_raise(source, link):
    try:
        os.symlink(source, link)
    except OSError as e:
        if e.errno == errno.EEXIST:
            return
        else:
            LOG.warn(_("Failed to create symlink from %(source)s to %(link)s"
                       ", error: %(e)s") %
                       {'source': source, 'link': link, 'e': e})


def safe_rstrip(value, chars=None):
    """Removes trailing characters from a string if that does not make it empty

    :param value: A string value that will be stripped.
    :param chars: Characters to remove.
    :return: Stripped value.

    """
    if not isinstance(value, six.string_types):
        LOG.warn(_("Failed to remove trailing character. Returning original "
                   "object. Supplied object is not a string: %s,") % value)
        return value

    return value.rstrip(chars) or value


def generate_uuid():
    return str(uuid.uuid4())


def is_uuid_like(val):
    """Returns validation of a value as a UUID.

    For our purposes, a UUID is a canonical form string:
    aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa

    """
    try:
        return str(uuid.UUID(val)) == val
    except (TypeError, ValueError, AttributeError):
        return False


def removekey(d, key):
    r = dict(d)
    del r[key]
    return r


def removekeys_nonmtce(d, keepkeys=None):
    if not keepkeys:
        keepkeys = []

    nonmtce_keys = ['created_at',
                    'updated_at',
                    'ihost_action',
                    'action_state',
                    'vim_progress_status',
                    'task',
                    'uptime',
                    'location',
                    'serialid',
                    'config_status',
                    'config_applied',
                    'config_target',
                    'reserved',
                    'forisystemid']
    r = dict(d)

    for k in nonmtce_keys:
        if r.get(k) and (k not in keepkeys):
            del r[k]
    return r


def removekeys_nonhwmon(d, keepkeys=None):
    if not keepkeys:
        keepkeys = []

    nonmtce_keys = ['created_at',
                    'updated_at',
                    ]
    r = dict(d)

    for k in nonmtce_keys:
        if r.get(k) and (k not in keepkeys):
            del r[k]
    return r


def notify_mtc_and_recv(mtc_address, mtc_port, idict):
    mtc_response_dict = {}
    mtc_response_dict['status'] = None

    serialized_idict = json.dumps(idict)

    # notify mtc this ihost has been added
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setblocking(1)  # blocking, timeout must be specified
        s.settimeout(6)   # give mtc a few secs to respond
        s.connect((mtc_address, mtc_port))
        LOG.warning("Mtc Command : %s" % serialized_idict)
        s.sendall(serialized_idict)

        mtc_response = s.recv(1024)  # check if mtc allows
        try:
            mtc_response_dict = json.loads(mtc_response)
            LOG.warning("Mtc Response: %s" % mtc_response_dict)
        except Exception:
            LOG.exception("Mtc Response Error: %s" % mtc_response)
            pass

    except socket.error as e:
        LOG.exception(_("Socket Error: %s on %s:%s for %s") % (e,
                        mtc_address, mtc_port, serialized_idict))
        # if e not in [errno.EWOULDBLOCK, errno.EINTR]:
        #  raise exception.CommunicationError(_(
        #   "Socket error:  address=%s port=%s error=%s ") % (
        #    self._mtc_address, self._mtc_port, e))
        pass

    finally:
        s.close()

    return mtc_response_dict


def touch(fname):
    with open(fname, 'a'):
        os.utime(fname, None)


def remove(fname):
    if os.path.exists(fname):
        os.remove(fname)


def symlink_force(source, link_name):
    """ Force creation of a symlink
        Params:
            source: path to the source
            link_name: symbolic link name
    """
    try:
        os.symlink(source, link_name)
    except OSError as e:
        if e.errno == errno.EEXIST:
            os.remove(link_name)
            os.symlink(source, link_name)


@contextlib.contextmanager
def mounted(remote_dir, local_dir):
    local_dir = os.path.abspath(local_dir)
    try:
        subprocess.check_output(  # pylint: disable=not-callable
            ["/bin/nfs-mount", remote_dir, local_dir],
            stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        raise OSError(("mount operation failed: "
                       "command={}, retcode={}, output='{}'").format(
                          e.cmd, e.returncode, e.output))
    try:
        yield
    finally:
        try:
            subprocess.check_output(  # pylint: disable=not-callable
                ["/bin/umount", local_dir],
                stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            raise OSError(("umount operation failed: "
                           "command={}, retcode={}, output='{}'").format(
                              e.cmd, e.returncode, e.output))


def timestamped(dname, fmt='{dname}_%Y-%m-%d-%H-%M-%S'):
    return datetime.datetime.now().strftime(fmt).format(dname=dname)


def nested_object(objclass, none_ok=True):
    def validator(val, objclass=objclass):
        if none_ok and val is None:
            return val
        if isinstance(val, objclass):
            return val
        raise ValueError('An object of class %s is required here' % objclass)
    return validator


def host_has_function(iHost, function):
    return function in (iHost.get('subfunctions') or iHost['personality'] or '')


@memoized
def is_virtual():
    '''
    Determines if the system is virtualized or not
    '''
    subp = subprocess.Popen(['facter', 'is_virtual'],
                            stdout=subprocess.PIPE, universal_newlines=True)
    if subp.wait():
        raise Exception("Failed to read virtualization status from facter")
    output = subp.stdout.readlines()
    if len(output) != 1:
        raise Exception("Unexpected number of lines: %d" % len(output))
    result = output[0].strip()
    return bool(result == 'true')


def is_virtual_worker(ihost):
    if not (os.path.isdir("/etc/sysinv/.virtual_worker_nodes")):
        return False
    try:
        ip = ihost['mgmt_ip']
        return os.path.isfile("/etc/sysinv/.virtual_worker_nodes/%s" % ip)
    except AttributeError:
        return False


def get_platform_core_count(dbapi):
    """
    Determine the number of platform cores available
    Returns the minimum of the 2 controllers or 1
    """
    core_list = []
    controllers = dbapi.ihost_get_by_personality(constants.CONTROLLER)
    platform_functions = [
        constants.PLATFORM_FUNCTION,
        constants.SHARED_FUNCTION
    ]
    for controller in controllers:
        number_platform_cores = 0
        cpu_list = dbapi.icpu_get_by_ihost(controller.uuid)
        for cpu in cpu_list:
            if int(cpu['thread']) == 0:
                if cpu['allocated_function'] in platform_functions:
                    number_platform_cores += 1
        if number_platform_cores > 0:
            core_list.append(number_platform_cores)

    return min(core_list, default=1)


def is_low_core_system(ihost, dba):
    """
    Determine if the hosts core count is less than or equal to a xeon-d cpu
    used with get_required_platform_reserved_memory to set the required
    platform memory for xeon-d systems
    """
    cpu_list = dba.icpu_get_by_ihost(ihost['uuid'])
    number_physical_cores = 0
    for cpu in cpu_list:
        if int(cpu['thread']) == 0:
            number_physical_cores += 1
    return number_physical_cores <= constants.NUMBER_CORES_XEOND


def get_minimum_platform_reserved_memory(dbapi, ihost, numa_node):
    """Returns the minimum amount of memory to be reserved by the platform for a
    given NUMA node. Standard controller, system controller and compute nodes
    all require reserved memory because the balance of the memory is allocated
    to pods or VM instances. Storage nodes have exclusive use of the memory
    so no explicit reservation is required.
    """
    reserved = 0

    system = dbapi.isystem_get_one()
    ihost_inodes = dbapi.inode_get_by_ihost(ihost['uuid'])
    numa_node_count = len(ihost_inodes)

    if is_virtual() or is_virtual_worker(ihost):
        # minimal memory requirements for VirtualBox
        if host_has_function(ihost, constants.WORKER):
            if numa_node == 0:
                reserved += 1200
                if host_has_function(ihost, constants.CONTROLLER):
                    reserved += 5000
            else:
                reserved += 500
    elif (system.distributed_cloud_role ==
              constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER and
          ihost['personality'] == constants.CONTROLLER):
        reserved += \
            constants.DISTRIBUTED_CLOUD_CONTROLLER_MEMORY_RESERVED_MIB // numa_node_count
    elif host_has_function(ihost, constants.WORKER):
            # Engineer 1G per numa node for disk IO RSS overhead
        reserved += constants.DISK_IO_RESIDENT_SET_SIZE_MIB
    elif ihost['personality'] == constants.CONTROLLER:
        # Standard controller
        reserved += constants.STANDARD_CONTROLLER_MEMORY_RESERVED_MIB // numa_node_count

    return reserved


def get_required_platform_reserved_memory(dbapi, ihost, numa_node, low_core=False):
    """Returns the amount of memory to be reserved by the platform for a
    given NUMA node. Standard controller, system controller and compute nodes
    all require reserved memory because the balance of the memory is allocated
    to pods or VM instances. Storage nodes have exclusive use of the memory
    so no explicit reservation is required.
    """
    required_reserved = 0

    system = dbapi.isystem_get_one()
    ihost_inodes = dbapi.inode_get_by_ihost(ihost['uuid'])
    numa_node_count = len(ihost_inodes)

    if is_virtual() or is_virtual_worker(ihost):
        # minimal memory requirements for VirtualBox
        required_reserved += constants.DISK_IO_RESIDENT_SET_SIZE_MIB_VBOX
        if host_has_function(ihost, constants.WORKER):
            if numa_node == 0:
                if ihost['personality'] == constants.WORKER:
                    required_reserved += \
                        constants.PLATFORM_CORE_MEMORY_RESERVED_MIB_VBOX_WORKER
                else:
                    required_reserved += \
                        constants.PLATFORM_CORE_MEMORY_RESERVED_MIB_VBOX
                if host_has_function(ihost, constants.CONTROLLER):
                    required_reserved += \
                        constants.COMBINED_NODE_CONTROLLER_MEMORY_RESERVED_MIB_VBOX
                else:
                    # If not a controller, add overhead for metadata and vrouters
                    required_reserved += \
                        constants.NETWORK_METADATA_OVERHEAD_MIB_VBOX
            else:
                required_reserved += \
                    constants.DISK_IO_RESIDENT_SET_SIZE_MIB_VBOX
    elif (system.distributed_cloud_role ==
             constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER and
          ihost['personality'] == constants.CONTROLLER):
        required_reserved += \
            constants.DISTRIBUTED_CLOUD_CONTROLLER_MEMORY_RESERVED_MIB // numa_node_count
    elif host_has_function(ihost, constants.WORKER):
        # Engineer reserve per numa node for disk IO RSS overhead
        required_reserved += constants.DISK_IO_RESIDENT_SET_SIZE_MIB
        if numa_node == 0:
            # Engineer platform reserve for worker
            required_reserved += \
                constants.PLATFORM_CORE_MEMORY_RESERVED_MIB
            if host_has_function(ihost, constants.CONTROLLER):
                # If AIO, reserve additional memory for controller function.
                # Controller memory usage depends on number of workers.
                if low_core:
                    required_reserved += \
                        constants.COMBINED_NODE_CONTROLLER_MEMORY_RESERVED_MIB_XEOND
                else:
                    required_reserved += \
                        constants.COMBINED_NODE_CONTROLLER_MEMORY_RESERVED_MIB
            else:
                # If not a controller, add overhead for metadata and vrouters
                required_reserved += \
                    constants.NETWORK_METADATA_OVERHEAD_MIB
    elif ihost['personality'] == constants.CONTROLLER:
        # Standard controller
        required_reserved += \
            constants.STANDARD_CONTROLLER_MEMORY_RESERVED_MIB // numa_node_count

    return required_reserved


def get_sw_version():
    return SW_VERSION


def _get_key_from_file(file_contents, key):
    """
    Extract value from KEY=VALUE entries.
    Ignore newline, ignore apostrophe, ignore quotation mark.

    :param file_contents: contents of file
    :param key: key to search
    :return: found value or ''
    """
    r = re.compile('^{}\=[\'\"]*([^\'\"\n]*)'.format(key), re.MULTILINE)
    match = r.search(file_contents)
    if match:
        return match.group(1)
    else:
        return ''


@memoized
def get_os_release(release_file=constants.OS_RELEASE_FILE):
    """
    Function to read release information.
    Ignore newline, ignore apostrophe, ignore quotation mark.

    :param release_file: file to read from
    :return: 3 element list [ ID, VERSION, '' ]
    """
    linux_distro = ('', '', '')

    try:
        with open(release_file, 'r') as f:
            data = f.read()
            linux_distro = (
                _get_key_from_file(data, 'ID'),
                _get_key_from_file(data, 'VERSION'),
                '')
    except Exception as e:
        raise exception.SysinvException(_(
            "Failed to open %s : %s") % (release_file, str(e)))

    if linux_distro[0] == '':
        raise exception.SysinvException(_(
            "Could not determine os type from %s") % release_file)

    # Hint: This code is added here to aid future unit test.
    # Probably running unit tests on a non-supported OS (example at
    # time of writing: ubuntu), which is perfect, because code reaching
    # here will fail, and we just identified a place that would split
    # logic between OSs. The failing tests should mock this function
    # (get_os_release) for each supported OS.
    if linux_distro[0] not in constants.SUPPORTED_OS_TYPES:
        raise exception.SysinvException(_(
            "Unsupported OS detected %s") % linux_distro[0])

    return linux_distro


def get_os_target(target_rel, feed_folder=constants.OS_UPGRADE_FEED_FOLDER):
    """
    Get the target release OS by reading the upgrade feed to check
    if os_tree repo is included

    :param target_rel (String): Target release version
    :param feed_folder (String, optional): Upgrade feed directory.
           Defaults to constants.OS_UPGRADE_FEED_FOLDER.
    :return String: constants.OS_DEBIAN or constants.OS_CENTOS
    """

    os_tree_dir = os.path.join(feed_folder, "rel-" + target_rel, "ostree_repo")
    return constants.OS_DEBIAN if os.path.exists(os_tree_dir) else constants.OS_CENTOS


def get_os_type(release_file=constants.OS_RELEASE_FILE):
    return get_os_release(release_file)[0]


def is_debian():
    return get_os_type() == constants.OS_DEBIAN


def is_centos():
    return get_os_type() == constants.OS_CENTOS


class ISO(object):

    def __init__(self, iso_path, mount_dir):
        self.iso_path = iso_path
        self.mount_dir = mount_dir
        self._iso_mounted = False
        self._mount_iso()

    def __del__(self):
        if self._iso_mounted:
            self._umount_iso()

    def _mount_iso(self):
        with open(os.devnull, "w") as fnull:
            subprocess.check_call(['mkdir', '-p', self.mount_dir], stdout=fnull,  # pylint: disable=not-callable
                                  stderr=fnull)
            subprocess.check_call(['mount', '-r', '-o', 'loop', self.iso_path,  # pylint: disable=not-callable
                                   self.mount_dir],
                                  stdout=fnull,
                                  stderr=fnull)
        self._iso_mounted = True

    def _umount_iso(self):
        try:
            # Do a lazy unmount to handle cases where a file in the mounted
            # directory is open when the umount is done.
            subprocess.check_call(['umount', '-l', self.mount_dir])  # pylint: disable=not-callable
            self._iso_mounted = False
        except subprocess.CalledProcessError as e:
            # If this fails for some reason, there's not a lot we can do
            # Just log the exception and keep going
            LOG.exception(e)


def unmount_stuck_isos():
    # get all mount info
    if six.PY2:
        output = subprocess.check_output(["mount"])  # pylint: disable=not-callable
    else:
        output = subprocess.check_output(["mount"]).decode("utf-8")  # pylint: disable=not-callable
    mountpoint_regex = "on (/tmp/tmp\w+) type iso"
    mountpoints = [re.search(mountpoint_regex, line).group(1)
                   for line in output.splitlines()
                   if re.search(mountpoint_regex, line)]
    # attempt to unmount tmp_loads
    for mnt in mountpoints:
        LOG.info("Unmounting tmp_load on %s..." % mnt)
        with open(os.devnull, "w") as fnull:
            subprocess.check_call(["umount", "-l", mnt],  # pylint: disable=not-callable
                                  stdout=fnull, stderr=fnull)


def get_active_load(loads):
    active_state = constants.ACTIVE_LOAD_STATE
    matches = [load for load in loads if load.state == active_state]
    if matches:
        return matches[0]
    else:
        raise exception.SysinvException(_("No active load found"))


def get_imported_load(loads):
    imported_states = constants.IMPORTED_LOAD_STATES
    matches = [load for load in loads if load.state in imported_states]
    if matches:
        return matches[0]
    else:
        raise exception.SysinvException(_("No imported load found"))


def validate_loads_for_import(loads):
    imported_states = constants.IMPORTED_LOAD_STATES
    matches = [load for load in loads if load.state in imported_states]
    if matches:
        raise exception.SysinvException(_("Imported load exists."))


def validate_load_for_delete(load):
    if not load:
        raise exception.SysinvException(_("Load not found"))

    valid_delete_states = [
        constants.IMPORTED_LOAD_STATE,
        constants.IMPORTED_METADATA_LOAD_STATE,
        constants.INACTIVE_LOAD_STATE,
        constants.ERROR_LOAD_STATE,
        constants.DELETING_LOAD_STATE
    ]

    if load.state not in valid_delete_states:
        raise exception.SysinvException(
            _("Only a load in an imported or error state can be deleted"))


def gethostbyname(hostname):
    return socket.getaddrinfo(hostname, None)[0][4][0]


def get_local_controller_hostname():
    try:
        local_hostname = socket.gethostname()
    except Exception as e:
        raise exception.SysinvException(_(
            "Failed to get the local hostname: %s") % str(e))
    return local_hostname


def get_mate_controller_hostname(hostname=None):
    if not hostname:
        try:
            hostname = socket.gethostname()
        except Exception as e:
            raise exception.SysinvException(_(
                "Failed to get the local hostname: %s") % str(e))

    if hostname == constants.CONTROLLER_0_HOSTNAME:
        mate_hostname = constants.CONTROLLER_1_HOSTNAME
    elif hostname == constants.CONTROLLER_1_HOSTNAME:
        mate_hostname = constants.CONTROLLER_0_HOSTNAME
    else:
        raise exception.SysinvException(_(
            "Unknown local hostname: %s)" % hostname))

    return mate_hostname


def format_address_name(hostname, network_type):
    return "%s-%s" % (hostname, network_type)


def validate_yes_no(name, value):
    if value.lower() not in ['y', 'n']:
        raise wsme.exc.ClientSideError((
            "Parameter '%s' must be a y/n value." % name))


def get_sriov_vf_index(addr, addrs):
    """
    Returns vf index of specified pci addr of the vf
    Returns None if not found
    """
    try:
        return addrs.index(addr)
    except ValueError:
        LOG.error("Index not found for this addr %s." % addr)
        return None


def get_dhcp_cid(hostname, network_type, mac):
    """Create the CID for use with dnsmasq. We use a unique identifier for a
    client since different networks can operate over the same device (and hence
    same MAC addr) when VLAN interfaces are concerned.  The mgmt network uses
    a default because it needs to exist before the board is handled by sysinv
    (i.e., the CID needs to exist in the dhclient.conf file at build time).

    Example:
    Format = 'id:' + colon-separated-hex(hostname:network_type) + ":" + mac
    """

    if network_type == constants.NETWORK_TYPE_MGMT:
        # Our default dhclient.conf files requests a prefix of '00:03:00' to
        # which dhclient adds a hardware address type of 01 to make final
        # prefix of '00:03:00:01'.
        prefix = '00:03:00:01'
    else:
        raise Exception("Network type {} does not support DHCP".format(
            network_type))
    return '{}:{}'.format(prefix, mac)


def get_personalities(host_obj):
    """
        Determine the personalities from host_obj
    """
    personalities = host_obj.subfunctions.split(',')
    if constants.LOWLATENCY in personalities:
        personalities.remove(constants.LOWLATENCY)
    return personalities


def is_cpe(host_obj):
    return (host_has_function(host_obj, constants.CONTROLLER) and
            host_has_function(host_obj, constants.WORKER))


def is_space_available(partition, size):
    """
        Returns if the given size is available in the specified partition
    """
    available_space = psutil.disk_usage(partition).free
    return False if available_space < size else True


def output_to_dict(output):
    dict = {}
    output = [_f for _f in output.split('\n') if _f]

    for row in output:
        values = row.split()
        if len(values) != 2:
            raise Exception("The following output does not respect the "
                            "format: %s" % row)
        dict[values[1]] = values[0]

    return dict


def bytes_to_GiB(bytes_number):
    return bytes_number / float(1024 ** 3)  # pylint: disable=W1619


def bytes_to_MiB(bytes_number):
    return bytes_number / float(1024 ** 2)  # pylint: disable=W1619


def check_lock_path():
    if os.path.isdir(constants.SYSINV_VOLATILE_PATH):
        return
    try:
        uid = pwd.getpwnam(constants.SYSINV_USERNAME).pw_uid
        gid = grp.getgrnam(constants.SYSINV_GRPNAME).gr_gid
        os.makedirs(constants.SYSINV_VOLATILE_PATH)
        os.chown(constants.SYSINV_VOLATILE_PATH, uid, gid)
        LOG.info("Created directory=%s" %
                 constants.SYSINV_VOLATILE_PATH)

    except OSError as e:
        LOG.exception("makedir %s OSError=%s encountered" %
                      (constants.SYSINV_VOLATILE_PATH, e))


def synchronized(name, external=True):
    if external:
        check_lock_path()
        lock_path = constants.SYSINV_VOLATILE_PATH
    else:
        lock_path = None
    return lockutils.synchronized(name,
                                  lock_file_prefix='sysinv-',
                                  external=external,
                                  lock_path=lock_path)


# TODO (rchurch): refactor this. Need for upgrades? Combine needs with
# _get_cinder_device_info()
def _get_cinder_device(dbapi, forihostid):
    if not forihostid:
        LOG.error("_get_cinder_device: host not defined. ")
        return

    cinder_device = None

    i_stors = dbapi.istor_get_by_ihost(forihostid)
    for stor in i_stors:
        if stor.function == constants.STOR_FUNCTION_CINDER:
            # Obtain the cinder disk.
            cinder_disk_uuid = stor.idisk_uuid
            cinder_disk = dbapi.idisk_get(cinder_disk_uuid)
            # Obtain the cinder device as the disk's device path.
            if cinder_disk.device_path:
                cinder_device = cinder_disk.device_path
            elif cinder_disk.device_node:
                # During upgrade from 16.10, the cinder device_path may
                # not be set for controller-0
                cinder_device = cinder_disk.device_node
                LOG.info("JKUNG host %s cinder device_path does not exist, return "
                         "device_node=%s" % (forihostid, cinder_disk.device_node))

    return cinder_device


def _get_cinder_device_info(dbapi, forihostid):
    if not forihostid:
        LOG.error("_get_cinder_device: host not defined. ")
        return

    cinder_device = None
    cinder_size_gib = 0

    # TODO (rchurch): get a DB query based on volume group name
    lvgs = dbapi.ilvg_get_by_ihost(forihostid)
    for vg in lvgs:
        if vg.lvm_vg_name == constants.LVG_CINDER_VOLUMES:
            pvs = dbapi.ipv_get_by_ihost(forihostid)
            for pv in pvs:
                if pv.forilvgid == vg.id:
                    # NOTE: Only supporting a single PV for cinder volumes
                    if cinder_device:
                        LOG.error("Another cinder device? ignoring! pv: %s" % pv.uuid)
                        continue
                    cinder_device = pv.disk_or_part_device_path

                    # NOTE: Should only ever be a single partition until we support
                    #       multiple PVs for cinder. Cinder device should
                    #       not be a disk. Log an error and continue
                    # Get the size of the pv from the parition info
                    try:
                        part = dbapi.partition_get(pv.disk_or_part_uuid)
                        cinder_size_gib = (int)(part.size_mib) >> 1
                    except exception.DiskPartitionNotFound:
                        LOG.error("Discovered cinder device is not a partition.")

    return cinder_device, cinder_size_gib


def _get_pv_type(lvm_pv_name):
    if "nvme" not in lvm_pv_name:
        if re.match("^/dev/.*[a-z][0-9]?$", lvm_pv_name):
            return constants.PV_TYPE_PARTITION
        return constants.PV_TYPE_DISK
    else:
        if re.match("^/dev/nvme.*p[0-9]?$", lvm_pv_name):
            return constants.PV_TYPE_PARTITION
        return constants.PV_TYPE_DISK


def get_pv_device_path(dbapi, ihost_uuid, pv):
    idisk = dbapi.idisk_get_by_ihost(ihost_uuid)

    pv_type = _get_pv_type(pv["lvm_pv_name"])
    for d in idisk:
        if d.device_node in pv["lvm_pv_name"]:
            if pv_type == constants.PV_TYPE_DISK:
                return d.device_path
            elif pv_type == constants.PV_TYPE_PARTITION:
                partitions = dbapi.partition_get_by_idisk(d.uuid)
                for p in partitions:
                    partition_number = re.match(".*?([0-9]+)$", pv["lvm_pv_name"]).group(1)
                    if "-part" + partition_number in p.device_path:
                        return p.device_path
    return None


def acquire_shared_nb_flock(lockfd, max_retry=5, wait_interval=5):
    """
    This method is to acquire a Shared Non-blocking lock for the
    given file descriptor to avoid conflict with other processes
    trying accessing the same file.

    :returns: fd of the lock, if successful. 0 on error.
    """
    return _acquire_file_lock(lockfd, fcntl.LOCK_SH | fcntl.LOCK_NB,
                              max_retry, wait_interval)


def acquire_exclusive_nb_flock(lockfd, max_retry=5, wait_interval=5):
    """
    This method is to acquire a Exclusive Non-blocking lock for the
    given file descriptor to avoid conflict with other processes
    trying accessing the same file.

    :returns: fd of the lock, if successful. 0 on error.
    """
    return _acquire_file_lock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB,
                              max_retry, wait_interval)


def release_flock(lockfd):
    """
    This method is used to release the file lock acquired by the process.
    """
    if lockfd:
        fcntl.flock(lockfd, fcntl.LOCK_UN)


def _acquire_file_lock(lockfd, operation, max_retry, wait_interval):
    count = 1
    while count <= max_retry:
        try:
            fcntl.flock(lockfd, operation)
            LOG.debug("Successfully acquired lock (fd={})".format(lockfd))
            return lockfd
        except IOError as e:
            # raise on unrelated IOErrors
            if e.errno != errno.EAGAIN:
                raise
            else:
                LOG.info("Could not acquire lock({}): {} ({}/{}), "
                         "will retry".format(lockfd, str(e),
                                             count, max_retry))
                time.sleep(wait_interval)
                count += 1

    LOG.error("Failed to acquire lock (fd={}). Stopped trying.".format(lockfd))
    return 0


def skip_udev_partition_probe(function):
    def wrapper(*args, **kwargs):
        """Decorator to skip partition rescanning in udev

        When reading partitions we have to avoid rescanning them as this
        will temporarily delete their dev nodes causing devastating effects
        for commands that rely on them (e.g. ceph-disk).

        UDEV triggers a partition rescan when a device node opened in write
        mode is closed. To avoid this, we have to acquire a shared lock on the
        device before other close operations do.

        Since both parted and sgdisk always open block devices in RW mode we
        must disable udev from triggering the rescan when we just need to get
        partition information.

        This happens due to a change in udev v214. For details see:
            http://tracker.ceph.com/issues/14080
            http://tracker.ceph.com/issues/15176
            https://github.com/systemd/systemd/commit/02ba8fb3357daf57f6120ac512fb464a4c623419

        :param   device_node: dev node or path of the device
        :returns decorated function
        """
        device_node = kwargs.get('device_node', None)
        if device_node:
            with open(device_node, 'r') as f:
                if acquire_shared_nb_flock(f):
                    try:
                        return function(*args, **kwargs)
                    finally:
                        # Since events are asynchronous we have to wait for udev
                        # to pick up the change.
                        time.sleep(0.1)
                        release_flock(f)
                else:
                    LOG.error("Failed to acquire lock (fd={}). Could not call decorated function {}"
                        .format(f, str(function)))
        else:
            return function(*args, **kwargs)
    return wrapper


def disk_is_gpt(device_node):
    """Checks if a device node is of GPT format.
    :param   device_node: the disk's device node
    :returns: True if partition table on disk is GPT
              False if partition table on disk is not GPT
    """
    sfdisk_command = '{} {}'.format('sfdisk -l', device_node)
    sfdisk_process = subprocess.Popen(
        sfdisk_command, stdout=subprocess.PIPE, shell=True,
        universal_newlines=True)
    sfdisk_output = sfdisk_process.stdout.read()
    return bool(re.search('Disklabel type: gpt', sfdisk_output))


def partitions_are_in_order(disk_partitions, requested_partitions):
    """Determine if a list of requested partitions can be created on a disk
    with other existing partitions."""

    partitions_nr = []

    for dp in disk_partitions:
        part_number = get_part_number(dp.get('device_path'))
        partitions_nr.append(int(part_number))

    for rp in requested_partitions:
        part_number = get_part_number(rp.get('device_path'))
        partitions_nr.append(int(part_number))

    return sorted(partitions_nr) == range(min(partitions_nr),
                                          max(partitions_nr) + 1)


# TODO(oponcea): Remove once sm supports in-service configuration reload.
def is_single_controller(dbapi):
    # Check the number of provisioned/upgrading/provisioning hosts. If there
    # is only one then we have a single controller (AIO-SX, single AIO-DX, or
    # single std controller). If this is the case reset sm after adding
    # cinder so that cinder DRBD/processes are managed.
    hosts = dbapi.ihost_get_list()
    prov_hosts = [h for h in hosts
                  if h.invprovision in [constants.PROVISIONED,
                                        constants.PROVISIONING,
                                        constants.UPGRADING]]
    if len(prov_hosts) == 1:
        return True
    return False


def get_size_gib_in_disk(host, device_path, dbapi):
    """Get the size for the device path
       returns: size space in GiB
    """
    size_gib = 0
    disks = dbapi.idisk_get_by_ihost(host.uuid)
    for disk in disks:
        if disk.device_path == device_path or disk.device_node == device_path:
            size_gib = disk.size_mib / 1024
    return size_gib


def get_available_gib_in_disk(host, device_path, dbapi):
    """Get the free space for the device path
       returns: Free space in GiB
    """
    available_gib = 0
    disks = dbapi.idisk_get_by_ihost(host.uuid)
    for disk in disks:
        if disk.device_path == device_path or disk.device_node == device_path:
            available_gib = disk.available_mib / 1024
    return available_gib


def is_partition_the_last(dbapi, partition):
    """Check that the partition we are trying to delete is the last partition
       on disk.
    """
    idisk_uuid = partition.get('idisk_uuid')
    onidisk_parts = dbapi.partition_get_by_idisk(idisk_uuid)
    part_number = get_part_number(partition.get('device_path'))

    if int(part_number) != len(onidisk_parts):
        return False

    return True


def get_network_address_pools(dbapi, networktype, primary_only):
    pools = []
    try:
        network = dbapi.network_get_by_type(networktype)
        if primary_only:
            if network.pool_uuid:
                pools.append(dbapi.address_pool_get(network.pool_uuid))
        else:
            pools = dbapi.address_pools_get_by_network(network.id)
    except exception.NetworkTypeNotFound:
        pass
    return pools


def get_central_cloud_gateway_network_and_addresses(dbapi, primary_only):
    # If the Admin network exists, use its gateway addresses. If not, use Management's instead.
    for networktype in [constants.NETWORK_TYPE_ADMIN, constants.NETWORK_TYPE_MGMT]:
        pools = get_network_address_pools(dbapi, networktype, primary_only)
        iface_network_list = dbapi.interface_networks_get_by_network_type(networktype)
        if pools and iface_network_list:
            gateway_addresses = {}
            for pool in pools:
                if pool.gateway_address:
                    gateway_addresses[pool.family] = pool.gateway_address
            return networktype, gateway_addresses
    return None, {}


def update_routes_to_system_controller(dbapi, hosts=None, primary_only=True):
    # Update routes to system controller network.
    # Assumption is we do not have to do any error checking
    # for local & reachable gateway etc, as config_subcloud
    # will have already done these checks before allowing
    # the system controller gateway into the database.

    cc_network_addr_pools = get_network_address_pools(dbapi,
        constants.NETWORK_TYPE_SYSTEM_CONTROLLER, primary_only)
    if not cc_network_addr_pools:
        LOG.info("DC Config: No entries found for the central cloud network")
        return

    if hosts is None:
        hosts = dbapi.ihost_get_by_personality(constants.CONTROLLER)
    host_index = {host.id: host for host in hosts}
    if not host_index:
        return

    route_query_values = {}
    for cc_pool in cc_network_addr_pools:
        route_query_values[cc_pool.family] = {'family': cc_pool.family,
                                              'network': cc_pool.network,
                                              'prefix': cc_pool.prefix}

    networktype, gateway_addresses = get_central_cloud_gateway_network_and_addresses(dbapi,
                                                                                     primary_only)
    host_route_create_values = {}
    if gateway_addresses:
        iface_network_list = dbapi.interface_networks_get_by_network_type(networktype)
        for iface_network in iface_network_list:
            host = host_index.get(iface_network.forihostid, None)
            if not host:
                continue
            for family, query_dict in route_query_values.items():
                gateway_address = gateway_addresses.get(family, None)
                if gateway_address:
                    create_dict = query_dict.copy()
                    create_dict['gateway'] = gateway_address
                    create_dict['interface_id'] = iface_network.interface_id
                    create_dict['metric'] = 1
                    host_route_create_values.setdefault(host.id, {})[family] = create_dict

    def get_route_description(route):
        return "network: {}/{}, gateway: {}, interface: {}, host: {}".format(route.network,
            route.prefix, route.gateway, route.ifname, host_index[route.forihostid].hostname)

    for host in host_index.values():
        host_route_create_dict = host_route_create_values.get(host.id, {})
        for family, query_dict in route_query_values.items():
            create_dict = host_route_create_dict.get(family, None)
            existing_routes = dbapi.routes_get_by_field_values(host.id, **query_dict)
            for route in existing_routes:
                if create_dict:
                    # If route already exists, skip creation
                    if route.interface_id == create_dict['interface_id'] and \
                            route.gateway == create_dict['gateway'] and \
                            route.metric == create_dict['metric']:
                        del host_route_create_dict[family]
                        continue
                route_descr = get_route_description(route)
                LOG.info("DC Config: Removing route to system controller: {}".format(route_descr))
                # If route exists but interface_id and gateway do not match, erase
                dbapi.route_destroy(route.id)

    for host_route_create_dict in host_route_create_values.values():
        for create_values in host_route_create_dict.values():
            interface_id = create_values.pop('interface_id')
            route = dbapi.route_create(interface_id, create_values)
            route_descr = get_route_description(route)
            LOG.info("DC Config: Added route to system controller: {}".format(route_descr))


def update_mgmt_controller_routes(dbapi, mgmt_iface_id, host=None):
    # Mirror the management routes from the mate controller.
    # Do this by copying all the routes configured on the management
    # interface on the mate controller (if it exists).

    if host:
        host_id = host.id
    else:
        mgmt_iface = dbapi.iinterface_get(mgmt_iface_id)
        host_id = mgmt_iface.forihostid
        host = dbapi.ihost_get(host_id)

    if host and host.personality != constants.CONTROLLER:
        LOG.debug("Host ID: {} is {}. Ignore route update for iface id: {}"
                  .format(host_id, host.personality, mgmt_iface_id))
        return

    controller_hosts = dbapi.ihost_get_by_personality(constants.CONTROLLER)
    mate_controller = None
    for controller_host in controller_hosts:
        if controller_host.id != host_id:
            mate_controller = controller_host
            break

    if not mate_controller:
        LOG.info("DC Config: Mate controller for host id {} not found."
                 " Routes not added.".format(host_id))
        return

    mate_interfaces = dbapi.iinterface_get_all(forihostid=mate_controller.id)
    for interface in mate_interfaces:
        if constants.NETWORK_TYPE_MGMT in interface.networktypelist:
            mate_mgmt_iface = interface
            break
    else:
        LOG.error("Management interface for host {} not found."
                  .format(mate_controller.hostname))
        return

    routes = dbapi.routes_get_by_interface(mate_mgmt_iface.id)
    for route in routes:
        new_route = {'family': route.family,
                     'network': route.network,
                     'prefix': route.prefix,
                     'gateway': route.gateway,
                     'metric': route.metric}
        try:
            dbapi.route_create(mgmt_iface_id, new_route)
        except exception.RouteAlreadyExists:
            LOG.info("DC Config: Attempting to add duplicate route to system controller.")

        LOG.info("DC Config: Added route to subcloud: {}/{} gw:{} on mgmt_iface_id: {}"
                 .format(new_route['network'], new_route['prefix'],
                         new_route['gateway'], mgmt_iface_id))


def perform_distributed_cloud_config(dbapi, mgmt_iface_id, host):
    """
    Check if we are running in distributed cloud mode and perform any
    necessary configuration.
    """
    update_mgmt_controller_routes(dbapi, mgmt_iface_id, host)
    update_routes_to_system_controller(dbapi, [host])


def is_upgrade_in_progress(dbapi):
    """ Checks whether a platform upgrade is in progress

    """
    try:
        upgrade = usm_service.get_platform_upgrade(dbapi)
        LOG.debug("Platform Upgrade in Progress: state=%s" % upgrade.state)
        return True, upgrade
    except exception.NotFound:
        LOG.debug("No Platform Upgrades in Progress")
        return False, None


def _check_upgrade(dbapi, host_obj=None):
    """ Check whether partition operation may be allowed.

        If there is an upgrade in place, reject the operation if the
        host was not created after upgrade start.
    """
    is_upgrading, upgrade = is_upgrade_in_progress(dbapi)
    if is_upgrading:
        if host_obj:
            if host_obj.created_at > upgrade.created_at:
                LOG.info("New host %s created after upgrade, allow partition" %
                         host_obj.hostname)
                return

        raise wsme.exc.ClientSideError(
            _("ERROR: Disk partition operations are not allowed during a "
              "software upgrade. Try again after the upgrade is completed."))


# TODO (mdecastr): This code is to support upgrades to stx 11,
# it can be removed in later releases.
def is_kube_apiserver_port_updated():
    return (os.path.exists(constants.KUBE_APISERVER_PORT_UPDATED) or
            not os.path.exists(constants.USM_UPGRADE_IN_PROGRESS))


def get_dhcp_client_iaid(mac_address):
    """Retrieves the client IAID from its MAC address."""
    hwaddr = list(int(byte, 16) for byte in mac_address.split(':'))
    return hwaddr[2] << 24 | hwaddr[3] << 16 | hwaddr[4] << 8 | hwaddr[5]


def is_filesystem_supported(fs, personality):
    """ Check to see if a filesystem is supported for the host personality.
    """

    if personality in constants.FILESYSTEM_HOSTS_SUPPORTED_LIST_DICT:
        if fs in constants.FILESYSTEM_HOSTS_SUPPORTED_LIST_DICT[personality]:
            return True
    return False


def get_current_fs_size(fs_name):
    """ Get the filesystem size from the lvdisplay command.
    """

    volume_name = fs_name + "-lv"

    args = ["lvdisplay",
            "--columns",
            "--options",
            "lv_size,lv_name",
            "--units",
            "g",
            "--noheading",
            "--nosuffix",
            "/dev/cgts-vg/" + volume_name]

    size_gib = 0

    with open(os.devnull, "w") as fnull:
        try:
            lvdisplay_output = subprocess.check_output(  # pylint: disable=not-callable
                    args, stderr=fnull, universal_newlines=True)
        except subprocess.CalledProcessError:
            raise Exception("Failed to get filesystem %s size" % fs_name)

        lvdisplay_dict = output_to_dict(lvdisplay_output)
        size_gib = int(math.ceil(float(lvdisplay_dict.get(volume_name))))
        if not size_gib:
            raise Exception("Unexpected size_gib=%s" % size_gib)

    return size_gib


def get_cgts_vg_free_space():
    """Determine free space in cgts-vg"""

    try:
        # Determine space in cgts-vg in GiB
        vg_free_str = subprocess.check_output(  # pylint: disable=not-callable
            ['vgdisplay', '-C', '--noheadings', '--nosuffix',
             '-o', 'vg_free', '--units', 'g', 'cgts-vg'],
            close_fds=True, universal_newlines=True).rstrip()
        cgts_vg_free = int(float(vg_free_str))
    except subprocess.CalledProcessError:
        LOG.error("Command vgdisplay failed")
        raise Exception("Command vgdisplay failed")

    return cgts_vg_free


def read_filtered_directory_content(dirpath, *filters):
    """ Reads the content of a directory, filtered on
    glob like expressions.

    Returns a dictionary, with the "key" being the filename
    and the "value" being the content of that file
    """
    def filter_directory_files(dirpath, *filters):
        return it.chain.from_iterable(glob.iglob(dirpath + '/' + filter)
                                      for filter in filters)

    content_dict = {}
    for filename in filter_directory_files(dirpath, *filters):
        content = ""
        with open(os.path.join(filename), 'rb') as obj:
            content = obj.read()
        try:
            # If the filter specified binary files then
            # these will need to be base64 encoded so that
            # they can be transferred over RPC and stored in DB
            content.decode('utf-8')
        except UnicodeError:
            content = base64.encode_as_text(content)
            content_dict['base64_encoded_files'] = \
                content_dict.get("base64_encoded_files", []) + [filename]

        content_dict[filename] = content
    return content_dict


def get_disk_capacity_mib(device_node):

    # Check if the device_node is a full path, if not assume
    # /dev/<device_node>
    if device_node[0] != "/":
        device_node = os.path.join('/dev', device_node)

    # Run command
    fdisk_command = 'fdisk -l %s | grep "^Disk %s:"' % (
        device_node, device_node)

    try:
        fdisk_output, _ = execute(fdisk_command, check_exit_code=[0],
                                  run_as_root=True, attempts=3,
                                  shell=True)
    except exception.ProcessExecutionError:
        LOG.error("Error running fdisk command: %s" %
                  fdisk_command)
        return 0

    # Parse output
    second_half = fdisk_output.split(',')[1]
    size_bytes = second_half.split()[0].strip()

    # Convert bytes to MiB (1 MiB = 1024 * 1024 bytes)
    int_size = int(size_bytes)
    size_mib = int_size // (1024 ** 2)

    return int(size_mib)


def parse_range_set(range_string):
    """ Return a non-sorted list specified by a range string."""
    # TODO: add UTs for this.

    # Parse a range string as specified by format_range_set() below
    # Be generous dealing with duplicate entries in the specification.
    if not range_string:
        return []
    ranges = [
        (lambda sublist: range(sublist[0], sublist[-1] + 1))
        (list(map(int, subrange.split('-')))) for subrange in range_string.split(',')]
    return list(set([y for x in ranges for y in x]))


def format_range_set(items):
    # Generate a pretty-printed value of ranges, such as 3-6,8-9,12-17
    ranges = []
    for k, iterable in it.groupby(enumerate(sorted(items)),
                                         lambda x: x[1] - x[0]):
        rng = list(iterable)
        if len(rng) == 1:
            s = str(rng[0][1])
        else:
            s = "%s-%s" % (rng[0][1], rng[-1][1])
        ranges.append(s)
    return ','.join(ranges)


def get_numa_index_list(obj):
    """Create map of objects indexed by numa node"""
    obj_lists = collections.defaultdict(list)
    for index, o in enumerate(obj):
        o["_index"] = index
        obj_lists[o.numa_node].append(o)
    return obj_lists


def format_ceph_mon_address(ip_address, service_port_mon):
    return '%s:%d' % (format_url_address(ip_address), service_port_mon)


def get_files_matching(path, pattern):
    return [(root, file) for root, dirs, files in os.walk(path, topdown=True)
            for file in files if file.endswith(pattern)]


def extract_tarfile(target_dir, tarfile, demote_user=False):
    with open(os.devnull, "w") as fnull:
        try:
            if demote_user:
                tarcmd_str = 'tar -xf ' + tarfile + ' -m --no-same-owner ' +\
                          '--no-same-permissions -C ' + target_dir
                cmd = ['su', '-s', '/bin/bash', constants.SYSINV_USERNAME,
                       '-c', tarcmd_str]
            else:
                cmd = ['tar', '-xf', tarfile, '-m', '--no-same-owner',
                       '--no-same-permissions', '-C', target_dir]

            subprocess.check_call(cmd, stdout=fnull, stderr=fnull)  # pylint: disable=not-callable

            return True
        except subprocess.CalledProcessError as e:
            LOG.error("Error while extracting tarfile %s: %s" % (tarfile, e))
            return False


def is_app_applied(dbapi, app_name):
    """ Checks whether the application is applied successfully.
    """
    try:
        return dbapi.kube_app_get(app_name).active
    except exception.KubeAppNotFound:
        return False


def find_openstack_app(dbapi):
    return dbapi.kube_app_get_endswith(constants.HELM_APP_OPENSTACK)


def is_openstack_applied(dbapi):
    """ Checks whether the OpenStack application is applied successfully. """
    try:
        applied = find_openstack_app(dbapi).active
        LOG.debug("is Openstack app applied? %s", applied)
        return applied
    except exception.KubeAppNotFound:
        return False


def is_url(url_str):
    uri = rfc3986.uri_reference(url_str)
    validator = rfc3986.validators.Validator().require_presence_of(
        'scheme', 'host',
    ).check_validity_of(
        'scheme', 'host', 'path',
    )
    try:
        validator.validate(uri)
    except rfc3986.exceptions.RFC3986Exception:
        return False
    return True


def is_valid_domain(url_str):
    r = re.compile(
        r'^(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)'  # domain...
        r'+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'[A-Z0-9-_]*)'  # localhost, hostname
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    url = r.match(url_str)
    if url:
        return True
    else:
        return False


def is_valid_domain_or_ip(url_str):
    if url_str:
        url_without_path = url_str.split('/')[0]
        url_with_port = url_without_path.split(':')
        if len(url_with_port) <= 2:
            if is_valid_domain(url_with_port[0]):
                return True
            # check ipv4 or ipv4 with port
            return is_valid_ipv4(url_with_port[0])
        else:
            # check ipv6
            if '[' in url_without_path:
                try:
                    bkt_idx = url_without_path.index(']')
                    return is_valid_ipv6(url_without_path[1:bkt_idx])
                except Exception:
                    return False
            else:
                # check ipv6 without port
                return is_valid_ipv6(url_without_path)


def is_valid_domain_name(value):
    """ Validate domain name based on RFC specs including IDN """
    p = re.compile(
        r'^(([a-zA-Z]{1})|([a-zA-Z]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z]{1}[0-9]{1})|([0-9]{1}[a-zA-Z]{1})|'
        r'([a-zA-Z0-9][-_.a-zA-Z0-9]{0,61}[a-zA-Z0-9]))\.'
        r'([a-zA-Z]{2,13}|[a-zA-Z0-9-]{2,30}.[a-zA-Z]{2,3})$'
    )
    m = p.match(value)
    if m:
        return True
    else:
        return False


def is_valid_dns_hostname(value):
    """ Validate dns hostname with TLD based on RFC specs """
    p = re.compile(
        # Doesn't contain underscore
        r'^(?!.*?_.*?)'
        # Doesn't contain dash at the beginning of a label
        r'(?!(?:[\d\w]+?\.)?\-[\w\d\.\-]*?)'
        # Doesn't contain dash at the end of a label
        r'(?![\w\d]+?\-\.(?:[\d\w\.\-]+?))'
        # Starts with a non-limit char
        r'(?=[\w\d])'
        # Contains at least 1 dot
        r'(?=[\w\d\.\-]*?\.+[\w\d\.\-]*?)'
        # Not longer than 253 chars
        r'(?![\w\d\.\-]{254})'
        # Doesn't contain a label longer than 63 char
        r'(?!(?:\.?[\w\d\-\.]*?[\w\d\-]{64,}\.)+?)'
        # Allowed chars
        r'[\w\d\.\-]+?'
        # TLD is at most 24 characters
        r'(?<![\w\d\-]{25})$'
    )
    m = p.match(value)
    if m:
        return True
    else:
        return False


def verify_checksum(path):
    """ Find and validate the checksum file in a given directory. """
    rc = True
    for f in os.listdir(path):
        if f.endswith('.md5'):
            with open(os.devnull, "w") as fnull:
                try:
                    subprocess.check_call(['md5sum', '-c', f],  # pylint: disable=not-callable
                                          cwd=path, stdout=fnull, stderr=fnull)
                    LOG.info("Checksum file is included and validated.")
                    return rc
                except Exception as e:
                    LOG.exception(e)
                    rc = False
    LOG.info("Checksum file is not included, skipping validation.")
    return rc


def find_fluxcd_manifests_directory(path, name):
    """For FluxCD apps we expect to have one top-level manifest directory that
       contains the name of constants.APP_FLUXCD_MANIFEST_DIR. Validate that it
       is present and provide some basic validation of its structure.
    """
    def _is_fluxcd_app_compliant(path):
        """Check if the directory has the desired FluxCD app structure"""
        mandatory_components = ("base", constants.APP_ROOT_KUSTOMIZE_FILE)
        check_mandatory = all(comp in os.listdir(path)
                              for comp in mandatory_components)
        return check_mandatory

    mfiles = []
    manifest_dir_abs = os.path.join(path, constants.APP_FLUXCD_MANIFEST_DIR)
    if os.path.isdir(manifest_dir_abs) and \
       _is_fluxcd_app_compliant(manifest_dir_abs):
        mfiles.append((("{}-{}".format(name, constants.APP_FLUXCD_MANIFEST_DIR)),
                      manifest_dir_abs))
    return mfiles


def get_http_port(dbapi):
    http_port = constants.SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT
    try:
        http_port = int(dbapi.service_parameter_get_one(
            constants.SERVICE_TYPE_HTTP,
            constants.SERVICE_PARAM_SECTION_HTTP_CONFIG,
            constants.SERVICE_PARAM_HTTP_PORT_HTTP).value)
    except exception.NotFound:
        LOG.error("Failed to find service parameter for %s,%s,%s" % (
            constants.SERVICE_TYPE_HTTP,
            constants.SERVICE_PARAM_SECTION_HTTP_CONFIG,
            constants.SERVICE_PARAM_HTTP_PORT_HTTP))
    return http_port


def is_virtual_system_config(dbapi):
    try:
        virtual_system = ast.literal_eval(
            dbapi.service_parameter_get_one(
                constants.SERVICE_TYPE_PLATFORM,
                constants.SERVICE_PARAM_SECTION_PLATFORM_CONFIG,
                constants.SERVICE_PARAM_NAME_PLAT_CONFIG_VIRTUAL).value)
    except exception.NotFound:
        # Not virtual system
        virtual_system = False
    return virtual_system


def has_openstack_compute(labels):
    """Returns true if the host has the openstack compute label set """
    if not labels:
        return False

    for label in labels:
        if label.label_key == helm_common.LABEL_COMPUTE_LABEL and label.label_value:
                return helm_common.LABEL_VALUE_ENABLED == label.label_value.lower()

    # We haven't found the openstack compute node key. Return False
    return False


def has_sriovdp_enabled(labels):
    """Returns true if the sriovdp=enabled label is set """
    if not labels:
        return False

    for label in labels:
        if label.label_key == helm_common.LABEL_SRIOVDP and label.label_value:
            return helm_common.LABEL_VALUE_ENABLED == label.label_value.lower()

    # We haven't found the sriovdp node key. Return False
    return False


def has_power_management_enabled(labels):
    """Returns true if the power-management=enabled label is set """
    if not labels:
        return False

    for label in labels:
        if label.label_key == constants.KUBE_POWER_MANAGER_LABEL and label.label_value:
            return constants.KUBE_POWER_MANAGER_VALUE == label.label_value.lower()

    # We haven't found the power-management node key. Return False
    return False


def has_disable_nohz_full_enabled(labels):
    """Returns true if the disable-nohz-full=enabled label is set """
    if not labels:
        return False

    for label in labels:
        if (label.label_key == helm_common.LABEL_DISABLE_NOHZ_FULL and
                label.label_value):
            return helm_common.LABEL_VALUE_ENABLED == label.label_value.lower()

    # We haven't found the nohz_full node key. Return False
    return False


def has_vswitch_enabled(host_labels, dbapi):
    """Returns true if the vswitch label is set """
    if not host_labels:
        return False

    labels = {
        label.label_key: label.label_value for label in host_labels
    }

    # For downstream implementations of vswitch we need to have a label
    # enabling the vswitch.
    platform_vswitch = get_vswitch_type(dbapi)
    if platform_vswitch in labels:
        vswitch_label_value = labels.get(platform_vswitch)
        if vswitch_label_value:
            return helm_common.LABEL_VALUE_ENABLED == vswitch_label_value.lower()

    ovs_labels_to_types = {
        'openvswitch': [constants.VSWITCH_TYPE_OVS_DPDK],
    }

    for ovs_allowed_label in ovs_labels_to_types:
        if platform_vswitch in ovs_labels_to_types[ovs_allowed_label]:
            vswitch_label_value = labels.get(ovs_allowed_label)
            if vswitch_label_value:
                return helm_common.LABEL_VALUE_ENABLED == vswitch_label_value.lower()

    # We haven't found the platform vswitch node key. Return False
    return False


def get_vswitch_type(dbapi):
    system = dbapi.isystem_get_one()
    return system.capabilities.get('vswitch_type', None)


def is_initial_config_complete():
    return os.path.isfile(tsc.INITIAL_CONFIG_COMPLETE_FLAG)


def is_default_huge_pages_required(host):
    if not host_has_function(host, constants.WORKER):
        return False
    if is_virtual() or is_virtual_worker(host):
        return False
    return True


def is_inventory_config_complete(dbapi, forihostid):
    """Check if the initial inventory has completed
    """

    try:
        host = dbapi.ihost_get(forihostid)
        return host.inv_state == constants.INV_STATE_INITIAL_INVENTORIED
    except Exception:
        return False


def is_fqdn_ready_to_use(ignore_upgrade=False):
    """
    Return true if FQDN can be used instead of IP ADDRESS
    The use of FQDN is limited to management network
    after the bootstrap.
    During an duplex/standard upgrade the FQDN can't be used
    since the old release doesn't support it.
    """
    if (os.path.isfile(constants.ANSIBLE_BOOTSTRAP_COMPLETED_FLAG) and
        (os.path.isfile(tsc.PLATFORM_SIMPLEX_FLAG) or
         (not os.path.isfile(tsc.UPGRADE_DO_NOT_USE_FQDN) or
          ignore_upgrade))):
        return True

    return False


def is_platform_certificates_creation_enabled():
    """Check if platform certificates were created during bootstrap/upgrade
    """
    return os.path.isfile(constants.CREATE_PLATFORM_CERTIFICATES_IN_BOOTSTRAP)


def is_system_local_ca_data_from_user():
    """Check if system-local-ca data was provided by user during bootstrap/update playbook
    """
    return os.path.isfile(constants.SYSTEM_LOCAL_CA_DATA_PROVIDED)


def platform_certificates_upgraded():
    """Check if platform certificates were updated during upgrade
    """
    return os.path.isfile(constants.PLATFORM_CERTIFICATES_UPDATED_IN_UPGRADE)


def is_std_system(dbapi):
    system = dbapi.isystem_get_one()
    return system.system_type == constants.TIS_STD_BUILD


def is_aio_system(dbapi):
    system = dbapi.isystem_get_one()
    return system.system_type == constants.TIS_AIO_BUILD


def is_aio_simplex_system(dbapi):
    system = dbapi.isystem_get_one()
    return (system.system_type == constants.TIS_AIO_BUILD and
            system.system_mode == constants.SYSTEM_MODE_SIMPLEX)


def is_aio_duplex_system(dbapi):
    system = dbapi.isystem_get_one()
    return (system.system_type == constants.TIS_AIO_BUILD and
            (system.system_mode == constants.SYSTEM_MODE_DUPLEX or
             system.system_mode == constants.SYSTEM_MODE_DUPLEX_DIRECT))


def generate_synced_fluxcd_dir(app_name, app_version):
    """ FluxCD application: Top level directory. """
    return os.path.join(constants.APP_FLUXCD_DATA_PATH, app_name, app_version)


def generate_synced_fluxcd_manifests_fqpn(app_name, app_version):
    """ FluxCD application: Top level kustomize manifests directory. """
    return os.path.join(
        constants.APP_FLUXCD_DATA_PATH, app_name, app_version,
        app_name + '-' + constants.APP_FLUXCD_MANIFEST_DIR)


def generate_synced_fluxcd_metadata_fqpn(app_name, app_version):
    """ FluxCD application: Application metadata file. """
    return os.path.join(
        constants.APP_FLUXCD_DATA_PATH, app_name, app_version,
        'metadata.yaml')


def is_app_openstack(app_name):
    return app_name.endswith("openstack")


def find_app_plugin_name(app_name):
    return "openstack" if is_app_openstack(app_name) else app_name


def find_kube_app(dbapi, app_name):
    try:
        if is_app_openstack(app_name):
            app_name = find_openstack_app(dbapi).name

        app = dbapi.kube_app_get(app_name)
    except exception.KubeAppNotFound:
        LOG.exception("Application %s not found." % app_name)
        raise
    return app


def is_chart_enabled(dbapi, app_name, chart_name, namespace):
    """
    Check if the chart is enabled at an application level

    :param app_name: Application name
    :param chart_name: Chart supplied with the application
    :param namespace: Namespace where the chart will be executed

    Returns false by default since if the app is not present or overrides aren't
    present, the charts are not supposed to be enabled.
    """
    try:
        db_app = find_kube_app(dbapi, app_name)
        db_chart = dbapi.helm_override_get(db_app.id, chart_name, namespace)
    except exception.KubeAppNotFound:
        LOG.warning("is_chart_enabled: %s application unknown" % (app_name))
        return False
    except exception.HelmOverrideNotFound:
        LOG.warning("is_chart_enabled: %s/%s/%s overrides missing" % (
            app_name, chart_name, namespace))
        return False

    return db_chart.system_overrides.get(helm_common.HELM_CHART_ATTR_ENABLED,
                                         False)


def get_app_supported_kube_version(app_name, app_version):
    """Get the application supported k8s version from the synced application metadata file"""

    app_metadata_path = os.path.join(
        constants.APP_FLUXCD_DATA_PATH, app_name,
        app_version, constants.APP_METADATA_FILE)

    kube_min_version = None
    kube_max_version = None
    if (os.path.exists(app_metadata_path) and
            os.path.getsize(app_metadata_path) > 0):
        with io.open(app_metadata_path, 'r', encoding='utf-8') as f:
            y = yaml.safe_load(f)
            supported_kube_version = y.get('supported_k8s_version', {})
            kube_min_version = supported_kube_version.get('minimum', None)
            kube_max_version = supported_kube_version.get('maximum', None)
    return kube_min_version, kube_max_version


def app_reapply_flag_file(app_name):
    return "%s.%s" % (
        constants.APP_PENDING_REAPPLY_FLAG,
        app_name)


def app_reapply_pending_fault_entity(app_name):
    return "%s=%s" % (
        fm_constants.FM_ENTITY_TYPE_APPLICATION,
        app_name)


def get_local_docker_registry_auth():
    registry_password = keyring.get_password(
        constants.DOCKER_REGISTRY_USER, "services")

    if not registry_password:
        raise exception.DockerRegistryCredentialNotFound(
            name=constants.DOCKER_REGISTRY_USER)

    return dict(username=constants.DOCKER_REGISTRY_USER,
                password=registry_password)


def get_aws_ecr_registry_credentials(dbapi, registry, username, password):
    def _set_advanced_config_for_botocore_client(dbapi):
        """ This function is to set advanced configuration
            for botocore client

        supported configuration:
            proxies(optional): A dictionary of proxy servers
                to use by protocal or endpoint.
                e.g.:
                {'http': 'http://128.224.150.2:3128',
                'https': 'http://128.224.150.2:3129'}

        """
        config = None

        proxies = dbapi.service_parameter_get_all(
            service=constants.SERVICE_TYPE_DOCKER,
            section=constants.SERVICE_PARAM_SECTION_DOCKER_PROXY)

        proxies_dict = {}
        for proxy in proxies:
            if proxy.name == constants.SERVICE_PARAM_NAME_DOCKER_HTTP_PROXY:
                proxies_dict.update({'http': str(proxy.value)})

            elif proxy.name == constants.SERVICE_PARAM_NAME_DOCKER_HTTPS_PROXY:
                proxies_dict.update({'https': str(proxy.value)})

        if proxies_dict:
            config = Config(proxies=proxies_dict)
        return config

    try:
        region = re.compile("[0-9]*.dkr.ecr.(.*).amazonaws.com.*").match(registry)
        if region:
            ecr_region = region.groups()[0]
        else:
            ecr_region = 'us-west-2'

        config = _set_advanced_config_for_botocore_client(dbapi)
        client = boto3.client(
            'ecr',
            region_name=ecr_region,
            aws_access_key_id=username,
            aws_secret_access_key=password,
            config=config)

        response = client.get_authorization_token()
        token = response['authorizationData'][0]['authorizationToken']
        username, password = base64.decode_as_text(token).split(':')
    except Exception as e:
        raise exception.SysinvException(_(
            "Failed to get AWS ECR credentials: %s" % e))

    return dict(username=username, password=password)


def extract_ca_private_key_bytes_from_pem(pem_content):
    """ Extract key from the PEM file bytes

    :param pem_content: bytes from PEM file where we'll get the key
    from. It could be pkcs1 or pkcs8 encoded.
    :return base64_crt: extracted key base64 encoded
    """
    found_marker = False
    for begin_marker in [constants.BEGIN_PRIVATE_KEY_MARKER,
                         constants.BEGIN_RSA_PRIVATE_KEY_MARKER]:
        begin_search = pem_content.find(begin_marker)
        if begin_search >= 0:
            found_marker = True
            break

    if not found_marker:
        raise exception.InvalidKubernetesCA

    found_marker = False
    for end_marker in [constants.END_PRIVATE_KEY_MARKER,
                       constants.END_RSA_PRIVATE_KEY_MARKER]:
        end_search = pem_content.find(end_marker)
        if end_search >= 0:
            found_marker = True
            end_search += len(end_marker)
            break

    if not found_marker:
        raise exception.InvalidKubernetesCA

    base64_key = base64.encode_as_text(pem_content[begin_search:end_search])
    return base64_key


def extract_ca_crt_bytes_from_pem(pem_content):
    """ Extract certificate from the PEM file bytes

    :param pem_content: bytes from PEM file where we'll get the certificate
    :return base64_crt: extracted certificate base64 encoded
    """
    begin_search = pem_content.find(constants.BEGIN_CERTIFICATE_MARKER)
    if begin_search < 0:
        raise exception.InvalidKubernetesCA

    end_search = pem_content.find(constants.END_CERTIFICATE_MARKER)
    if end_search < 0:
        raise exception.InvalidKubernetesCA

    end_search += len(constants.END_CERTIFICATE_MARKER)
    base64_crt = base64.encode_as_text(pem_content[begin_search:end_search])
    return base64_crt


def extract_certs_from_pem(pem_contents):
    """
    Extract certificates from a pem string

    :param pem_contents: A string in pem format
    :return certs: A list of x509 cert objects
    """
    start = 0
    certs = []
    while True:
        index = pem_contents.find(constants.BEGIN_CERTIFICATE_MARKER, start)
        if index == -1:
            break
        try:
            cert = x509.load_pem_x509_certificate(pem_contents[index::],
                                                  default_backend())
        except Exception:
            LOG.exception(_("Load pem x509 certificate failed at file "
                            "location: %s") % index)
            raise exception.SysinvException(_(
                "Failed to load pem x509 certificate"))

        certs.append(cert)
        start = index + len(constants.BEGIN_CERTIFICATE_MARKER)
    return certs


def check_cert_validity(cert):
    """
    Perform checks on the validity period of a certificate
    """
    now = datetime.datetime.utcnow()
    msg = ("certificate is not valid before %s nor after %s" %
            (cert.not_valid_before, cert.not_valid_after))
    LOG.info(msg)
    if now <= cert.not_valid_before or now >= cert.not_valid_after:
        msg = ("certificate is not valid before %s nor after %s" %
                (cert.not_valid_before, cert.not_valid_after))
        LOG.info(msg)
        return msg
    if cert.not_valid_after - cert.not_valid_before < datetime.timedelta(days=1):
        msg = ("The certificate has less than 24h of duration, "
               "please upload a certificate with a longer duration")
        LOG.info(msg)
        return msg
    if cert.not_valid_after - now < datetime.timedelta(days=1):
        msg = ("The certificate will expire in less than 24h, "
               "please upload a certificate with a longer expiration date")
        LOG.info(msg)
        return msg
    return None


def is_ca_cert(cert):
    """
    Check if the certificate is a CA certficate

    :param cert: the certificate to be checked
    :return: True is the certificate is a CA certificate, otherwise
             False
    """
    # extract "ca" value from cert extensions
    is_ca = False
    try:
        basic_constraints = cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.BASIC_CONSTRAINTS)
        value = getattr(basic_constraints, 'value', None)
        if value:
            is_ca = getattr(value, 'ca', False)
    except x509.ExtensionNotFound:
        LOG.debug("The cert doesn't have BASIC_CONSTRAINTS extension")
        pass
    return is_ca


def get_cert_issuer_hash(cert):
    """
    Get the hash value of the cert's issuer DN

    :param cert: the certificate to get issuer from
    :return: The hash value of the cert's issuer DN
    """
    try:
        public_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM)
        cert_c = crypto.load_certificate(crypto.FILETYPE_PEM, public_bytes)
        hash_issuer = cert_c.get_issuer().hash()
    except Exception:
        LOG.exception()
        raise exception.SysinvException(_(
            "Failed to get certificate issuer hash."))

    return hash_issuer


def get_cert_issuer_string_hash(cert):
    """
    Get the hash value of the cert's issuer DN

    :param cert: the certificate to get issuer from
    :return: The hash value of the cert's issuer DN
    """
    try:
        public_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM)
        cert_c = crypto.load_certificate(crypto.FILETYPE_PEM, public_bytes)

        # get the issuer object from the loaded certificate
        cert_issuer = cert_c.get_issuer()

        # for each component presented on certificate issuer,
        # converts the respective name and value for strings and join all
        # together
        issuer_attributes = "".join("/{0:s}={1:s}".format(name.decode(),
                                                           value.decode())
                                     for name, value in
                                         cert_issuer.get_components())

        # apply the hash function to binary form of the string above and
        # digest it as a hexdecimal value, and take the first 16 bytes.
        hashed_attributes = \
            hashlib.md5(issuer_attributes.encode()).hexdigest()[:16]

        LOG.debug("hashed issuer attributes %s from certificate "
                 % hashed_attributes)
    except Exception:
        LOG.exception()
        raise exception.SysinvException(_(
            "Failed to get certificate issuer hash."))

    return hashed_attributes


def get_cert_serial(cert):
    try:
        public_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM)
        cert_c = crypto.load_certificate(crypto.FILETYPE_PEM, public_bytes)
        serial_number = cert_c.get_serial_number()
    except Exception:
        LOG.exception()
        raise exception.SysinvException(_(
            "Failed to get certificate serial number."))
    return serial_number


def get_cert_IPAddresses(cert):
    """ Given a cert, extracts the IP addresses listed in SAN

    :param cert: a x509 certificate which is going to be used
    :return: a list of strings representing the respective IP addresses
    """
    try:
        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        addresses = ext.value.get_values_for_type(x509.IPAddress)
    except Exception:
        raise exception.SysinvException(_(
            "Failed to get certificate SAN's IPAddresses."))
    return [format(ips) for ips in addresses]


def get_cert_DNSNames(cert):
    """ Given a cert, extracts the DNS names listed in SAN

    :param cert: a x509 certificate which is going to be used
    :return: a list of strings representing the respective DNS names
    """
    try:
        ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        dns_names = ext.value.get_values_for_type(x509.DNSName)
    except Exception:
        raise exception.SysinvException(_(
            "Failed to get certificate SAN's DNSNames."))
    return dns_names


def get_cert_subject_hash(cert):
    """
    Get the hash value of the cert's subject DN

    :param cert: the certificate to get subject from
    :return: The hash value of the cert's subject DN
    """
    try:
        public_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM)
        cert_c = crypto.load_certificate(crypto.FILETYPE_PEM, public_bytes)
        hash_subject = cert_c.get_subject().hash()
    except Exception:
        LOG.exception()
        raise exception.SysinvException(_(
            "Failed to get certificate subject hash."))

    return hash_subject


def get_cert_subject_string_hash(cert):
    """
    Get the hash value of the cert's subject DN

    :param cert: the certificate to get subject from
    :return: The hash value of the cert's subject DN
    """
    try:
        public_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM)
        cert_c = crypto.load_certificate(crypto.FILETYPE_PEM, public_bytes)

        # get the subject object from the loaded certificate
        cert_subject = cert_c.get_subject()

        # for each component presented on certificate subject,
        # converts the respective name and value for strings and join all
        # together
        subject_attributes = "".join("/{0:s}={1:s}".format(name.decode(),
                                                           value.decode())
                                     for name, value in
                                         cert_subject.get_components())

        # apply the hash function to binary form of the string above and
        # digest it as a hexdecimal value, and take the first 16 bytes.
        hashed_attributes = \
            hashlib.md5(subject_attributes.encode()).hexdigest()[:16]

        LOG.info("hashed subject attributes %s from certificate "
                % hashed_attributes)
    except Exception:
        LOG.exception()
        raise exception.SysinvException(_(
            "Failed to get certificate subject hash."))

    return hashed_attributes


def get_certificate_from_file(file_path, index=0):
    """ Extract certificate from a specific file

    :param file_path: the absolute path of the file which has the certificate
    :index: index of certificate in the list returns from the extract_certs_from_pem()
    :returns: a x509.Certificate object that will store information regarding this certificate
    """
    LOG.debug("extracting information of certificate in %s" % file_path)
    try:
        with open(file_path, 'rb') as file_data:
            file_data.seek(0, os.SEEK_SET)
            read_file = file_data.read()
            certificate = extract_certs_from_pem(read_file)[index]
    except Exception as e:
        LOG.warning("No certificate was extracted from file %s"
                    "due to %s" % (file_path, e))
        return None
    return certificate


def build_cert_identifier(cert):
    """ Builds a certificate identifier.

    This identifier will consist of a hash from certificate
    issuer representation and its serial number

    :param cert: x509.Certificate object
    :returns: a string in the format of the identifier <issuer_hash>-<serial_number>
    """
    hash_subject = get_cert_issuer_string_hash(cert)
    serial_number = get_cert_serial(cert)
    cert_id = '%s-%s' % (hash_subject, serial_number)
    return cert_id


def add_certificate_subject(subject, spec):
    """ Utility method to build a subject data structure along
        k8s Certificate resources. This method supports addition of
        Organization (O), OrganizationalUnits (OU), Country (C) and
        State/Province (ST).

        :param subject: a dictionary with keys respective to the
        subject fields mentioned above.
        :param spec: a dicitionary specifying the Certificate.spec that
        is going to be used on the resource creation.
    """
    certificate_subject = {}
    # the template we're using to build Certificate resource doesn't
    # accept fields with None or empty values. We just add fields below
    # if they are specified by the user, otherwise we simply ignore them.
    if subject.get('O'):
        spec['organization'] = [subject.get('O')]
    if subject.get('CN'):
        spec['commonName'] = subject.get('CN')
    if subject.get('OU'):
        certificate_subject['organizationalUnits'] = [subject.get('OU')]
    if subject.get('C'):
        certificate_subject['countries'] = [subject.get('C')]
    if subject.get('ST'):
        certificate_subject['provinces'] = [subject.get('ST')]
    if subject.get('L'):
        certificate_subject['localities'] = [subject.get('L')]
    spec['subject'] = certificate_subject
    return spec


def calculate_k8s_component_certificate_duration():
    """ Calculate the duration to be set in the Certificates of various
    k8s components in kube rootca update procedure. The default
    standard duration is 1 year, but if the new root CA has less than 1 year
    of validation, these certificates will be set to have the same duration as
    the root CA certificate.
    """
    year_period = 8760  # number of hours in 1 year period
    new_rootca_cert = get_certificate_from_file(kubernetes.KUBERNETES_NEW_ROOTCA_CERT)
    validation_period = new_rootca_cert.not_valid_after - new_rootca_cert.not_valid_before
    duration = validation_period.days * 24
    if duration > year_period:
        duration = year_period
    return duration


def format_image_filename(device_image):
    """ Format device image filename """
    return "{}-{}-{}-{}.bit".format(device_image.bitstream_type,
                                    device_image.pci_vendor,
                                    device_image.pci_device,
                                    device_image.uuid)


def format_admin_endpoint_cert(tls_key, tls_cert):
    return '%s\n%s' % (tls_key.strip('\n'), tls_cert.strip('\n'))


def get_admin_ep_cert(dc_role):
    """
    Get endpoint certificate data from kubernetes
    :param dc_role:
    :return: data dict {'dc_root_ca_crt': '<dc root ca crt>,
                        'admin_ep_crt': '<admin endpoint crt> }
             or None if the node is not a DC controller
    raise KubeNotConfigured exception when kubernetes is not configured
    raise Exception for kubernetes data errors
    """
    if dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
        endpoint_cert_secret_name = constants.DC_ADMIN_ENDPOINT_SECRET_NAME
        endpoint_cert_secret_ns = 'dc-cert'
    elif dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
        endpoint_cert_secret_name = constants.SC_ADMIN_ENDPOINT_SECRET_NAME
        endpoint_cert_secret_ns = 'sc-cert'
    else:
        return None

    secret_data = {'ca_crt': None, 'admin_ep_crt': None}
    kube = kubernetes.KubeOperator()
    secret = kube.kube_get_secret(
        endpoint_cert_secret_name, endpoint_cert_secret_ns)

    if not hasattr(secret, 'data'):
        raise Exception('Invalid secret %s\\%s' % (
            endpoint_cert_secret_ns, endpoint_cert_secret_name
        ))

    data = secret.data
    if 'tls.crt' not in data or 'tls.key' not in data:
        raise Exception("Invalid admin endpoint certificate data.")

    try:
        tls_crt = base64.decode_as_text(data['tls.crt'])
        tls_key = base64.decode_as_text(data['tls.key'])
    except TypeError:
        raise Exception('admin endpoint secret is invalid %s' %
                        endpoint_cert_secret_name)

    if dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SUBCLOUD:
        try:
            with open(constants.DC_ROOT_CA_CONFIG_PATH, 'r') as f:
                ca_crt = f.read()
        except Exception as e:
            # this is an error condition, but would be likely to be repaired
            # when intermediate or root ca is renewed.
            # but the operation should not stop here, b/c if admin endpoint
            # certificate is not updated, system controller may lost
            # access to the subcloud admin endpoints which will make the
            # situation impossible to recover.
            LOG.error('Cannot read DC root CA certificate %s' % e)
    elif dc_role == constants.DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER:
        try:
            ca_crt = base64.decode_as_text(data['ca.crt'])
        except TypeError:
            raise Exception('admin endpoint secret is invalid %s' %
                            endpoint_cert_secret_name)

    secret_data['dc_root_ca_crt'] = ca_crt
    secret_data['admin_ep_crt'] = "%s%s" % (tls_key, tls_crt)
    return secret_data


def check_k8s_resource_ready(object_dict):
    for item in object_dict.get('status', {}).get('conditions', {}):
        if item.get('type', None) == 'Ready':
            return True
    return False


def get_secret_type(secret_name, secret_ns):
    """
    Get k8s secret type
    :param secret_name: the name of the secret
    :param secret_ns: the namespace of the secret
    :return: secret type as string in lowercase or None if secret isn't found
    raise Exception if thrown by kubernetes api
    """
    kube = kubernetes.KubeOperator()
    try:
        secret = kube.kube_get_secret(secret_name, secret_ns)
        if secret is not None:
            return secret.type.lower()
        else:
            return None
    except Exception as e:
        LOG.error("Could not retrieve secret type: %s" % str(e))
        raise


def get_certificate_from_secret(secret_name, secret_ns):
    """
    Get certificate from k8s secret
    :param secret_name: the name of the secret
    :param secret_ns: the namespace of the secret
    :return: tls_crt: the certificate.
             tls_key: the corresponding private key of the certificate.
             ca_crt: the CA certificate that issued tls_crt if available.
    raise Exception for kubernetes data errors
    """
    kube = kubernetes.KubeOperator()
    secret = kube.kube_get_secret(secret_name, secret_ns)

    if not hasattr(secret, 'data'):
        raise Exception('Invalid secret %s\\%s' % (secret_ns, secret_name))

    data = secret.data
    if 'tls.crt' not in data or 'tls.key' not in data:
        raise Exception('Invalid certificate data from secret %s\\%s' %
                (secret_ns, secret_name))

    try:
        tls_crt = base64.decode_as_text(data['tls.crt'])
        tls_key = base64.decode_as_text(data['tls.key'])
        if 'ca.crt' in data:
            ca_crt = base64.decode_as_text(data['ca.crt'])
        else:
            LOG.warning("Secret doesn't have CA data stored:  %s\\%s" %
                        (secret_ns, secret_name))
            ca_crt = ''
    except TypeError:
        raise Exception('Certificate secret data is invalid %s\\%s' %
                (secret_ns, secret_name))

    return tls_crt, tls_key, ca_crt


def get_ca_certificate_from_opaque_secret(secret_name, secret_ns):
    """
    Get a CA certificate from a k8s opaque secret (tls secret requires
    both tls.crt and tls.key present, a CA certificate alone can be stored
    as an opaque secret ca.crt)
    :param secret_name: the name of the secret
    :param secret_ns: the namespace of the secret
    :return: ca_crt: the CA certificate.
    raise Exception for kubernetes data errors
    """
    kube = kubernetes.KubeOperator()
    secret = kube.kube_get_secret(secret_name, secret_ns)

    if not hasattr(secret, 'data'):
        raise Exception('Invalid secret %s\\%s' % (secret_ns, secret_name))

    data = secret.data
    if 'ca.crt' not in data:
        raise Exception('Invalid CA certificate data from secret %s\\%s' %
                (secret_ns, secret_name))

    try:
        ca_crt = base64.decode_as_text(data['ca.crt'])
    except TypeError:
        raise Exception('CA certificate secret data is invalid %s\\%s' %
                (secret_ns, secret_name))

    return ca_crt


# TODO(mdecastr): verify replacing cert verification methods that
#                 rely on proc calls w/ lib cryptography
def verify_self_signed_ca_cert(crt):
    with tempfile.NamedTemporaryFile() as tmpfile:
        tmpfile.write(crt.encode('utf8'))
        tmpfile.flush()
        cmd = ['openssl', 'verify', '-no-CApath', '-CAfile', tmpfile.name, tmpfile.name]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True)
        stdout, stderr = proc.communicate()
        proc.wait()
        if 0 == proc.returncode:
            return True
        else:
            LOG.info('Provided CA cert is not self-signed\n%s\n%s\n%s' %
                     (crt, stdout, stderr))
            return False


def verify_cert_issuer(cert, issuer):
    if cert == issuer:
        return verify_self_signed_ca_cert(cert)

    tmpfile_crt = tempfile.NamedTemporaryFile()
    tmpfile_crt.write(
        extract_certs_from_pem(cert.encode('utf-8'))[-1].public_bytes(serialization.Encoding.PEM))
    tmpfile_crt.flush()

    tmpfile_issuer = tempfile.NamedTemporaryFile()
    tmpfile_issuer.write(
        extract_certs_from_pem(issuer.encode('utf-8'))[0].public_bytes(serialization.Encoding.PEM))
    tmpfile_issuer.flush()

    cmd = ['openssl', 'verify', '-partial_chain', '-trusted', tmpfile_issuer.name, tmpfile_crt.name]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True)
    stdout, stderr = proc.communicate()
    proc.wait()
    if 0 == proc.returncode:
        return True
    else:
        LOG.error('Provided issuer does not match cert\n%s\n%s\n%s' %
                    (cert + issuer, stdout, stderr))
        return False


def verify_cert_chain_trusted(cert_chain):
    certs = extract_certs_from_pem(cert_chain.encode('utf-8'))
    certs_number = len(certs)

    for index, cert in enumerate(certs):
        if index == certs_number - 1:
            return verify_cert_against_trusted_bundle(
                cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'))

        if not verify_cert_issuer(cert.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
                                  certs[index + 1].public_bytes(serialization.Encoding.PEM).decode('utf-8')):
            LOG.error('Provided cert chain cannot be verified as trusted\n%s\n%s\n%s' % cert_chain)
            return False


def verify_cert_against_trusted_bundle(crt):
    with tempfile.NamedTemporaryFile() as tmpfile:
        tmpfile.write(crt.encode('utf8'))
        tmpfile.flush()
        cmd = ['openssl', 'verify', '-trusted', constants.SSL_CERT_CA_FILE_SHARED, tmpfile.name]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True)
        stdout, stderr = proc.communicate()
        proc.wait()
        if 0 == proc.returncode:
            return True
        else:
            LOG.info('Provided cert cannot be verified as trusted\n%s\n%s\n%s' %
                    (crt, stdout, stderr))
            return False


def verify_ca_crt(crt):
    with tempfile.NamedTemporaryFile() as tmpfile:
        tmpfile.write(crt.encode('utf8'))
        tmpfile.flush()
        cmd = ['openssl', 'verify', '-CAfile', tmpfile.name]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True)

        stdout, stderr = proc.communicate(input=crt)
        proc.wait()
        if 0 == proc.returncode:
            return True
        else:
            LOG.info('Provided CA cert is invalid\n%s\n%s\n%s' %
                     (crt, stdout, stderr))
            return False


def verify_intermediate_ca_cert(ca_crt, tls_crt):
    with tempfile.NamedTemporaryFile() as tmpfile:
        tmpfile.write(ca_crt.encode('utf8'))
        tmpfile.flush()
        cmd = ['openssl', 'verify', '-CAfile', tmpfile.name]
        proc = subprocess.Popen(cmd, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                universal_newlines=True)

        stdout, stderr = proc.communicate(input=tls_crt)
        proc.wait()
        if 0 == proc.returncode:
            return True
        else:
            LOG.info('Provided intermediate CA cert is invalid\n%s\n%s\n%s' %
                     (tls_crt, stdout, stderr))
            return False


def get_root_ca_cert():
    secret_name = constants.DC_ADMIN_ROOT_CA_SECRET_NAME
    dc_ns = constants.DC_ADMIN_ENDPOINT_NAMESPACE
    kube = kubernetes.KubeOperator()
    secret = kube.kube_get_secret(secret_name, dc_ns)

    if not hasattr(secret, 'data'):
        raise Exception('Invalid secret %s\\%s' % (dc_ns, secret_name))

    data = secret.data
    try:
        ca_crt = base64.decode_as_text(data['ca.crt'])
    except TypeError:
        raise Exception('Secret is invalid %s' % secret_name)

    secret_data = {'dc_root_ca_crt': ca_crt}
    return secret_data


def run_playbook(playbook_command):
    exec_env = os.environ.copy()
    exec_env["ANSIBLE_LOG_PATH"] = "/dev/null"
    proc = subprocess.Popen(playbook_command, stdout=subprocess.PIPE,
            env=exec_env, universal_newlines=True)
    out, _ = proc.communicate()
    LOG.info("ansible-playbook: %s." % out)
    return proc.returncode


def generate_random_password(length=16):
    """
    Generate a random password with as least one uppercase, one lowercase,
    one number and one of the special characters in [!*_-+=] (the square
    brackets are not included).

    :param length: the length of the password
    :return: the password in unicode
    :raises exception.SysinvException: if password length is less than minimum
    """
    if length < constants.MINIMUM_PASSWORD_LENGTH:
        msg = _("Length %s is below required minimum %s") % \
               (length, constants.MINIMUM_PASSWORD_LENGTH)
        raise exception.SysinvException(msg)

    randomer = random.SystemRandom()

    # Possible password characters
    norm_chars = string.ascii_uppercase \
                  + string.ascii_lowercase \
                  + string.digits
    special_chars = "!*_-+="
    password_chars = norm_chars + special_chars

    # As least one uppercase, one lowercase, one digit and one special
    # character.
    at_least_chars = randomer.choice(string.ascii_uppercase) \
                     + randomer.choice(string.ascii_lowercase) \
                     + randomer.choice(string.digits) \
                     + randomer.choice(special_chars)

    password = at_least_chars \
               + ''.join(randomer.choice(password_chars)
                         for i in range(length - len(at_least_chars) - 1))

    # Shuffle the password to mix the at least to have characters
    password_list = list(password)
    randomer.shuffle(password_list)

    # The leading char is always an ascii char or a number.
    password = randomer.choice(norm_chars) + ''.join(password_list)

    # Return the password in unicode
    if six.PY2:
        password = password.decode()
    return password


def get_upgradable_hosts(dbapi):
    """
    Get hosts that could be upgraded.
    """
    all_hosts = dbapi.ihost_get_list()
    # TODO:(mingyuan) Exclude edgeworker host from upgradable hosts
    # until the final phase of the edgeworker feature completed
    hosts = [i for i in all_hosts if i.personality != constants.EDGEWORKER]

    return hosts


def deep_get(nested_dict, keys, default=None):
    """Get a value from nested dictionary."""
    if not isinstance(nested_dict, dict):
        raise exception.SysinvException(_(
            "Expected a dictionary, cannot get keys {}.".format(keys)))

    def _reducer(d, key):
        if isinstance(d, dict):
            return d.get(key, default)
        return default

    return functools.reduce(_reducer, keys, nested_dict)


@contextlib.contextmanager
def TempDirectory():
    tmpdir = tempfile.mkdtemp()
    os.chmod(tmpdir, stat.S_IRWXU)
    try:
        yield tmpdir
    finally:
        try:
            LOG.debug("Cleaning up temp directory %s" % tmpdir)
            shutil.rmtree(tmpdir)
        except OSError as e:
            LOG.error(_('Could not remove tmpdir: %s'), str(e))


def get_stevedore_major_version():
    if six.PY2:
        # Hardcode Stevedore 1.25.0 for CentOS7 that has Python2.
        # Support for Python2 will be dropped soon, and this removed.
        return 1

    package = 'stevedore'
    if USE_IMPORTLIB_METADATA_STDLIB:
        distribution = importlib.metadata.distribution
    else:
        distribution = importlib_metadata.distribution

    return int(distribution(package).version.split('.')[0])


def get_distribution_from_entry_point(entry_point):
    """
    With Stevedore 3.0.0 the entry_point object was changed.
    https://docs.openstack.org/releasenotes/stevedore/victoria.html

    This affects some of our Stevedore based logic on Debian Bullseye which
    currently uses Stevedore 3.2.2.

    In Python3.9.2 used on Debian Bullseye the EntryPoint returned by
    importlib does not hold a reference to a Distribution object.
    https://bugs.python.org/issue42382

    Determine the missing information by parsing all modules in Python3 envs.
    This can be removed when Python will be patched or upgraded.

    :param entry_point: An EntryPoint object
    :return: A Distribution object
    :raises exception.SysinvException: If distribution could not be found
    """
    # Just a refactor on this path
    if get_stevedore_major_version() < 3:
        return entry_point.dist

    if six.PY2:
        raise exception.SysinvException(_(
            "Python2 + Stevedore 3 and later support not implemented: "
            "parsing modules in Python2 not implemented."))

    loaded_entry_point = entry_point.load()
    if isinstance(loaded_entry_point, types.ModuleType):
        module_path = loaded_entry_point.__file__
    else:
        module_path = sys.modules[loaded_entry_point.__module__].__file__
    if USE_IMPORTLIB_METADATA_STDLIB:
        distributions = importlib.metadata.distributions
    else:
        distributions = importlib_metadata.distributions

    for distribution in distributions():
        try:
            relative = pathlib.Path(module_path).relative_to(
                distribution.locate_file("")
            )
        except ValueError:
            pass
        else:
            if distribution.files and relative in distribution.files:
                return distribution

    raise exception.SysinvException(_(
            "Distribution information for entry point {} "
            "could not be found.".format(entry_point)))


def get_project_name_and_location_from_distribution(distribution):
    """
    With Stevedore 3.0.0 the entry_point object was changed.
    https://docs.openstack.org/releasenotes/stevedore/victoria.html

    This affects some of our Stevedore based logic on Debian Bullseye which
    currently uses Stevedore 3.2.2.

    Determine the missing information by parsing the Distribution object.

    :param distribution: A Distribution object
    :return: Tuple of project name and project location. Location being
             the parent of directory named <project name>
    """
    # Just a refactor on this path
    if get_stevedore_major_version() < 3:
        return (distribution.project_name, distribution.location)

    project_name = distribution.metadata.get('Name')
    project_location = str(distribution._path.parent)
    return (project_name, project_location)


def get_module_name_from_entry_point(entry_point):
    """
    With Stevedore 3.0.0 the entry_point object was changed.
    https://docs.openstack.org/releasenotes/stevedore/victoria.html

    This affects some of our Stevedore based logic on Debian Bullseye which
    currently uses Stevedore 3.2.2.

    :param entry_point: An EntryPoint object
    :return: Module name
    :raises exception.SysinvException: If module name could not be found
    """
    if 'module_name' in dir(entry_point):
        return entry_point.module_name
    elif 'module' in dir(entry_point):
        return entry_point.module

    raise exception.SysinvException(_(
            "Module name for entry point {} "
            "could not be determined.".format(entry_point)))


def get_mpath_from_dm(dm_device):
    """Get mpath node from /dev/dm-N"""
    mpath_device = None

    context = pyudev.Context()

    pydev_device = pyudev.Devices.from_device_file(context, dm_device)

    device_mapper_name = pydev_device.get("DM_NAME", "")
    if constants.DEVICE_NAME_MPATH in device_mapper_name:
        device_mapper_mpath = pydev_device.get("DM_MPATH", None)
        if device_mapper_mpath:
            mpath_device = os.path.join("/dev/mapper", device_mapper_mpath)
        else:
            mpath_device = os.path.join("/dev/mapper", device_mapper_name)

    return mpath_device


def get_part_device_path(disk_device_path, part_number):
    """Get the partition device path.
    :param   disk_device_path: the device path of the disk on which the
             partition resides
    :param   part_number: the partition number
    :returns the partition device path
    """
    part_device_path = '{}-part{}'.format(disk_device_path, part_number)
    return part_device_path


def get_part_number(part_device_path):
    """Obtain the number of a partition.
    :param    part_device_path: the partition's device path
    :returns  the partition's number
    """
    part_num = ""
    if 'by-path' in part_device_path or 'by-id' in part_device_path:
        part_num = re.match('.*?([0-9]+)$', part_device_path).group(1)
    return part_num


def is_part_of_disk(part_device_path, disk_device_path):
    """Check if a partition is part of a disk
    :param    part_device_path: the partition's device path
    :param    disk_device_path: the disk's device path
    :returns  the partition's number
    """
    is_part_of_disk = False

    if disk_device_path in part_device_path:
        is_part_of_disk = True
    elif constants.DEVICE_NAME_MPATH in disk_device_path:
        path_split = disk_device_path.split(constants.DEVICE_NAME_MPATH)
        if (path_split[0] in part_device_path and
                path_split[1] in part_device_path):
            is_part_of_disk = True

    return is_part_of_disk


def replace_helmrepo_url_with_floating_address(dbapi, helmrepository_url):
    """Replaces the repo url with the network addr floating address

    :param    helmrepository_url: repo url defined in the app
    :returns  repo url replaced with the floating address of the controller
    """

    parsed_helm_repo_url = urlparse(helmrepository_url)
    sc_network = \
        dbapi.network_get_by_type(constants.NETWORK_TYPE_CLUSTER_HOST)
    sc_network_addr_pool = \
        dbapi.address_pool_get(sc_network.pool_uuid)
    sc_float_ip = sc_network_addr_pool.floating_address
    if is_valid_ipv6(sc_float_ip):
        sc_float_ip = '[' + sc_float_ip + ']'

    return "http://{}:{}{}".format(
        sc_float_ip,
        get_http_port(dbapi),
        parsed_helm_repo_url.path
    )


def get_system_ca_file():
    """Return path to system default CA file."""
    # Standard CA file locations for Debian/Ubuntu, RedHat/Fedora,
    # Suse, FreeBSD/OpenBSD
    ca_path = ['/etc/ssl/certs/ca-certificates.crt',
               '/etc/pki/tls/certs/ca-bundle.crt',
               '/etc/ssl/ca-bundle.pem',
               '/etc/ssl/cert.pem']
    for ca in ca_path:
        if os.path.exists(ca):
            return ca
    return None


def is_host_filesystem_enabled(dbapi, host_id_or_uuid, fs_name):
    """Check if a host filesystem is present """
    filesystems = dbapi.host_fs_get_by_ihost(host_id_or_uuid)
    for fs in filesystems:
        if fs.name == fs_name:
            return True
    return False


def get_enabled_controller_filesystem(dbapi, fs_name):
    """Check if a controller filesystem is present """
    filesystems = dbapi.controller_fs_get_list()
    for fs in filesystems:
        if (fs.name == fs_name):
            return fs
    return None


def count_local_monitors_assigned(dbapi):
    """ Count hostfs with monitor function """
    count = 0
    hostfs_list = dbapi.host_fs_get_list()
    for fs in hostfs_list:
        if fs['name'] == constants.FILESYSTEM_NAME_CEPH:
                functions = fs['capabilities']['functions']
                if constants.FILESYSTEM_CEPH_FUNCTION_MONITOR in functions:
                    count += 1
    return count


def is_floating_monitor_assigned(dbapi):
    try:
        controller_fs = dbapi.controller_fs_get_by_name(
                            constants.FILESYSTEM_NAME_CEPH_DRBD)
        functions = controller_fs.capabilities.get('functions', [])
        if constants.FILESYSTEM_CEPH_FUNCTION_MONITOR in functions:
            return True
    except exception.ControllerFSNameNotFound:
        pass
    return False


def get_rpm_package(load_version, package_name):
    """Search for a package or its initial characters in a specific
    load version. First, it will look in the patch directory, if it
    doesn't find it, it will look in the feed directory.

    :param   load_version: the load version where the package is located.
    :param   package_name: the package name or its initial characters.
    :returns the package full path or None if not found.
    """
    packages_dir = [
        "/var/www/pages/updates/rel-%s/Packages/" % load_version,
        "/var/www/pages/feed/rel-%s/Packages/" % load_version,
    ]

    for package_dir in packages_dir:
        if not os.path.isdir(package_dir):
            continue

        for package in os.listdir(package_dir):
            if package.startswith(package_name):
                return os.path.join(package_dir, package)


def extract_rpm_package(rpm_package, target_dir):
    try:
        rpm2cpio_cmd = subprocess.run(
            ["rpm2cpio", rpm_package],
            capture_output=True,
            check=True,
        )

        subprocess.run(
            ["cpio", "-idm", "-D", target_dir],
            input=rpm2cpio_cmd.stdout,
            check=True,
        )
    except Exception as error:
        raise exception.SysinvException(
            "Error extracting rpm %s: %s" % (rpm_package, error),
        )


def get_ostree_commit(ostree_repo):
    repo_arg = "--repo=%s" % ostree_repo

    try:
        refs = subprocess.run(
            ["ostree", repo_arg, "refs"],
            capture_output=True,
            check=True,
            text=True,
        )

        commit = subprocess.run(
            ["ostree", repo_arg, "log", refs.stdout],
            capture_output=True,
            check=True,
            text=True,
        )
    except Exception as error:
        raise exception.SysinvException(
            "Error getting ostree commit: %s" % (error),
        )

    result = commit.stdout.split()

    if result[0] != "commit":
        return None

    return result[1]


def checkout_ostree(ostree_repo, commit, target_dir, subpath):
    repo_arg = "--repo=%s" % ostree_repo
    path_arg = None

    if subpath:
        path_arg = "--subpath=%s" % subpath

    try:
        subprocess.run(
            ["ostree", repo_arg, path_arg, "--union", "checkout", commit, target_dir],
            check=True,
        )
    except Exception as error:
        raise exception.SysinvException(
            "Error checkout ostree commit: %s" % (error),
        )


def is_bundle_extension_valid(filename):
    """Check if application bundles have the correct extension

    :param filename: Bundle filename
    :return: Returns True if the extension is correct.
             Otherwise returns False.
    """

    file_extension = pathlib.Path(filename).suffix
    return file_extension.lower() == ".tgz"


def get_host_mgmt_ip(dbapi, host_obj):
    """Return the host's management network primary address

    :param dbapi: the database api
    :param host_obj: the host object

    :return: the address in string format, or None if not found
    """
    if host_obj.hostname:
        hostname = host_obj.hostname

        if host_obj.hostname == constants.CONTROLLER_0_HOSTNAME:

            # During mgmt network reconfiguration, do not change the mgmt IP
            # in maintencance as it will be updated after the unlock.
            if os.path.isfile(tsc.MGMT_NETWORK_RECONFIGURATION_ONGOING):
                return gethostbyname(constants.CONTROLLER_0_FQDN)

            system = dbapi.isystem_get_one()
            if (system.capabilities.get('simplex_to_duplex_migration') or
                    system.capabilities.get('simplex_to_duplex-direct_migration')):
                        # during migration, controller-0 is still using the mgmt floating address,
                        # the unit address will be available only after unlock to finish
                        # migration to DX
                        hostname = constants.CONTROLLER_HOSTNAME

        addr_name = format_address_name(hostname, constants.NETWORK_TYPE_MGMT)
        addr_obj = get_primary_address_by_name(dbapi, addr_name,
                                               constants.NETWORK_TYPE_MGMT)
        if addr_obj:
            return addr_obj.address
    return None


def get_primary_address_by_name(dbapi, db_address_name, networktype, raise_exc=False):
    """Search address by database name to retrieve the relevant address from
       the primary pool, if multiple entries for the same name are found, the
       query will use the network's pool_uuid to get the address family (IPv4 or
       IPv6) related to the primary.

    :param dbapi: the database api reference
    :param db_address_name: the address name in the database
    :param networktype: the network type
    :param raise_exc: raise AddressNotFoundByName instead of returning None

    :return: the address object if found, None otherwise
    """
    if (
        is_aio_simplex_system(dbapi)
        and networktype in (
            constants.NETWORK_TYPE_ADMIN,
            constants.NETWORK_TYPE_MGMT,
            constants.NETWORK_TYPE_CLUSTER_HOST,
            constants.NETWORK_TYPE_STORAGE,
            constants.NETWORK_TYPE_PXEBOOT,
        )
        and db_address_name == f"{constants.CONTROLLER_0_HOSTNAME}-{networktype}"
    ):
        db_address_name = f"{constants.CONTROLLER_HOSTNAME}-{networktype}"
    else:
        system = dbapi.isystem_get_one()
        if (system.capabilities.get('simplex_to_duplex_migration') or
                system.capabilities.get('simplex_to_duplex-direct_migration')) and \
                db_address_name == f"{constants.CONTROLLER_0_HOSTNAME}-{networktype}":
            if len(dbapi.address_get_by_name(db_address_name)) == 0:
                db_address_name = f"{constants.CONTROLLER_HOSTNAME}-{networktype}"

    # first search directly by name
    address = dbapi.address_get_by_name(db_address_name)
    if len(address) == 0:
        # if there is no match by name return here
        LOG.info(f"address {db_address_name} not found, returning")
        if raise_exc:
            raise exception.AddressNotFoundByName(name=db_address_name)
        return None

    # if there is a single entry, return here
    if len(address) == 1:
        return address[0]

    # if there are more than one entry, it is dual-stack, search the primary pool
    # to return the desired IP based on address family
    if len(address) > 1:
        address = None
        try:
            # there only one network per type
            networks = dbapi.networks_get_by_type(networktype)
            if networks:
                if networks[0].pool_uuid:
                    pool = dbapi.address_pool_get(networks[0].pool_uuid)
                    address = dbapi.address_get_by_name_and_family(db_address_name,
                                                                   pool.family)
            else:
                LOG.info(f"cannot find network for type {networktype}")

        except exception.AddressNotFoundByNameAndFamily:
            LOG.info(f"cannot find address for name={db_address_name} with"
                     f" network type={networktype}")
            pass
        except Exception as ex:
            LOG.info(f"get_primary_address_by_name general exception: {str(ex)}")

    if not address and raise_exc:
        raise exception.AddressNotFoundByName(name=db_address_name)
    return address


def get_secondary_address_by_name(dbapi, db_address_name, networktype, raise_exc=False):
    """Search address by database name to retrieve the relevant address from
       the secondary pool, if multiple entries for the same name are found, the
       query will use the network's pool_uuid to get the address family (IPv4 or
       IPv6) related to the secondary.

    :param dbapi: the database api reference
    :param db_address_name: the address name in the database
    :param networktype: the network type
    :param raise_exc: raise AddressNotFoundByName instead of returning None

    :return: the address object if found, None otherwise
    """
    address = None
    secondary_pool = None

    if not db_address_name or not networktype:
        LOG.err(f"no db_address_name={db_address_name} or networktype={networktype} provided")
        return address

    if (
        is_aio_simplex_system(dbapi)
        and networktype in (
            constants.NETWORK_TYPE_MGMT,
            constants.NETWORK_TYPE_CLUSTER_HOST,
        )
        and db_address_name == f"{constants.CONTROLLER_0_HOSTNAME}-{networktype}"
    ):
        db_address_name = f"{constants.CONTROLLER_HOSTNAME}-{networktype}"
    else:
        system = dbapi.isystem_get_one()
        if (system.capabilities.get('simplex_to_duplex_migration') or
                system.capabilities.get('simplex_to_duplex-direct_migration')) and \
                db_address_name == f"{constants.CONTROLLER_0_HOSTNAME}-{networktype}":
            if len(dbapi.address_get_by_name(db_address_name)) == 0:
                db_address_name = f"{constants.CONTROLLER_HOSTNAME}-{networktype}"

    try:
        networks = dbapi.networks_get_by_type(networktype)
        if networks and len(networks) == 1:
            net_pools = dbapi.network_addrpool_get_by_network_id(networks[0].id)
            if len(net_pools) == 2 and networks[0].pool_uuid:
                for net_pool in net_pools:
                    if net_pool.address_pool_uuid != networks[0].pool_uuid:
                        # this is the secondary
                        secondary_pool = dbapi.address_pool_get(net_pool.address_pool_uuid)
            else:
                LOG.debug(f"network {networks[0].type},{networks[0].pool_uuid} have"
                         f" {len(net_pools)} pools")
        else:
            LOG.debug(f"It is only possible to have one network obj for networktype={networktype}")

        if secondary_pool:
            address = dbapi.address_get_by_name_and_family(db_address_name,
                                                           secondary_pool.family)

    except exception.AddressPoolNotFound:
        LOG.debug(f"cannot find address pool for name={db_address_name} with"
                  f" network type={networktype}")
        pass
    except exception.AddressNotFoundByNameAndFamily:
        LOG.debug(f"cannot find secondary address for name={db_address_name} with"
                  f" network type={networktype} and family={secondary_pool.family}")
        pass
    except Exception as ex:
        LOG.info(f"get_secondary_address_by_name general exception: {str(ex)}")
        pass

    if not address and raise_exc:
        raise exception.AddressNotFoundByName(name=db_address_name)
    return address


def update_config_file(config_filepath: str, values_to_update: list):
    """Update a config file with the desired information

    :param config_filepath: Path of the config file
    :param values_to_update: List of dicts with the following format
        values_to_update = [
            {'section': '<section-name1>', 'key': '<key1>', 'value': 'value1'},
            {'section': '<section-name2>', 'key': '<key2>', 'value': 'value2'},
            {'section': '<section-name3>', 'key': '<key3>', 'value': 'value3'},
        ]
    Note: It was opted to do it this way because the configparser from std library
          doesn't preserve comments when writing to a file.
    """
    with open(config_filepath, 'r') as file:
        lines = file.readlines()

    for value_to_update in values_to_update:
        section = value_to_update['section']
        key = value_to_update['key']
        value = value_to_update['value']

        if not (section and key and value):
            raise Exception('Invalid config to update: Neither section, key or '
                            'value can be blank. Provided config: '
                            f'{section=}, {key=}, {value=}')

        key_value = f"{key}={value}\n"
        current_section = None
        temp_section = None
        sections_list = []
        line_index_to_update = None
        line_index_to_insert = None

        for list_index, line in enumerate(lines):
            # Ignore lines until first section definition
            if not (current_section or line.startswith('[')):
                continue
            if line.startswith('['):
                current_section = line.strip('\n[]')
                if (temp_section and
                        current_section != temp_section and
                        temp_section == section):
                    # We changed sections, but the previous was the desired one,
                    # meaning we should add the line to the specified index
                    # if already defined (after key comment) or at current position
                    # if it's not (append at the end of section)
                    if not line_index_to_insert:
                        line_index_to_insert = list_index
                    break
                temp_section = current_section
                sections_list.append(current_section)
            if current_section != section:
                # Current section is not the one we're searching, keep skipping
                # until we reach the correct one
                continue
            if line.startswith('#') and ' = ' in line:
                # Line is a comment and has an example value
                current_key = line.lstrip('# ').split(' ')[0]
                if current_key == key:
                    # Add 1 to insert at the line right after the comment
                    line_index_to_insert = list_index + 1
            elif not line.startswith('#') and line.strip() != "":
                # Line is not a comment and it's not empty, so it has a config value
                current_key = line.split('=')[0]
                if current_key == key:
                    line_index_to_update = list_index
                    break
        if line_index_to_update:
            lines[line_index_to_update] = key_value
        elif line_index_to_insert:
            lines.insert(line_index_to_insert, key_value)
        else:
            if section not in sections_list:
                # Desired section does not exist, create it at the end of the file
                lines.append(f'[{section}]\n')
            lines.append(key_value)
    with open(config_filepath, 'w') as file:
        file.writelines(lines)


def get_cert_values(cert_obj):
    data = {}
    x509v3_extn = "X509v3 extensions"
    critical = "critical"
    data[constants.RESIDUAL_TIME] = "{}d".format(
        (cert_obj.not_valid_after - datetime.datetime.now()).days)
    data["Version"] = cert_obj.version.name
    data["Serial Number"] = hex(cert_obj.serial_number)
    data["Issuer"] = cert_obj.issuer.rfc4514_string()
    data[constants.VALIDITY] = {}
    data[constants.VALIDITY][constants.NOT_BEFORE] = cert_obj.not_valid_before.strftime(
        '%B %d %H:%M:%S %Y')
    data[constants.VALIDITY][constants.NOT_AFTER] = cert_obj.not_valid_after.strftime(
        '%B %d %H:%M:%S %Y')
    data["Subject"] = cert_obj.subject.rfc4514_string()
    if hasattr(cert_obj.public_key(), 'key_size'):
        pub_key_info = {}
        key_size = cert_obj.public_key().key_size
        pub_key_info['key_size'] = f"({key_size} bit)"
        data["Subject Public Key Info"] = pub_key_info
    data[x509v3_extn] = {}
    for ext in cert_obj.extensions:
        ext_value = ext.value
        if isinstance(ext_value, x509.extensions.KeyUsage):
            ext_name = "X509v3 Key Usage"
            data[x509v3_extn][ext_name] = {}
            value = ""
            if ext_value.digital_signature:
                value = f"{value}Digital Signature"
            if ext_value.key_encipherment:
                value = f"{value}, Key Encipherment"
            if ext_value.content_commitment:
                value = f"{value}, Content Commitment"
            if ext_value.data_encipherment:
                value = f"{value}, Data Encipherment"
            if ext_value.key_agreement:
                value = f"{value}, Key Agreement"
            if ext_value.crl_sign:
                value = f"{value}, CRL Sign" if value else f"{value}CRL Sign"
            if value:
                data[x509v3_extn][ext_name]["values"] = value
            if ext.critical:
                data[x509v3_extn][ext_name][critical] = ext.critical
        elif isinstance(ext_value, x509.extensions.BasicConstraints):
            ext_name = "X509v3 Basic Constraints"
            data[x509v3_extn][ext_name] = {}
            data[x509v3_extn][ext_name]["CA"] = ext_value.ca
            if ext.critical:
                data[x509v3_extn][ext_name][critical] = ext.critical
        elif isinstance(ext_value, x509.extensions.AuthorityKeyIdentifier):
            identifier = {}
            if hasattr(ext_value, 'key_identifier'):
                identifier["keyid"] = ext_value.key_identifier.hex()
            if ext.critical:
                identifier[critical] = ext.critical
            if identifier:
                data[x509v3_extn]["X509v3 Authority Key Identifier"] = identifier
        elif isinstance(ext_value, x509.extensions.SubjectKeyIdentifier):
            identifier = {}
            if hasattr(ext_value, 'key_identifier'):
                identifier["keyid"] = ext_value.key_identifier.hex()
            if ext.critical:
                identifier[critical] = ext.critical
            if identifier:
                data[x509v3_extn]["X509v3 Subject Key Identifier"] = identifier
        elif isinstance(ext_value, x509.extensions.SubjectAlternativeName):
            ext_name = "X509v3 Subject Alternative Name"
            data[x509v3_extn][ext_name] = {}
            dns_names = get_cert_DNSNames(cert_obj)
            ip_addresses = get_cert_IPAddresses(cert_obj)
            if dns_names:
                data[x509v3_extn][ext_name]["DNS"] = get_cert_DNSNames(cert_obj)
            if ip_addresses:
                data[x509v3_extn][ext_name]["IP Address"] = get_cert_IPAddresses(cert_obj)
    data["Signature Algorithm"] = getattr(cert_obj.signature_algorithm_oid, '_name')
    data["Signature"] = cert_obj.signature.hex()
    return data


def get_secrets_info(secrets_list=None):
    kube_operator = kubernetes.KubeOperator()
    certificates = kube_operator.list_custom_resources("cert-manager.io", "v1", "certificates")
    certs_secrets_list = [cert["spec"]["secretName"] for cert in certificates]
    k8s_secrets = []
    if secrets_list:
        if not isinstance(secrets_list, list):
            secrets_list = [secrets_list, ]
        for secret, ns in secrets_list:
            secret_obj = kube_operator.kube_get_secret(secret, ns)
            if secret_obj:
                k8s_secrets.append(secret_obj)
    else:
        opaque_secrets = kube_operator.kube_list_secret_for_all_namespaces(selector='type=Opaque')
        tls_secrets = kube_operator.kube_list_secret_for_all_namespaces(
            selector='type=kubernetes.io/tls')
        k8s_secrets = opaque_secrets + tls_secrets

    cert_suf = ("cert", "crt", "ca", "pem", "cer")
    certs_info = {}
    for secret in k8s_secrets:
        if hasattr(secret, 'data') and secret.data is not None:
            secret_name = secret.metadata.name
            if secret_name == "kubeadm-certs":
                continue
            ns = secret.metadata.namespace
            secret_type = secret.type
            renewal = "Manual"
            if secret_name in certs_secrets_list:
                renewal = "Automatic"
            if secret_type == "Opaque":
                for key, val in secret.data.items():
                    # exception for cm-cert-manager-webhook-ca opaque secret
                    if secret_name == "cm-cert-manager-webhook-ca":
                        renewal = "Automatic"
                    # list elastic-services,kibana cert from "mon-elastic-services-secrets" secret
                    if secret_name == "mon-elastic-services-secrets":
                        if key not in ["ext-elastic-services.crt", "kibana.crt", "ca.crt",
                                       "ext-ca.crt"]:
                            continue
                    if key.endswith(cert_suf) and val:
                        cert_name = f"{secret_name}/{key}"
                        crt = base64.decode_as_bytes(val)
                        cert_obj = extract_certs_from_pem(crt)[0]
                        certs_info[cert_name] = get_cert_values(cert_obj)
                        certs_info[cert_name][constants.NAMESPACE] = ns
                        certs_info[cert_name][constants.SECRET] = secret_name
                        certs_info[cert_name][constants.RENEWAL] = renewal
                        certs_info[cert_name][constants.SECRET_TYPE] = secret_type
            elif secret_type == "kubernetes.io/tls":
                # exception for sc-adminep-ca-certificate tls secret as there is no
                # corresponding certificate exist.
                if secret_name == "sc-adminep-ca-certificate":
                        renewal = "Automatic"
                cert_name = secret_name
                crt = base64.decode_as_bytes(secret.data.get('tls.crt'))
                cert_obj = extract_certs_from_pem(crt)[0]
                certs_info[cert_name] = get_cert_values(cert_obj)
                certs_info[cert_name][constants.NAMESPACE] = ns
                certs_info[cert_name][constants.SECRET] = secret_name
                certs_info[cert_name][constants.RENEWAL] = renewal
                certs_info[cert_name][constants.SECRET_TYPE] = secret_type

    LOG.debug(certs_info)
    return certs_info


def get_drbd_secure_config(dbapi):

    sp_names = {
        'hmac': constants.SERVICE_PARAM_NAME_DRBD_HMAC,
        'secret': constants.SERVICE_PARAM_NAME_DRBD_SECRET,
        'secure': constants.SERVICE_PARAM_NAME_DRBD_SECURE,
    }
    service = constants.SERVICE_TYPE_PLATFORM
    section = constants.SERVICE_PARAM_SECTION_PLATFORM_DRBD
    conf = {
        'hmac': 'sha1',
        'secret': "",
        'secure': 'False',
    }

    for key in sp_names:
        try:
            val = dbapi.service_parameter_get_one(
                service,
                section,
                sp_names[key])
            conf[key] = val.value

        except exception.NotFound:
            LOG.info("System parameter %s does not exist", key)
    LOG.info("get_drbd_secure_config: conf=%s", str(conf))

    return conf


def update_drbd_secure_config(dbapi, conf):

    LOG.info("update_drbd_secure_config: conf=%s", str(conf))
    sp_names = {
        'hmac': constants.SERVICE_PARAM_NAME_DRBD_HMAC,
        'secret': constants.SERVICE_PARAM_NAME_DRBD_SECRET,
        'secure': constants.SERVICE_PARAM_NAME_DRBD_SECURE,
    }

    service = constants.SERVICE_TYPE_PLATFORM
    section = constants.SERVICE_PARAM_SECTION_PLATFORM_DRBD

    conf['secure'] = conf['secure'].title()
    for key in sp_names:
        try:
            val = dbapi.service_parameter_get_one(
                service,
                section,
                sp_names[key])
            if conf[key] != val.value:
                dbapi.service_parameter_update(
                    val.uuid, {'value': conf[key]})

        except exception.NotFound:
            LOG.info("System parameter %s does not exist", key)
            try:
                dbapi.service_parameter_create({
                    'uuid': uuidutils.generate_uuid(),
                    'service': service,
                    'section': section,
                    'name': sp_names[key],
                    'value': conf[key],
                })
            except exception.NotFound:
                msg = _("Service parameter add failed:  "
                        "service %s section %s name %s value %s"
                        % (service, section, key, conf[key]))
                raise wsme.exc.ClientSideError(msg)


def get_resources_list_via_kubectl_kustomize(manifest_dir):
    """
    Executes the 'kubectl kustomize' command in the specified directory and returns the
    generated output.

    :param manifests_dir: String path of the directory containing the kustomization.yaml file.

    :return: List of dictionaries for each resource.
    """
    resources_list = []

    try:
        cmd = ['kubectl', 'kustomize', manifest_dir]

        process = subprocess.Popen(cmd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True)

        stdout, stderr = process.communicate()

        if process.returncode != 0:
            LOG.error(f"Error executing kubectl kustomize: {stderr}")
            return resources_list

        # Split the output into individual YAML resources
        yaml_resources = stdout.split('---')
        # Parse each YAML resource
        resources_list = \
            [yaml.safe_load(resource) for resource in yaml_resources if resource.strip()]

    except Exception as e:
        LOG.error(f"Error when trying to extract the return of the \
                  command 'kubectl kustomize {manifest_dir}', reason: {e}")

    return resources_list


def filter_helm_objects(resources, kind):
    """
    Filters the resources to include only those with the parameterized kind".

    param: resources: The list of dictionaries representing the KRM resources.

    Returns: List of dictionaries containing the requested kind.
    """

    return [resource for resource in resources if resource.get('kind') == kind]


def filter_helm_releases(resources):
    """
    Filters the resources to include only those with kind 'HelmRelease'.

    param: resources: The list of dictionaries representing the KRM resources.

    Returns: List of dictionaries with kind 'HelmRelease'.
    """

    return filter_helm_objects(resources, 'HelmRelease')


def filter_helm_repositories(resources):
    """
    Filters the resources to include only those with kind 'HelmRepository'.

    param: resources: The list of dictionaries representing the KRM resources.

    Returns: List of dictionaries with kind 'HelmRepository'.
    """

    return filter_helm_objects(resources, 'HelmRepository')


def is_certificate_request_created(name):
    """
    Verify if there is a CertificateRequest already created with this name

    param: name: The name of the resource to check

    Returns: True or False
    """

    try:
        cmd = ['kubectl', '--kubeconfig', kubernetes.KUBERNETES_ADMIN_CONF,
               '-n', constants.CERT_NAMESPACE_PLATFORM_CERTS, 'get',
               constants.CERT_REQUEST_RESOURCE, name]

        process = subprocess.Popen(cmd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True)

        stdout, stderr = process.communicate()

        if process.returncode != 0:
            return False

        if name in str(stdout):
            return True

    except Exception as e:
        LOG.error(f"Error trying to retrieve CertificateRequest resource info, reason: {e}")

    return False


def run_kubectl(cmd):
    """Run a kubectl command and return stdout, stderr)."""
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True
    )

    stdout, stderr = process.communicate()

    return stdout.strip("'"), stderr.strip("'")


def get_certificate_request(name):
    """
    Get a CertificateRequest resource

    Param: name: The name of the resource to get the content

    Return: The content of the CertificateRequest resource
    """

    try:
        # Try a few times to wait for the certificaterequest to be ready
        interval = 2
        count = 3
        for i in range(count):
            # check if the certificaterequest is ready
            cmd = ['kubectl', '--kubeconfig', kubernetes.KUBERNETES_ADMIN_CONF,
                   '-n', constants.CERT_NAMESPACE_PLATFORM_CERTS, 'get',
                   constants.CERT_REQUEST_RESOURCE, name, '-o',
                   "jsonpath='{.status.conditions[?(@.type==\"Ready\")].status}'"]
            ready, stderr = run_kubectl(cmd)

            # certificaterequest is ready
            if ready == "True":
                break

            if i == count - 1:
                raise exception.SysinvException("CertificateRequest %s is not ready "
                                                "in %s seconds." % (name, interval * count))
            LOG.info(f"{name} is not ready: {stderr}. Will retry in {interval} seconds ...")
            time.sleep(interval)

        # Try a few times to retrieve the certificate from the certificaterequest
        interval = 2
        count = 3
        for i in range(count):
            cmd = ['kubectl', '--kubeconfig', kubernetes.KUBERNETES_ADMIN_CONF,
                   '-n', constants.CERT_NAMESPACE_PLATFORM_CERTS, 'get',
                   constants.CERT_REQUEST_RESOURCE, name, '-o',
                   "jsonpath='{.status.certificate}'"]
            cert, stderr = run_kubectl(cmd)

            # The certificate is retrieved
            if cert:
                break

            if i == count - 1:
                raise exception.SysinvException("Certificate %s is not retrieved "
                                                "in %s seconds." % (name, interval * count))
            LOG.info(f"{name} is still empty: {stderr}. Will retry in {interval} seconds ...")
            time.sleep(interval)

        return cert

    except Exception as e:
        LOG.error(f"Error trying to get CertificateRequest resource, reason: {e}")

    return None


def delete_certificate_request(name):
    """
    Delete a CertificateRequest resource

    Param: The name of the resource to delete

    Return: True or False
    """

    try:
        cmd = ['kubectl', '--kubeconfig', kubernetes.KUBERNETES_ADMIN_CONF,
               '-n', constants.CERT_NAMESPACE_PLATFORM_CERTS, 'delete',
               constants.CERT_REQUEST_RESOURCE, name]

        process = subprocess.Popen(cmd,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True)

        stdout, stderr = process.communicate()

        if process.returncode != 0:
            LOG.error(f"Failed to delete CertificateRequest resource. {stderr}")
            return False

        return True

    except Exception as e:
        LOG.error(f"Error trying to delete CertificateRequest resource, reason: {e}")

    return False


def truncate_message(message, max_length=255):
    """Truncate a progress message to fit within the database field limit.

    :param message: The progress message to truncate.
    :param max_length: The maximum allowed length for the message (default is 255).
    :returns: The truncated message.
    """
    if not isinstance(message, str):
        raise ValueError("Message must be a string.")
    if max_length <= 0:
        raise ValueError("Maximum length must be a positive integer.")
    return (message[:max_length - 3] + '...') if len(message) > max_length else message


def update_app_status(rpc_app, new_status=None, new_progress=None):
    """Update the status and progress of an application in the database.

    :param rpc_app: The application object to update.
    :param new_status: The new status to set for the application.
    :param new_progress: The new progress message to set for the application.
    """
    if new_status is not None:
        rpc_app.status = new_status

    # Define a persistent lock object at the module level
    rpc_app_lock = threading.Lock()

    # New progress info can contain large messages from exceptions raised.
    # It may need to be truncated to fit the corresponding database field.
    if new_progress is not None:
        new_progress = truncate_message(new_progress)
        rpc_app.progress = new_progress

    with rpc_app_lock:
        rpc_app.save()


def get_app_metadata_from_tarfile(absolute_tarball_path):
    """Extract metadata from a tar file.

    :params app_name: application name
    :params tarball_name: absolute path of app tarfile
    :returns: metadata dictionary
    """
    metadata = {}
    with TempDirectory() as app_path:
        if not extract_tarfile(app_path, absolute_tarball_path):
            LOG.error("Failed to extract tar file {}.".format(
                os.path.basename(absolute_tarball_path)))
            return None
        metadata_file = os.path.join(app_path,
                                     constants.APP_METADATA_FILE)

        if os.path.exists(metadata_file):
            with io.open(metadata_file, 'r', encoding='utf-8') as f:
                # The RoundTripLoader removes the superfluous quotes by default.
                # Set preserve_quotes=True to preserve all the quotes.
                # The assumption here: there is just one yaml section
                metadata = yaml.safe_load(f)

    return metadata


def compare_lists_of_dict(dependent_parent_list, dependent_parent_exceptions):
    """
    Compare two lists of dictionaries to determine if they are equivalent.
    This function converts the input lists of dictionaries into sets of tuples,
    where each tuple represents the key-value pairs of a dictionary. It then
    compares the two sets for equality.
    Args:
        dependent_parent_list (list[dict]): A list of dictionaries representing
            the first set of dependent parents.
        dependent_parent_exceptions (list[dict]): A list of dictionaries representing
            the second set of dependent parents to compare against.
    Returns:
        bool: True if the two lists are equivalent (contain the same dictionaries),
              False otherwise.
    """
    # Convert both lists to sets of tuples for easier comparison
    set_parent_list = {tuple(item.items()) for item in dependent_parent_list}
    set_parent_exceptions = {tuple(item.items()) for item in dependent_parent_exceptions}

    # Compare the sets
    return set_parent_list == set_parent_exceptions


def pmon_restart_service(service_name):
    """Restart a systemd service using pmon

    :param: service_name: string: Name of the service to be restarted
    :raises: SysinvException upon failure
    """
    try:
        cmd = [constants.PMON_RESTART_FULL_PATH, service_name]
        execute(*cmd, check_exit_code=0)
        LOG.info("Service %s pmon-restarted successfully" % (service_name))
    except Exception as ex:
        raise exception.SysinvException("Failed to restart the service %s with error: [%s]"
                                        % (service_name, ex))


def flatten_nested_lists(nested_lists):
    """
    Recursively flattens a nested list structure into a single flat list.

    Args:
        nested_lists (list): A list which may contain other nested lists at arbitrary depth.

    Returns:
        list: A flat list containing all the elements from the nested lists.

    Example:
        >>> flatten_nested_lists([1, [2, [3, 4], 5], 6])
        [1, 2, 3, 4, 5, 6]
    """

    flat_list = []
    for item in nested_lists:
        if isinstance(item, list):
            flat_list.extend(flatten_nested_lists(item))
        else:
            flat_list.append(item)
    return flat_list


def render_jinja_template_from_file(path_to_template, template_file_name,
                                    custom_filters=None, values=None):
    """ Render a jinja template with values passed

    :param: path_to_template: Full path to the parent directory of .j2 template file
    :param: template_file_name: .j2 template file name
    :param: custom_filters: dictionary of custom filters with built-in jinja2 filters as keys
                            and their equivalent handler methods (either library or custom)
                            as values
    :param: values: key-value pairs to be rendered
    :returns: rendered_string
    :raises: SysinvEnxception in case of an error
    """
    rendered_string = ""
    try:
        file_loader = FileSystemLoader(path_to_template)
        env = Environment(loader=file_loader, autoescape=True)
        if custom_filters:
            env.filters.update(custom_filters)
        template = env.get_template(template_file_name)
        if not values:
            values = {}
        rendered_string = template.render(values)
    except Exception as e:
        raise exception.SysinvException("Failed to render jinja template [%s] at [%s] "
                                        "with values: [%s]. Error: [%s] "
                                        % (template_file_name, path_to_template, values, e))
    return rendered_string


def verify_activate_rollback_in_progress(dbapi):
    """
    Check if a platform upgrade is currently in the 'activate rollback' state.

    Args:
        dbapi: Database API object used to access upgrade information.

    Returns:
        bool: True if an activate rollback is in progress, False otherwise.
    """

    result = False
    try:
        upgrade = usm_service.get_platform_upgrade(dbapi)
    except exception.NotFound:
        pass
    else:
        if upgrade.state in [constants.DEPLOY_STATE_ACTIVATE_ROLLBACK]:
            result = True

    return result


def remove_public_registry_port(img_tag):
    """
    Fix image tag by removing public registry port when pushing to
    the local registry.

    image goes from the incorrect format:
    registry.local:9001/public.example.com:30093/stx/some-image:some-tag

    to the compliant:
    registry.local:9001/public.example.com/stx/some-image:some-tag

    :param img_tag: str
    :return: str

    """
    regex_pattern = r"(?P<url1>.*)\/(?P<url2>.+)(?P<port>:\d+)\/(?P<image>.+)"
    substitution_pattern = "\\g<url1>/\\g<url2>/\\g<image>"

    return re.sub(regex_pattern, substitution_pattern, img_tag, 1)


def atomic_update_yaml_file(values, file_path):
    """
    Atomically updates a YAML file with the provided values.
    This function creates a temporary file within the same folder as the file_path
    parameter and updates it with the values parameter, then atomically renames the
    temporary file to the target file path. This ensures that the update is atomic
    and reduces the risk of data corruption.

    Args:
        values (iterable): The data to be written to the YAML file.
        file_path (str): The path to the YAML file to be updated.
    """

    if os.path.exists(file_path):
        # Get the directory of the file to be updated
        file_dir = os.path.dirname(file_path)
        with tempfile.TemporaryDirectory(dir=file_dir) as temp_dirname:
            # Create a temporary file path in the same directory
            temp_file_path = os.path.join(temp_dirname, os.path.basename(file_path))

            with open(temp_file_path, 'w', encoding='utf-8') as f:
                try:
                    # Write the values to the temporary file using yaml.safe_dump
                    yaml.safe_dump(values, f, default_flow_style=False)
                    LOG.debug(f"Temporary file {temp_file_path} generated")
                except Exception as e:
                    raise exception.SysinvException(
                        f"Failed to generate temporary file {temp_file_path}: {e}")
            try:
                # Atomically rename the temporary file to the target file path
                os.rename(temp_file_path, file_path)
                LOG.debug(f"Updated file {file_path} atomically with {temp_file_path}")
            except Exception as e:
                raise exception.SysinvException(f"Failed to update file "
                        f"{file_path} with temporary file {temp_file_path}: {e}")
    else:
        raise exception.SysinvException(f"File {file_path} does not exist. Cannot update.")
