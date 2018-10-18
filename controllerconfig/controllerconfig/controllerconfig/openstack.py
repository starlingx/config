#
# Copyright (c) 2014-2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

"""
OpenStack
"""

import os
import time
import subprocess

from common import log
from common.exceptions import SysInvFail
from common.rest_api_utils import get_token
import sysinv_api as sysinv


LOG = log.get_logger(__name__)

KEYSTONE_AUTH_SERVER_RETRY_CNT = 60
KEYSTONE_AUTH_SERVER_WAIT = 1  # 1sec wait per retry


class OpenStack(object):

    def __init__(self):
        self.admin_token = None
        self.conf = {}
        self._sysinv = None

        source_command = 'source /etc/platform/openrc && env'

        with open(os.devnull, "w") as fnull:
            proc = subprocess.Popen(
                ['bash', '-c', source_command],
                stdout=subprocess.PIPE, stderr=fnull)

        for line in proc.stdout:
            key, _, value = line.partition("=")
            if key == 'OS_USERNAME':
                self.conf['admin_user'] = value.strip()
            elif key == 'OS_PASSWORD':
                self.conf['admin_pwd'] = value.strip()
            elif key == 'OS_PROJECT_NAME':
                self.conf['admin_tenant'] = value.strip()
            elif key == 'OS_AUTH_URL':
                self.conf['auth_url'] = value.strip()
            elif key == 'OS_REGION_NAME':
                self.conf['region_name'] = value.strip()
            elif key == 'OS_USER_DOMAIN_NAME':
                self.conf['user_domain'] = value.strip()
            elif key == 'OS_PROJECT_DOMAIN_NAME':
                self.conf['project_domain'] = value.strip()

        proc.communicate()

    def __enter__(self):
        if not self._connect():
            raise Exception('Failed to connect')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._disconnect()

    def __del__(self):
        self._disconnect()

    def _connect(self):
        """ Connect to an OpenStack instance """

        if self.admin_token is not None:
            self._disconnect()

        # Try to obtain an admin token from keystone
        for _ in xrange(KEYSTONE_AUTH_SERVER_RETRY_CNT):
            self.admin_token = get_token(self.conf['auth_url'],
                                         self.conf['admin_tenant'],
                                         self.conf['admin_user'],
                                         self.conf['admin_pwd'],
                                         self.conf['user_domain'],
                                         self.conf['project_domain'])
            if self.admin_token:
                break
            time.sleep(KEYSTONE_AUTH_SERVER_WAIT)

        return self.admin_token is not None

    def _disconnect(self):
        """ Disconnect from an OpenStack instance """
        self.admin_token = None

    def lock_hosts(self, exempt_hostnames=None, progress_callback=None,
                   timeout=60):
        """ Lock hosts of an OpenStack instance except for host names
            in the exempt list
        """
        failed_hostnames = []

        if exempt_hostnames is None:
            exempt_hostnames = []

        hosts = sysinv.get_hosts(self.admin_token, self.conf['region_name'])
        if not hosts:
            if progress_callback is not None:
                progress_callback(0, 0, None, None)
            return

        wait = False
        host_i = 0

        for host in hosts:
            if host.name in exempt_hostnames:
                continue

            if host.is_unlocked():
                if not host.force_lock(self.admin_token,
                                       self.conf['region_name']):
                    failed_hostnames.append(host.name)
                    LOG.warning("Could not lock %s" % host.name)
                else:
                    wait = True
            else:
                host_i += 1
                if progress_callback is not None:
                    progress_callback(len(hosts), host_i,
                                      ('locking %s' % host.name),
                                      'DONE')

        if wait and timeout > 5:
            time.sleep(5)
            timeout -= 5

        for _ in range(0, timeout):
            wait = False

            for host in hosts:
                if host.name in exempt_hostnames:
                    continue

                if (host.name not in failed_hostnames) and host.is_unlocked():
                    host.refresh_data(self.admin_token,
                                      self.conf['region_name'])

                    if host.is_locked():
                        LOG.info("Locked %s" % host.name)
                        host_i += 1
                        if progress_callback is not None:
                            progress_callback(len(hosts), host_i,
                                              ('locking %s' % host.name),
                                              'DONE')
                    else:
                        LOG.info("Waiting for lock of %s" % host.name)
                        wait = True

            if not wait:
                break

            time.sleep(1)
        else:
            failed_hostnames.append(host.name)
            LOG.warning("Wait failed for lock of %s" % host.name)

        return failed_hostnames

    def power_off_hosts(self, exempt_hostnames=None, progress_callback=None,
                        timeout=60):
        """ Power-off hosts of an OpenStack instance except for host names
            in the exempt list
        """

        if exempt_hostnames is None:
            exempt_hostnames = []

        hosts = sysinv.get_hosts(self.admin_token, self.conf['region_name'])

        hosts[:] = [host for host in hosts if host.support_power_off()]
        if not hosts:
            if progress_callback is not None:
                progress_callback(0, 0, None, None)
            return

        wait = False
        host_i = 0

        for host in hosts:
            if host.name in exempt_hostnames:
                continue

            if host.is_powered_on():
                if not host.power_off(self.admin_token,
                                      self.conf['region_name']):
                    raise SysInvFail("Could not power-off %s" % host.name)
                wait = True
            else:
                host_i += 1
                if progress_callback is not None:
                    progress_callback(len(hosts), host_i,
                                      ('powering off %s' % host.name),
                                      'DONE')

        if wait and timeout > 5:
            time.sleep(5)
            timeout -= 5

        for _ in range(0, timeout):
            wait = False

            for host in hosts:
                if host.name in exempt_hostnames:
                    continue

                if host.is_powered_on():
                    host.refresh_data(self.admin_token,
                                      self.conf['region_name'])

                    if host.is_powered_off():
                        LOG.info("Powered-Off %s" % host.name)
                        host_i += 1
                        if progress_callback is not None:
                            progress_callback(len(hosts), host_i,
                                              ('powering off %s' % host.name),
                                              'DONE')
                    else:
                        LOG.info("Waiting for power-off of %s" % host.name)
                        wait = True

            if not wait:
                break

            time.sleep(1)
        else:
            failed_hosts = [h.name for h in hosts if h.is_powered_on()]
            msg = "Wait timeout for power-off of %s" % failed_hosts
            LOG.info(msg)
            raise SysInvFail(msg)

    def wait_for_hosts_disabled(self, exempt_hostnames=None, timeout=300,
                                interval_step=10):
        """Wait for hosts to be identified as disabled.
           Run check every interval_step seconds
        """
        if exempt_hostnames is None:
            exempt_hostnames = []

        for _ in xrange(timeout / interval_step):
            hosts = sysinv.get_hosts(self.admin_token,
                                     self.conf['region_name'])
            if not hosts:
                time.sleep(interval_step)
                continue

            for host in hosts:
                if host.name in exempt_hostnames:
                    continue

                if host.is_enabled():
                    LOG.info("host %s is still enabled" % host.name)
                    break
            else:
                LOG.info("all hosts disabled.")
                return True

            time.sleep(interval_step)

        return False

    @property
    def sysinv(self):
        if self._sysinv is None:
            # TOX cannot import cgts_client and all the dependencies therefore
            # the client is being lazy loaded since TOX doesn't actually
            # require the cgtsclient module.
            from cgtsclient import client as cgts_client

            endpoint = self.admin_token.get_service_url(
                self.conf['region_name'], "sysinv", "platform", 'admin')
            self._sysinv = cgts_client.Client(
                sysinv.API_VERSION,
                endpoint=endpoint,
                token=self.admin_token.get_id())

        return self._sysinv
