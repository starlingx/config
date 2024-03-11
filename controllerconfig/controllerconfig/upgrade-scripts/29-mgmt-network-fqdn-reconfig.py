#!/usr/bin/env python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This migration script is used to disable the FQDN during an upgrade
# this flag must be deleted during thr upgrade complete/abort
# during the upgrade the controller-0 runs version X
# and controller-1 runs version X+1
# to use the FQDN the active controller must run dnsmasq
# with the FQDN entries. It doesn't happen during an upgrade.
#
# during migrate stage of platform upgrade. It will:
# - create a flag that will be used by sysinv and puppet code to not
#     use FQDN entries

import sys

import subprocess
import os.path
import socket

from controllerconfig.common import log

PLATFORM_CONF_PATH = '/etc/platform'
PLATFORM_SIMPLEX_FLAG = '/etc/platform/simplex'
UPGRADE_DO_NOT_USE_FQDN = PLATFORM_CONF_PATH + \
    '/.upgrade_do_not_use_fqdn'


LOG = log.get_logger(__name__)


def remove_unused_files_from_hieradata(to_release):
    # after the upgrade it is necessary to remove the old hieradata
    # <ctrl1>.yaml from /opt/platform/puppet/<TO_RELEASE>/hieradata
    # the reason is: it was replaced by <hostname>.yaml
    # i.e: controller-1.yaml
    ctrl1_mgmt_ip = socket.getaddrinfo("controller-1", None)[0][4][0]

    ctrl1_old_hiera = "/opt/platform/puppet/{}/hieradata/{}.yaml".format(
        to_release, ctrl1_mgmt_ip)

    command = "rm -f {}".format(ctrl1_old_hiera)

    sub = subprocess.Popen(command, shell=True,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()

    if sub.returncode != 0:
        LOG.error('Cmd Failed:\n%s\n.%s\n%s' %
                  (command, stdout, stderr))
        raise Exception('Error removing unused file: {} '.format(
            ctrl1_old_hiera))


def main():
    action = None
    from_release = None
    to_release = None
    arg = 1
    res = 0

    log.configure()

    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            # optional port parameter for USM upgrade
            # port = sys.argv[arg]
            pass
        else:
            LOG.error("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    LOG.info("%s invoked with from_release = %s to_release = %s action = %s"
             % (sys.argv[0], from_release, to_release, action))

    # create a flag to not use FQDN during a SW upgrade
    # this flag must be deleted during thr upgrade complete/abort
    # during the activate, remove the unused file in hieradata
    if not os.path.exists(PLATFORM_SIMPLEX_FLAG):
        if action in ['start', 'migrate'] and \
                from_release in ['21.12', '22.12']:
            open(UPGRADE_DO_NOT_USE_FQDN, 'w').close()

        elif action in ['activate'] and to_release in ['24.09']:
            remove_unused_files_from_hieradata(to_release)

    return res


if __name__ == "__main__":
    sys.exit(main())
