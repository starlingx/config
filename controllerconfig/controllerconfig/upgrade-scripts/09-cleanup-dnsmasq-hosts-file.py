#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script enables IPsec on all hosts and should be executed
# at the end of upgrade-activate stage.

import os
import sys
import subprocess

from controllerconfig.common import log

LOG = log.get_logger(__name__)

DNSMASQ_HOSTS_FILE = "/opt/platform/config/%s/dnsmasq.hosts"


def main():
    action = None
    from_release = None  # noqa
    to_release = None
    arg = 1
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]  # noqa
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            # optional port parameter for USM upgrade
            port = sys.argv[arg]  # noqa
            pass
        else:
            print(f"Invalid option {sys.argv[arg]}.")
            return 1
        arg += 1

    log.configure()

    if action != "activate":
        return

    dnsmasq_hosts_file = DNSMASQ_HOSTS_FILE % to_release

    if not os.path.exists(dnsmasq_hosts_file):
        LOG.info("%s file does not exist, aborting" % dnsmasq_hosts_file)
        return

    LOG.info("Cleaning mgmt addresses from %s" % dnsmasq_hosts_file)

    with open(dnsmasq_hosts_file, 'r') as f_in:
        lines = f_in.readlines()

    with open(dnsmasq_hosts_file, 'w') as f_out:
        for line in lines:
            fields = line.split(",")
            if len(fields) == 4:
                if "pxeboot-" not in fields[1]:
                    LOG.info("Skipping line: '%s'" % line.strip())
                    continue
            LOG.info("Keeping line: '%s'" % line.strip())
            f_out.write(line)

    LOG.info("Restarting dnsmasq service")

    cmd = "/usr/bin/sm-restart-safe service dnsmasq"
    sub = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode != 0:
        msg = "Command '%s' failed:\n%s\n%s\n" % \
              (cmd, stdout.decode('utf-8'), stderr.decode('utf-8'))
        LOG.error(msg)
        raise Exception(msg)


if __name__ == "__main__":
    sys.exit(main())
