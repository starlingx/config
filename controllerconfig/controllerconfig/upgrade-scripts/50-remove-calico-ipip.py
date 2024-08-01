#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import logging as LOG
import sys
import subprocess
from sysinv.common.kubernetes import KUBERNETES_ADMIN_CONF

KUBE_CMD = 'kubectl --kubeconfig=' + KUBERNETES_ADMIN_CONF + ' '


def main():
    action = None
    from_release = None
    to_release = None
    arg = 1

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
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    LOG.basicConfig(filename="/var/log/software.log",
                    format=log_format, level=LOG.INFO, datefmt="%FT%T")
    res = 0
    if action == "activate" and from_release == '22.12':
        LOG.info("%s invoked from_release = %s to_release = %s action = %s"
                 % (sys.argv[0], from_release, to_release, action))
        try:
            res = do_update(from_release, to_release)
        except Exception as e:
            LOG.exception(e)
            res = 1

    return res


def do_update(from_release, to_release):
    # Check if IPv4 IPIP pool exists
    cmd = (KUBE_CMD + "get ippools.crd.projectcalico.org" +
                      " --no-headers" +
                      " -o custom-columns=NAME:.metadata.name")
    stdout, _ = run_cmd(cmd)

    # Disable IPIP overlay by setting default IPv4 ippool's ipipMode to Never
    if stdout.rstrip('\n') == "default-ipv4-ippool":
        LOG.info("Disabling Calico's IPIP tunnel")
        cmd = (KUBE_CMD + "patch ippools.crd.projectcalico.org" +
                          " default-ipv4-ippool" +
                          " --type=merge -p" +
                          " '{\"spec\":{\"ipipMode\":\"Never\"}}'")
        run_cmd(cmd)
    else:
        LOG.info("Skipping, default-ipv4-ippool not found")


def run_cmd(cmd):
    sub = subprocess.Popen(cmd, shell=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = sub.communicate()
    if sub.returncode != 0:
        LOG.error('Command failed:\n %s\n. %s\n%s\n'
                  % (cmd, stdout.decode('utf-8'), stderr.decode('utf-8')))
        raise Exception(f'Cannot run cmd: "{cmd}"')
    return stdout.decode('utf-8'), stderr.decode('utf-8')


if __name__ == "__main__":
    sys.exit(main())
