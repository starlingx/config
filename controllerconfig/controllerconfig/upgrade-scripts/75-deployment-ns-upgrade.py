#!/usr/bin/python
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script updates the dc root ca certificate to include more
# DN information and add separated admin endpoint certificate.
# This is in preparation for the future certificate renewal.
#
# This script can be removed in the release that follows 20.06.
#

import subprocess
import sys
from controllerconfig.common import log

LOG = log.get_logger(__name__)


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
        else:
            print ("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()
    LOG.debug("%s invoked with from_release = %s to_release = %s action = %s"
              % (sys.argv[0], from_release, to_release, action))

    if from_release == '20.06' and action == 'activate':
        create_deployment_ns()


deployment_ns_yaml = """
---
apiVersion: v1
kind: Namespace
metadata:
  name: deployment
"""


def create_deployment_ns():
    cmd = "echo '%s' | " \
          "kubectl --kubeconfig=/etc/kubernetes/admin.conf apply -f -" % \
          deployment_ns_yaml
    sub = subprocess.Popen(cmd, shell=True,
                           stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE,
                           universal_newlines=True)

    stdout, stderr = sub.communicate()
    if sub.returncode != 0:
        LOG.error('Command failed:\n %s\n. %s\n%s' % (cmd, stdout, stderr))
        raise Exception('Cannot create deployment namespace')

    LOG.info('Deployment namespace updated successfully')


if __name__ == "__main__":
    sys.exit(main())
