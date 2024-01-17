#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import argparse
import os
import sys
import textwrap

from sysinv.ipsec_auth.common import constants
from sysinv.ipsec_auth.server.server import IPsecServer


def main():
    if not os.geteuid() == 0:
        print("%s must be run with root privileges" % (sys.argv[0]))
        exit(1)

    port = constants.DEFAULT_LISTEN_PORT

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent('''\
            Command line interface for IPsec Auth Server.

            %(prog)s is used to initialize IPsec Auth Server
            and establish connections and IPsec security
            associations with other nodes in the cluster through
            MGMT network.
            '''),
        epilog=textwrap.dedent('''\
            Note: This command must be run with root privileges.
            '''))

    parser.add_argument("-p", "--port", metavar='<port>', type=int,
                help='Port number (Default: ' + str(port) + ')')
    args = parser.parse_args()

    if args.port:
        port = args.port

    server = IPsecServer(port)
    server.run()
