#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import argparse
import os
import sys
import textwrap

from oslo_config import cfg
from oslo_log import log as logging
from sysinv.ipsec_auth.common import constants
from sysinv.ipsec_auth.server.server import IPsecServer

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


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
    parser.add_argument('-d', "--debug", action="store_true",
                help="If enabled, the logging level will be set "
                "to DEBUG instead of the default INFO level.")
    args = parser.parse_args()

    if args.port:
        port = args.port

    logging.register_options(CONF)
    logging.set_defaults()

    CONF.set_default("use_syslog", True)
    CONF.set_default("syslog_log_facility", "local6")

    if args.debug:
        CONF.set_default("debug", True)

    logging.setup(CONF, 'ipsec-server')

    server = IPsecServer(port)
    server.run()
