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
from sysinv.ipsec_auth.client.client import Client
from sysinv.ipsec_auth.common import constants

LOG = logging.getLogger(__name__)
CONF = cfg.CONF


def main():
    if not os.geteuid() == 0:
        print("%s must be run with root privileges" % sys.argv[0])
        exit(1)

    port = constants.DEFAULT_LISTEN_PORT
    opcode = 1
    force_reload = False

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description=textwrap.dedent('''\
            Command line interface for IPsec Auth Client.

            %(prog)s is used to initiate connections with
            IPsec Auth Servers and configure strongswan to
            establish IPsec security associations with
            other nodes in the cluster.'''),
        epilog=textwrap.dedent('''\
            Note: This command must be run with root privileges
                  to configure strongswan files'''))

    parser.add_argument('host', metavar='<host>',
                help="IPsec Auth Server's host address")
    parser.add_argument("-p", "--port", metavar='<port>', type=int,
                help='Port number (Default: ' + str(port) + ')')
    parser.add_argument('-d', "--debug", action="store_true",
                help=textwrap.dedent('''\
                If enabled, the logging level will be set
                to DEBUG instead of the default INFO level.'''))
    parser.add_argument('-f', "--force-reload", action="store_true",
                help=textwrap.dedent('''\
                If enabled, force to reload all configuration
                files on StrongSwan during certificate renewal
                procedure. This flag only applies to cert-renewal
                operation (opcode 2)'''))
    parser.add_argument("-o", "--opcode", metavar='<opcode>',
                type=int, choices=[1, 2, 3],
                help='Operational code (Default: ' + str(opcode) + ')')
    args = parser.parse_args()

    host = args.host

    if args.port:
        port = args.port

    if args.opcode:
        opcode = args.opcode

    if args.force_reload:
        force_reload = args.force_reload

    logging.register_options(CONF)
    logging.set_defaults()

    CONF.set_default("use_syslog", True)
    CONF.set_default("syslog_log_facility", "local6")

    if args.debug:
        CONF.set_default("debug", True)

    logging.setup(CONF, 'ipsec-client')

    if not os.path.exists(constants.LUKS_DIR_IPSEC_KEYS):
        os.makedirs(constants.LUKS_DIR_IPSEC_KEYS)
        os.makedirs(constants.LUKS_DIR_IPSEC_CERTS)

    client = Client(host, port, opcode, force_reload)
    client.run()
