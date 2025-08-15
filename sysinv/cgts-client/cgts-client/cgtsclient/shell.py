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


"""
Command-line interface for System Inventory and Maintenance
"""

from __future__ import print_function
import argparse
import httplib2
import logging
import sys

import cgtsclient
from cgtsclient import client as cgclient
from cgtsclient.common import utils
from cgtsclient import exc
from datetime import datetime
from datetime import timedelta

import os


class CgtsShell(object):

    # Key name for store cache data
    CACHE_KEY = 'cgtsclient:session'

    def __init__(self):
        self.subcommands = None
        self.parser = None
        self.keyring = False

    def get_base_parser(self):
        parser = argparse.ArgumentParser(
            prog='system',
            description=__doc__.strip(),
            epilog='See "system help COMMAND" '
                   'for help on a specific command.',
            add_help=False,
            formatter_class=HelpFormatter,
        )

        # Global arguments
        parser.add_argument('-h', '--help',
                            action='store_true',
                            help=argparse.SUPPRESS,
                            )

        parser.add_argument('--version',
                            action='version',
                            version=cgtsclient.__version__)

        parser.add_argument('--debug',
                            default=bool(utils.env('SYSTEMCLIENT_DEBUG')),
                            action='store_true',
                            help='Defaults to env[SYSTEMCLIENT_DEBUG]')

        parser.add_argument('-v', '--verbose',
                            default=False, action="store_true",
                            help="Print more verbose output")

        parser.add_argument('-k', '--insecure',
                            default=False,
                            action='store_true',
                            help="Explicitly allow system client to "
                            "perform \"insecure\" SSL (https) requests. "
                            "The server's certificate will "
                            "not be verified against any certificate "
                            "authorities. This option should be used with "
                            "caution")

        parser.add_argument('--cert-file',
                            help='Path of certificate file to use in SSL '
                            'connection. This file can optionally be prepended'
                            ' with the private key')

        parser.add_argument('--key-file',
                            help='Path of client key to use in SSL connection.'
                            ' This option is not necessary if your key is '
                            'prepended to your cert file')

        parser.add_argument('--ca-file',
                            default=utils.env('OS_CACERT'),
                            help='Path of CA SSL certificate(s) used to verify'
                            ' the remote server certificate. Without this '
                            'option systemclient looks for the default system '
                            'CA certificates')

        parser.add_argument('--timeout',
                            default=600,
                            help='Number of seconds to wait for a response')

        parser.add_argument('--os-username',
                            default=utils.env('OS_USERNAME'),
                            help='Defaults to env[OS_USERNAME]')

        parser.add_argument('--os_username',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-password',
                            default=utils.env('OS_PASSWORD'),
                            help='Defaults to env[OS_PASSWORD]')

        parser.add_argument('--os_password',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-tenant-id',
                            default=utils.env('OS_TENANT_ID'),
                            help='Defaults to env[OS_TENANT_ID]')

        parser.add_argument('--os_tenant_id',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-tenant-name',
                            default=utils.env('OS_TENANT_NAME'),
                            help='Defaults to env[OS_TENANT_NAME]')

        parser.add_argument('--os_tenant_name',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-auth-url',
                            default=utils.env('OS_AUTH_URL'),
                            help='Defaults to env[OS_AUTH_URL]')

        parser.add_argument('--os_auth_url',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-region-name',
                            default=utils.env('OS_REGION_NAME'),
                            help='Defaults to env[OS_REGION_NAME]')

        parser.add_argument('--os_region_name',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-auth-token',
                            default=utils.env('OS_AUTH_TOKEN'),
                            help='Defaults to env[OS_AUTH_TOKEN]')

        parser.add_argument('--os_auth_token',
                            help=argparse.SUPPRESS)

        parser.add_argument('--system-url',
                            default=utils.env('SYSTEM_URL'),
                            help='Defaults to env[SYSTEM_URL]')

        parser.add_argument('--system_url',
                            help=argparse.SUPPRESS)

        parser.add_argument('--system-api-version',
                            default=utils.env('SYSTEM_API_VERSION', default='1'),
                            help='Defaults to env[SYSTEM_API_VERSION] '
                            'or 1')

        parser.add_argument('--system_api_version',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-service-type',
                            default=utils.env('OS_SERVICE_TYPE'),
                            help='Defaults to env[OS_SERVICE_TYPE]')

        parser.add_argument('--os_service_type',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-endpoint-type',
                            default=utils.env('OS_ENDPOINT_TYPE'),
                            help='Defaults to env[OS_ENDPOINT_TYPE]')

        parser.add_argument('--os_endpoint_type',
                            help=argparse.SUPPRESS)

        parser.add_argument('--os-user-domain-id',
                            default=utils.env('OS_USER_DOMAIN_ID'),
                            help='Defaults to env[OS_USER_DOMAIN_ID].')

        parser.add_argument('--os-user-domain-name',
                            default=utils.env('OS_USER_DOMAIN_NAME'),
                            help='Defaults to env[OS_USER_DOMAIN_NAME].')

        parser.add_argument('--os-project-id',
                            default=utils.env('OS_PROJECT_ID'),
                            help='Another way to specify tenant ID. '
                                 'This option is mutually exclusive with '
                                 ' --os-tenant-id. '
                                 'Defaults to env[OS_PROJECT_ID].')

        parser.add_argument('--os-project-name',
                            default=utils.env('OS_PROJECT_NAME'),
                            help='Another way to specify tenant name. '
                                 'This option is mutually exclusive with '
                                 ' --os-tenant-name. '
                                 'Defaults to env[OS_PROJECT_NAME].')

        parser.add_argument('--os-project-domain-id',
                            default=utils.env('OS_PROJECT_DOMAIN_ID'),
                            help='Defaults to env[OS_PROJECT_DOMAIN_ID].')

        parser.add_argument('--os-project-domain-name',
                            default=utils.env('OS_PROJECT_DOMAIN_NAME'),
                            help='Defaults to env[OS_PROJECT_DOMAIN_NAME].')

        parser.add_argument('--refresh-cache',
                            action='store_true',
                            default=False,
                            help='Forces the update of the cached settings')

        parser.add_argument('--no-cache',
                            action='store_true',
                            default=utils.env('CGTSCLIENT_NO_CACHE', default=False),
                            help='Disables cache feature (Env: CGTSCLIENT_NO_CACHE)')

        return parser

    def get_subcommand_parser(self, version):
        parser = self.get_base_parser()

        self.subcommands = {}
        subparsers = parser.add_subparsers(metavar='<subcommand>')
        submodule = utils.import_versioned_module(version, 'shell')
        submodule.enhance_parser(parser, subparsers, self.subcommands)
        utils.define_commands_from_module(subparsers, self, self.subcommands)
        self._add_bash_completion_subparser(subparsers)
        return parser

    def _add_bash_completion_subparser(self, subparsers):
        subparser = subparsers.add_parser(
            'bash_completion',
            add_help=False,
            formatter_class=HelpFormatter
        )
        self.subcommands['bash_completion'] = subparser
        subparser.set_defaults(func=self.do_bash_completion)

    def _setup_debugging(self, debug):
        if debug:
            logging.basicConfig(
                format="%(levelname)s (%(module)s:%(lineno)d) %(message)s",
                level=logging.DEBUG)

            httplib2.debuglevel = 1
        else:
            logging.basicConfig(format="%(levelname)s %(message)s", level=logging.CRITICAL)

    def main(self, argv):
        # Parse args once to find version
        parser = self.get_base_parser()
        (options, args) = parser.parse_known_args(argv)
        self._setup_debugging(options.debug)

        # build available subcommands based on version
        api_version = options.system_api_version
        subcommand_parser = self.get_subcommand_parser(api_version)
        self.parser = subcommand_parser

        # Handle top-level --help/-h before attempting to parse
        # a command off the command line
        if options.help or not argv:
            self.do_help(options)
            return 0

        # Parse args again and call whatever callback was selected
        args = subcommand_parser.parse_args(argv)

        # Short-circuit and deal with help command right away.
        if args.func == self.do_help:  # pylint: disable=comparison-with-callable
            self.do_help(args)
            return 0
        elif args.func == self.do_bash_completion:  # pylint: disable=comparison-with-callable
            self.do_bash_completion(args)
            return 0

        if not (args.os_auth_token and args.system_url):

            os_auth_token = None
            system_url = None

            if not (args.refresh_cache or args.no_cache):
                os_auth_token, system_url = utils.load_auth_session_keyring_by_name(
                    self._cache_key(args.os_username))

                if os_auth_token and system_url:
                    self.keyring = True

            # Reuses the last authorization token and service endpoint obtained from
            # keystone when available in the cache (keyring)
            if os_auth_token and system_url:
                args.os_auth_token = os_auth_token
                args.system_url = system_url

            else:
                if not args.os_username:
                    raise exc.CommandError("You must provide a username via "
                                           "either --os-username or via "
                                           "env[OS_USERNAME]")

                if not args.os_password:
                    # priviledge check (only allow Keyring retrieval if we are root)
                    if os.geteuid() == 0:
                        import keyring
                        args.os_password = keyring.get_password('CGCS', args.os_username)
                    else:
                        raise exc.CommandError("You must provide a password via "
                                               "either --os-password or via "
                                               "env[OS_PASSWORD]")

                if not (args.os_project_id or args.os_project_name):
                    raise exc.CommandError("You must provide a project name via "
                                           "either --os-project-name or via "
                                           "env[OS_PROJECT_NAME]")

                if not args.os_auth_url:
                    raise exc.CommandError("You must provide an auth url via "
                                           "either --os-auth-url or via "
                                           "env[OS_AUTH_URL]")

                if not args.os_region_name:
                    raise exc.CommandError("You must provide an region name via "
                                           "either --os-region-name or via "
                                           "env[OS_REGION_NAME]")

        client = cgclient.get_client(api_version, **(args.__dict__))

        if not args.no_cache and isinstance(client.http_client,
                                            cgtsclient.common.http.SessionClient) \
           and client.http_client.session.auth.auth_ref:

            # Set the key timeout based on the token validity (in seconds)
            expires_at = client.http_client.session.auth.auth_ref.expires
            now = datetime.now().astimezone() + timedelta(seconds=10)
            timeout = str(int((expires_at - now).total_seconds()))

            utils.persist_auth_session_keyring(
                self._cache_key(args.os_username),
                client.http_client.session.get_token(),
                client.http_client.endpoint_override,
                timeout)

        try:
            args.func(client, args)
        except exc.Unauthorized:
            if not self.keyring:
                raise exc.CommandError("Invalid Identity credentials.")
            args.os_auth_token = None
            args.system_url = None
            self.keyring = False
            utils.revoke_keyring_by_name(self._cache_key(args.os_username))
            client = cgclient.get_client(api_version, **(args.__dict__))
            try:
                args.func(client, args)
            except (exc.Unauthorized, exc.HTTPForbidden) as e:
                raise e
        except exc.HTTPForbidden:
            raise exc.CommandError("Error: Forbidden")

    def do_bash_completion(self, args):
        """Prints all of the commands and options to stdout.
        """
        commands = set()
        options = set()
        for sc_str, sc in self.subcommands.items():
            commands.add(sc_str)
            for option in list(sc._optionals._option_string_actions):
                options.add(option)

        commands.remove('bash_completion')
        print(' '.join(commands | options))

    @utils.arg('command', metavar='<subcommand>', nargs='?',
               help='Display help for <subcommand>')
    def do_help(self, args):
        """Display help about this program or one of its subcommands."""
        if getattr(args, 'command', None):
            if args.command in self.subcommands:
                self.subcommands[args.command].print_help()
            else:
                raise exc.CommandError("'%s' is not a valid subcommand" %
                                       args.command)
        else:
            self.parser.print_help()

    def _cache_key(self, username: str) -> str:
        """Define the name of the key used to store user credentials in the cache."""
        return self.CACHE_KEY if not username else self.CACHE_KEY + ':' + username


class HelpFormatter(argparse.HelpFormatter):
    def start_section(self, heading):
        # Title-case the headings
        heading = '%s%s' % (heading[0].upper(), heading[1:])
        super(HelpFormatter, self).start_section(heading)


def main():
    try:
        CgtsShell().main(sys.argv[1:])

    except KeyboardInterrupt as e:
        print(('caught: %r, aborting' % (e)), file=sys.stderr)
        sys.exit(0)

    except IOError:
        sys.exit(0)

    except Exception as e:
        print(e, file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
