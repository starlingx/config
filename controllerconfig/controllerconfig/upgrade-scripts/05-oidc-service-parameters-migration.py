#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will migrate legacy oidc service parameters format
#  to the latest format.
# +---------------------+---------------------+
# |    Legacy Format    |    Latest Format    |
# +---------------------+---------------------+
# | oidc_client_id      | oidc-client-id      |
# | oidc_groups_claim   | oidc-groups-claim   |
# | oidc_issuer_url     | oidc-issuer-url     |
# | oidc_username_claim | oidc-username-claim |
# +---------------------+---------------------+
#
# This script rely on 'kubernetes-service-parameters-apply.py'
# to apply the parameters to kubeapi, needing to be executed before it.
#

import argparse
import logging as LOG
import psycopg2
import sys

SUCCESS = 0
ERROR = 1
RELEASE_22_12 = "22.12"
RELEASE_24_09 = "24.09"
DEFAULT_POSTGRES_PORT = 5432


class PostgresAPI(object):
    def __init__(self) -> None:
        username, password = self.get_db_credentials()
        self.conn = psycopg2.connect("dbname=sysinv user=%s password=%s \
                                     host=localhost port=%s"
                                     % (username, password,
                                        DEFAULT_POSTGRES_PORT))

    def get_db_credentials(self):
        import re
        import configparser

        configparser = configparser.ConfigParser()
        configparser.read('/etc/sysinv/sysinv.conf')
        conn_string = configparser['database']['connection']
        match = re.match(r'postgresql\+psycopg2://([^:]+):([^@]+)@',
                         conn_string)
        if match:
            username = match.group(1)
            password = match.group(2)
            return username, password
        else:
            raise Exception("Failed to get database credentials, sysinv.conf")

    def db_update(self, query):
        with self.conn.cursor() as cur:
            cur.execute(query)
        self.conn.commit()
        return cur.rowcount != 0


class OidcServiceParametersMigrator(object):
    def __init__(self, action=None) -> None:
        self.action_handlers = {
            "activate": self.activate,
            "activate-rollback": self.activate_rollback
        }
        self.db = None
        if action in self.action_handlers:
            self.db = PostgresAPI()

    def renaming(self):
        """
        Update the OIDC service parameters names.
        """
        legacy_oidc_parameters = ['oidc_client_id',
                                  'oidc_groups_claim',
                                  'oidc_issuer_url',
                                  'oidc_username_claim']
        was_renamed = False
        for parameter in legacy_oidc_parameters:
            query = "update service_parameter set name='%s' where name='%s';"\
                % (parameter.replace('_', '-'), parameter)
            if self.db.db_update(query):
                was_renamed = True
        return was_renamed

    def execute_action(self, action: str) -> int:
        if action in self.action_handlers:
            return self.action_handlers[action]()
        # No action handler registered, nothing to do here
        return SUCCESS

    def activate(self) -> int:
        """
        Start migration process
        """
        if self.renaming():
            LOG.info("OIDC: Legacy service parameters has been renamed")
            return SUCCESS
        LOG.info("OIDC: No legacy parameters were renamed")
        return SUCCESS

    def activate_rollback(self) -> int:
        LOG.info("No Rollback needed, 22.12 also supports the latest format")
        return SUCCESS


def is_upgrading(args):
    return args.from_release == RELEASE_22_12 \
        and args.to_release == RELEASE_24_09


def is_rollingback(args):
    return args.from_release == RELEASE_24_09 \
        and args.to_release == RELEASE_22_12


def main():
    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    LOG.basicConfig(filename="/var/log/software.log",
                    format=log_format, level=LOG.INFO, datefmt="%FT%T")

    parser = argparse.ArgumentParser()
    parser.add_argument("from_release", type=str)
    parser.add_argument("to_release", type=str)
    parser.add_argument("action", type=str)
    if len(sys.argv) == 5:
        parser.add_argument("postgres_port", type=int)
    args = parser.parse_args()

    oidc_sp_migrator = OidcServiceParametersMigrator(action=args.action)

    if is_upgrading(args) or is_rollingback(args):
        try:
            return oidc_sp_migrator.execute_action(action=args.action)
        except Exception as ex:
            LOG.exception(ex)
            return ERROR
    else:
        LOG.info("Nothing to do for releases from: %s and to: %s" %
                 (args.from_release, args.to_release))


if __name__ == "__main__":
    sys.exit(main())
