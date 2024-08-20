#!/usr/bin/env python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will update all the postgresql databases roles.
# This is required due the authentication method and password
# encryption method has been changed from md5 to sha-256
# The script can be removed in future versions.

import logging as LOG
import os
import sys
import subprocess
import yaml
from software.utilities import constants
import software.utilities.utils as utils

VERSION_2212 = "22.12"
VERSION_2409 = "24.09"
PSQL_CONFIG_DIR = "/etc/postgresql/"
PSQL_REAL_CONFIG_DIR = "/etc/postgresql/13/main"
DEFAULT_POSTGRES_PORT = '5432'


def main():
    action = None
    from_release = None
    to_release = None
    postgres_port = DEFAULT_POSTGRES_PORT
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
            postgres_port = sys.argv[arg]
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    LOG.basicConfig(filename="/var/log/software.log",
                    format=log_format, level=LOG.INFO, datefmt="%FT%T")

    LOG.debug("%s invoked with from_release = %s to_release = %s action = %s"
              % (sys.argv[0], from_release, to_release, action))

    if action == 'migrate' and to_release == VERSION_2409:
        try:
            update_postgresql_roles(to_release, postgres_port)
        except Exception as ex:
            LOG.exception(ex)
            return 1


def update_postgresql_roles(release_version, postgres_port):
    """
    Update postgresql roles
    """
    db_credentials = get_db_credentials(release_version)

    for db_name, values in db_credentials.items():
        username = values['username']
        password = values['password']
        sql_command = f"ALTER ROLE \"{username}\" WITH PASSWORD '{password}';"

        try:
            LOG.info(f"Updating {db_name} role")
            process = subprocess.Popen(
                ['sudo', '-u', 'postgres', 'psql', '-p', postgres_port,
                 '-c', sql_command],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                msg = f"Failed updating role: {db_name}, "
                rt_code = f"return code: {process.returncode}, "
                stderr = f"stderr: {stderr.strip()}, "
                stdout = f"stdout: {stdout.strip()}"
                LOG.warning(msg + rt_code + stderr + stdout)
            else:
                msg = f"Successfully updated role: {db_name}, "
                stdout = f"stdout: {stdout.strip()}"
                LOG.info(msg + stdout)

        except subprocess.CalledProcessError as ex:
            msg = f"Failed updating role: {db_name}, "
            rt_code = f"return code: {ex.returncode}, "
            stderr = f"stderr: {ex.stderr}, "
            stdout = f"stdout: {ex.stdout}"
            LOG.warning(msg + rt_code + stderr + stdout)
        except Exception as ex:
            LOG.warning(f"Failed updating role: {db_name}, ex: {ex}")


def get_db_credentials(release_version):
    """
    Returns database credentials.
    """
    db_credential_keys = {
        'barbican': {'hiera_user_key': 'barbican::db::postgresql::user',
                     'keyring_password_key': 'barbican'},
        'sysinv': {'hiera_user_key': 'sysinv::db::postgresql::user',
                   'keyring_password_key': 'sysinv'},
        'fm': {'hiera_user_key': 'fm::db::postgresql::user',
               'keyring_password_key': 'fm'},
        'keystone': {'hiera_user_key': 'keystone::db::postgresql::user',
                     'keyring_password_key': 'keystone'},
        'dcmanager': {'hiera_user_key': 'dcmanager::db::postgresql::user',
                      'keyring_password_key': 'dcmanager'},
        'dcorch': {'hiera_user_key': 'dcorch::db::postgresql::user',
                   'keyring_password_key': 'dcorch'},
        'helmv2': {
            'hiera_user_key': 'platform::helm::v2::db::postgresql::user',
            'keyring_password_key': 'helmv2'}
    }

    # Get the hiera data for the from release
    hiera_path = os.path.join(
        constants.PLATFORM_PATH, "puppet", release_version, "hieradata")
    static_file = os.path.join(hiera_path, "static.yaml")
    with open(static_file, 'r') as file:
        static_config = yaml.load(file, Loader=yaml.Loader)

    db_credentials = dict()
    for database, values in db_credential_keys.items():
        try:
            username = static_config[values['hiera_user_key']]
            password = utils.get_password_from_keyring(
                values['keyring_password_key'], "database")
            db_credentials[database] =\
                {'username': username, 'password': password}
        except Exception as ex:
            LOG.warning(f"Failed getting password from keyring: {ex}")

    return db_credentials


if __name__ == "__main__":
    sys.exit(main())
