#!/usr/bin/env python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will remove admin postgresql database role.
# The role is no longer required in the system.
# The script can be removed in future versions.

import logging as LOG
import sys
import subprocess

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

    if action == 'activate' and to_release == VERSION_2409:
        try:
            remove_postgresql_roles('admin', postgres_port)
        except Exception as ex:
            LOG.exception(ex)
            return 1


def remove_postgresql_roles(username, postgres_port):
    """
    Remove postgresql role
    """
    sql_command = f"DROP ROLE IF EXISTS \"{username}\";"

    try:
        LOG.info(f"Removing {username} role")
        process = subprocess.Popen(
            ['sudo', '-u', 'postgres', 'psql', '-p', postgres_port,
                '-c', sql_command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate()

        if process.returncode != 0:
            msg = f"Failed removing role: {username}, "
            rt_code = f"return code: {process.returncode}, "
            stderr = f"stderr: {stderr.strip()}, "
            stdout = f"stdout: {stdout.strip()}"
            LOG.warning(msg + rt_code + stderr + stdout)
        else:
            msg = f"Successfully removed role: {username}, "
            stdout = f"stdout: {stdout.strip()}"
            LOG.info(msg + stdout)

    except subprocess.CalledProcessError as ex:
        msg = f"Failed removing role: {username}, "
        rt_code = f"return code: {ex.returncode}, "
        stderr = f"stderr: {ex.stderr}, "
        stdout = f"stdout: {ex.stdout}"
        LOG.warning(msg + rt_code + stderr + stdout)
    except Exception as ex:
        LOG.warning(f"Failed removing role: {username}, ex: {ex}")


if __name__ == "__main__":
    sys.exit(main())
