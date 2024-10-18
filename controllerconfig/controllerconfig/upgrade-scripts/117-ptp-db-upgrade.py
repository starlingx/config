#!/usr/bin/env python
#
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This migration scripts is used to automaticaly upgrade the PTP
# system configuration, according to changes on linuxptp library,
# drivers, etc.

import os
import re
import sys
import yaml
import subprocess
import logging as log
import psycopg2 as db

from packaging import version
from controllerconfig.upgrades import utils
from tsconfig.tsconfig import PLATFORM_PATH

DEFAULT_POSTGRES_PORT = 5432
DB_CONNECTION_EXEC_FORMAT = "postgresql://%s:%s@127.0.0.1:%s/sysinv"


def get_db_credentials(release):
    """ get sysinv DB credentials """
    hiera_path = os.path.join(PLATFORM_PATH, "puppet", release,
                              "hieradata")
    static_file = os.path.join(hiera_path, "static.yaml")
    with open(static_file, 'r') as s_file:
        static_config = yaml.safe_load(s_file)
    username = static_config['sysinv::db::postgresql::user']

    password = utils.get_password_from_keyring('sysinv', 'database')
    return username, password


def db_connect(username, password, port):
    try:
        conn = db.connect(DB_CONNECTION_EXEC_FORMAT
                          % (username, password, port))
        return conn
    except Exception as e:
        log.exception("Error: {}".format(e))


def db_close(conn):
    try:
        conn.close()
    except Exception as e:
        log.exception("Error: {}".format(e))


def db_query(conn, query):
    result = []
    try:
        with conn.cursor() as curs:
            curs.execute(query)
            result = curs.fetchall()
    except Exception as e:
        log.exception("Error: {}".format(e))
    return result


def db_update(conn, query):
    try:
        with conn.cursor() as curs:
            curs.execute(query)
        conn.commit()
    except Exception as e:
        log.exception("Error: {}".format(e))


def convert_nmea_serial_port_name_path(v1_9_11_path):
    """ Convert the NMEA serial port path from
        ice driver version 1.9.11 to 1.14.9.x
    """

    try:
        # Retrieve the device's PCI slot from NMEA serial port
        # name. The serial port path in driver versoin 1.9.11
        # derives from PCI slot, and has the following pattern:
        #
        # /dev/ttyGNSS_xxxx_x
        #              ^    ^
        #              {bus}{function}
        #
        # Example: /dev/ttyGNSS_8a00_0
        pattern = '/dev/ttyGNSS_([0-9a-f]{4})_([0-9]{1})'
        match = re.search(pattern, v1_9_11_path)
        if match:
            bus_device = match.group(1)
            function = match.group(2)
        else:
            log.info("path: {} doesn't match version 1.9.11 pattern"
                     .format(v1_9_11_path))
            return None

        # Then create the PCI slot from bus and function data,
        # following the pattern:
        #
        # 0000:xx:xx.x
        #      ^     ^
        #      {bus} {function}
        #
        # Example: 0000:8a:00.0
        pci_slot = '0000:' + bus_device[0:2] + ':' + \
                   bus_device[2:4] + '.' + function
    except Exception as e:
        log.exception("Fail to convert NMEA serial port path to PCI slot: {}"
                      .format(e))

    try:
        # Using the PCI slot retrieve the NMEA serial port name
        # for ice driver version 1.14.9.x. The name is the same
        # of the folder inside device's gnss folder.
        device_path = '/sys/bus/pci/devices/' + pci_slot + '/gnss'
        serial_name = os.listdir(device_path)[0]
    except Exception as e:
        log.exception("Fail to get NMEA serial port name from PCI slot: {}"
                      .format(e))

    return '/dev/' + serial_name


def migrate_nmea_serial_port_name(conn):
    """" migrate DB NMEA serial port name """
    log.info("migrating nmea serial port name ...")

    # retrieve current configuration
    query = "select uuid,value from ptp_parameters where " \
            "name='ts2phc.nmea_serialport'"
    rows = db_query(conn, query)
    log.info("rows: {}".format(rows))

    for row in rows:
        uuid = row[0]
        v1_9_11_path = row[1]
        log.info("uuid: {}".format(uuid))
        log.info("path: {}".format(v1_9_11_path))
        v1_14_9_x_path = convert_nmea_serial_port_name_path(v1_9_11_path)
        if v1_14_9_x_path:
            log.info("new path: {}".format(v1_14_9_x_path))
            update_query = "update ptp_parameters set value='{}' "\
                "where uuid='{}'".format(v1_14_9_x_path, uuid)
            db_update(conn, update_query)


def apply_ptp_instance_configuration():
    """ apply PTP configuration and restart the services """
    try:
        cmd = 'system ptp-instance-apply'
        sub = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        stdout, stderr = sub.communicate()
        if sub.returncode == 0:
            log.info("PTP configuration applied.")
        else:
            log.error("Apply PTP configuration failed:\n{}\n{}\n{}"
                      .format(cmd, stdout.decode('utf-8'),
                              stderr.decode('utf-8')))
    except Exception as e:
        log.exception("Fail to get NMEA serial port name from PCI slot: {}"
                      .format(e))


def main():
    """" main - parsing args and call migration functions """
    # migration arguments
    action = None
    from_release = None
    to_release = None
    db_port = DEFAULT_POSTGRES_PORT

    # log config
    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    log.basicConfig(filename="/var/log/software.log",
                    format=log_format, level=log.INFO, datefmt="%FT%T")

    # parse args
    if len(sys.argv) >= 5:
        db_port = sys.argv[4]

    if len(sys.argv) >= 4:
        from_release = sys.argv[1]
        to_release = sys.argv[2]
        action = sys.argv[3]
    else:
        log.error("Missing arguments!\n"
                  "usage: migration.py <from-release> <to-release> <action>")
        return 1

    to_release_version = version.Version(to_release)
    min_to_release_version = version.Version("24.09")

    if action == 'activate' and \
            from_release in ['21.12', '22.12'] and \
            to_release_version >= min_to_release_version:
        db_username, db_password = get_db_credentials(to_release)
        conn = db_connect(db_username, db_password, db_port)
        if conn:
            migrate_nmea_serial_port_name(conn)
            db_close(conn)
            apply_ptp_instance_configuration()
    else:
        log.info("nothing to do")


if __name__ == "__main__":
    sys.exit(main())
