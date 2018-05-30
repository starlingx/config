#!/usr/bin/env python
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will update the controller_fs extension in the sysinv database.

import sys
import os
import subprocess
import math
import uuid
from datetime import datetime

import psycopg2
from controllerconfig import utils
from controllerconfig.common import log
from controllerconfig.common import constants
from psycopg2.extras import RealDictCursor
from sysinv.common import utils as sutils

LOG = log.get_logger(__name__)


def main():
    action = None
    from_release = None
    to_release = None  # noqa
    arg = 1
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]  # noqa
        elif arg == 3:
            action = sys.argv[arg]
        else:
            print ("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()
    if from_release == "17.06" and action == "migrate":
        try:
            update_extension()
        except Exception as ex:
            LOG.exception(ex)
            print ex
            return 1


def get_temp_sizes():
    """ Get the temporary filesystems sizes setup during upgrades.
    """
    total_temp_sizes = 0

    args = ["lvdisplay",
            "--columns",
            "--options",
            "lv_size,lv_name",
            "--units",
            "g",
            "--noheading",
            "--nosuffix",
            "/dev/cgts-vg/dbdump-temp-lv",
            "/dev/cgts-vg/postgres-temp-lv"]

    with open(os.devnull, "w") as fnull:
        try:
            lvdisplay_output = subprocess.check_output(args,
                                                       stderr=fnull)
        except Exception:
            LOG.info("migrate extension, total_temp_size=%s" %
                     total_temp_sizes)
            return total_temp_sizes

        lvdisplay_dict = utils.output_to_dict(lvdisplay_output)

        if lvdisplay_dict.get('dbdump-temp-lv'):
            total_temp_sizes = int(math.ceil(float(
                lvdisplay_dict.get('dbdump-temp-lv'))))

        if lvdisplay_dict.get('postgres-temp-lv'):
            total_temp_sizes += int(math.ceil(float(
                lvdisplay_dict.get('postgres-temp-lv'))))

    LOG.info("migrate extension, total_temp_sizes=%s" % total_temp_sizes)
    return total_temp_sizes


def update_extension():
    """ Update sysinv db controller_fs extension size on upgrade."""
    try:
        vg_free = sutils.get_cgts_vg_free_space()
        LOG.info("migrate extension, get_cgts_vg_free_space=%s" % vg_free)

        # Add back the temporary sizes
        vg_free = get_temp_sizes()
        LOG.info("migrate extension, vg_free=%s" % vg_free)

    except Exception as e:
        LOG.exception(e)
        print e
        return 1

    conn = psycopg2.connect("dbname='sysinv' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("select id from i_system;")
            row = cur.fetchone()
            if row is None:
                LOG.exception("migrate extension, failed to fetch "
                              "i_system data")
                raise

            controller_fs_uuid = str(uuid.uuid4())
            forisystemid = row.get('id')
            values = {'created_at': datetime.now(),
                      'updated_at': None,
                      'deleted_at': None,
                      'uuid': controller_fs_uuid,
                      'name': 'extension',
                      'size': 1,
                      'replicated': True,
                      'logical_volume': 'extension-lv',
                      'forisystemid': forisystemid}

            cur.execute("INSERT INTO controller_fs "
                        "(created_at, updated_at, deleted_at, "
                        "uuid, name, size, replicated, logical_volume, "
                        "forisystemid) "
                        "VALUES (%(created_at)s, %(updated_at)s, "
                        "%(deleted_at)s, %(uuid)s, %(name)s, %(size)s, "
                        "%(replicated)s, %(logical_volume)s, "
                        "%(forisystemid)s)",
                        values)

            LOG.info("migrate extension, controller_fs, insert new row with "
                     "data %s" % values)
            conn.commit()

            # If there is not enough space to add the new extension filesystem
            # then decrease the backup filesystem by the amount required (1G)

            cur.execute("select size from controller_fs where name='backup';")
            row = cur.fetchone()
            LOG.info("migrate extension, backup = %s" % row)
            if row is None:
                LOG.exception("migrate extension, failed to fetch "
                              "controller_fs data")
                raise
            backup_size = row.get('size')

            cur.execute(
                "select size from controller_fs where name='database';")
            row = cur.fetchone()
            LOG.info("migrate extension, database = %s" % row)
            if row is None:
                LOG.exception("migrate extension, failed to fetch "
                              "controller_fs data")
                raise
            database_size = row.get('size')

            cur.execute("select size from controller_fs where name='cgcs';")
            row = cur.fetchone()
            LOG.info("migrate extension, cgcs = %s" % row)
            if row is None:
                LOG.exception("migrate extension, failed to fetch "
                              "controller_fs data")
                raise
            cgcs_size = row.get('size')

            cur.execute(
                "select size from controller_fs where name='img-conversions';")
            row = cur.fetchone()
            LOG.info("migrate extension, img-conversions  = %s" % row)
            if row is None:
                LOG.exception("migrate extension, failed to fetch "
                              "controller_fs data")
                raise
            img_conversions_size = row.get('size')

            cur.execute(
                "select size from controller_fs where name='extension';")
            row = cur.fetchone()
            LOG.info("migrate extension, extension= %s" % row)
            if row is None:
                LOG.exception("migrate extension, failed to fetch "
                              "controller_fs data")
                raise
            extension_size = row.get('size')

            total_size = backup_size + (database_size * 2) + \
                cgcs_size + img_conversions_size + extension_size

            if vg_free < total_size:
                LOG.info("migrate extension, we have less than 1G free")
                new_backup_size = \
                    backup_size - constants.DEFAULT_EXTENSION_STOR_SIZE

                LOG.info("migrate extension, reduce the backup size by 1G. "
                         "new_backup_size = %s" % new_backup_size)
                cur.execute(
                    "UPDATE controller_fs SET size=%s where name='backup';",
                    (new_backup_size,))
                conn.commit()


if __name__ == "__main__":
    sys.exit(main())
