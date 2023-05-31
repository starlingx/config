#!/usr/bin/env python
# Copyright (c) 2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
import psycopg2
import re
import sys
from controllerconfig.common import log
from psycopg2.extras import RealDictCursor
from sysinv.agent import disk
from sysinv.common import constants


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
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1
    log.configure()
    LOG.info(
        "%s invoked from_release = %s to_release = %s action = %s"
        % (sys.argv[0], from_release, to_release, action)
    )
    res = 0
    if action == "migrate" and (
        from_release == "21.12" and
        to_release == "22.12"
    ):
        if not is_multipath():
            LOG.info("Multipath not detected, nothing to do")
            return 0

        try:
            conn = psycopg2.connect("dbname=sysinv user=postgres")
            do_update_i_host(conn)
            do_update_i_idisks(conn)
            do_update_partitions(conn)
            do_update_i_pv(conn)
            do_update_hw_settle(conn)
        except Exception as e:
            LOG.exception("Error: {}".format(e))
            res = 1
    return res


def do_update_partitions(conn):
    partitions_db = get_partitions(conn)

    for partition_db in partitions_db:
        new_path_device_node = transform_device_node_path(
            partition_db["device_node"]
        )
        new_part_path_device_path = transform_part_device_path(
            partition_db["device_path"])

        query = (
            "UPDATE partition SET device_path='{}', "
            "device_node='{}' WHERE id={};".format(
                new_part_path_device_path,
                new_path_device_node,
                partition_db["id"],
            )
        )
        LOG.info(
            "Update partition id={} query={}".format(
                partition_db["id"], query)
        )
        do_update_query(conn, query)


def do_update_i_pv(conn):
    i_pvs = get_i_pvs(conn)

    for i_pv in i_pvs:
        new_path_device_node = transform_device_node_path(
            i_pv["disk_or_part_device_node"]
        )

        new_disk_or_part_device_path = transform_part_device_path(
            i_pv["disk_or_part_device_path"]
        )

        query = (
            "UPDATE i_pv SET disk_or_part_device_node='{}', "
            "lvm_pv_name='{}', disk_or_part_device_path='{}' "
            "WHERE id={}").format(
                new_path_device_node,
                new_path_device_node,
                new_disk_or_part_device_path,
                i_pv["id"])
        LOG.info("Update i_pv id={} query= {}".format(
            i_pv["id"], query))

        do_update_query(
            conn,
            query
        )


def do_update_i_idisks(conn):
    i_disks_db = get_idisks(conn)

    for i_disk_db in i_disks_db:
        new_device_path = transform_device_path(i_disk_db["device_path"])
        query = "UPDATE i_idisk SET device_path='{}' "\
                "WHERE id={};".format(
                    new_device_path, i_disk_db["id"])
        LOG.info(
            "Update disk id={} device_path={} "
            "to {}".format(
                i_disk_db["id"],
                i_disk_db["device_path"],
                new_device_path))
        do_update_query(conn, query)


def do_update_i_host(conn):
    i_hosts = get_i_hosts(conn)

    for i_host in i_hosts:
        query = (
            "UPDATE i_host SET boot_device='/dev/mapper/mpatha', "
            "rootfs_device='/dev/mapper/mpatha' "
            "WHERE id={};".format(
                i_host["id"]
            )
        )
        LOG.info("Update i_hosts id={} query= {}".format(
            i_host["id"], query))

        do_update_query(conn, query)


def get_idisks(conn):
    query = "SELECT id, device_node, serial_id, device_id, device_path "\
            "FROM i_idisk;"
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(query)
        i_disks = cur.fetchall()
    return i_disks


def get_partitions(conn):
    query = "SELECT id, device_node, device_path FROM partition;"
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(query)
        partitions = cur.fetchall()
    return partitions


def get_i_pvs(conn):
    query = (
        "SELECT id, disk_or_part_device_node, lvm_pv_name, "
        "disk_or_part_device_path FROM i_pv;"
    )
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(query)
        pvs = cur.fetchall()
    return pvs


def get_i_hosts(conn):
    query = "SELECT id, boot_device, rootfs_device "\
            "FROM i_host WHERE personality='controller';"
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(query)
        ihosts = cur.fetchall()
    return ihosts


def do_update_query(conn, query):
    with conn.cursor() as cur:
        cur.execute(query)
    conn.commit()


def do_update_hw_settle(conn):
    query = "UPDATE i_host SET hw_settle='30'; "
    LOG.info("Update hw_settle query= {}".format(query))
    do_update_query(conn, query)


def is_multipath():
    disk_operator = disk.DiskOperator()
    system_disk = disk_operator.idisk_get()[0]
    if constants.DEVICE_NAME_MPATH in system_disk["device_node"]:
        return True
    return False


def transform_device_node_path(path):
    regex = r"(\/dev\/mapper\/mpath)([a-zA-Z])(\d)"
    result = re.match(regex, path)
    if result:
        return "{}{}-part{}".format(result[1], result[2], result[3])
    return path


def transform_device_path(path):
    # This regex is used to support QEMU virtualization devices,
    # while all other real iSCSI devices start with 0
    regex = r"(\/dev\/disk\/by-id\/)dm-uuid-mpath-[0-9](.*)"
    result = re.match(regex, path)
    if result:
        return "{}wwn-0x{}".format(result[1], result[2])
    return path


def transform_part_device_path(path):
    # This regex is used to support QEMU virtualization devices,
    # while all other real iSCSI devices start with 0
    regex = r"(\/dev\/disk\/by-id\/)dm-uuid-(.*)-mpath-[0-9](.*)"
    result = re.match(regex, path)
    if result:
        return "{}wwn-0x{}-{}".format(result[1], result[3], result[2])
    return path


if __name__ == "__main__":
    sys.exit(main())
