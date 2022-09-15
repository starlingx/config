#!/usr/bin/env python
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This is a data migration script to pickup the partition changes during
# upgrade to Debian OS.
# The migration refreshes the i_idisk, partition, i_pv and i_lvg tables
# with the new partition configuration on filessytem of Debian StarlingX
# after controller-1 is upgraded.
#

import json
import sys
import psycopg2
from controllerconfig.common import log
from datetime import datetime
from psycopg2.extras import DictCursor
import uuid

from sysinv.common import constants
from sysinv.agent import disk as Disk
from sysinv.agent import lvg as Lvg
from sysinv.agent import partition as Partition
from sysinv.agent import pv as Pv

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
    LOG.info("%s invoked from_release = %s to_release = %s action = %s"
             % (sys.argv[0], from_release, to_release, action))
    res = 0
    if action == "migrate" and (from_release == '22.06'and
                                to_release == '22.12'):
        try:
            res = do_update()
        except Exception:
            LOG.exception("Remapping partition action failed")
            res = 1

    return res


IDISK_COLUMNS = 'created_at', 'updated_at', 'deleted_at', 'uuid', \
                'device_node', 'device_num', 'device_type', 'size_mib', \
                'serial_id', 'capabilities', 'forihostid', 'foristorid', \
                'foripvid', 'rpm', 'device_id', 'device_path', 'device_wwn', \
                'available_mib'

IPARTITION_COLUMNS = 'created_at', 'updated_at', 'deleted_at', 'uuid', \
                     'start_mib', 'end_mib', 'size_mib', 'device_path', \
                     'type_guid', 'type_name', 'idisk_id', 'idisk_uuid', \
                     'capabilities', 'status', 'foripvid', 'forihostid', \
                     'device_node'

LVG_COLUMNS = 'created_at', 'updated_at', 'deleted_at', 'uuid', 'vg_state', \
              'lvm_vg_name', 'lvm_vg_uuid', 'lvm_vg_access', 'lvm_max_lv', \
              'lvm_cur_lv', 'lvm_max_pv', 'lvm_cur_pv', 'lvm_vg_size', \
              'lvm_vg_total_pe', 'lvm_vg_free_pe', 'capabilities', 'forihostid'

IPV_COLUMNS = 'created_at', 'updated_at', 'deleted_at', 'uuid', 'pv_state', \
              'pv_type', 'disk_or_part_uuid', 'disk_or_part_device_node', \
              'lvm_pv_name', 'lvm_vg_name', 'lvm_pv_uuid', 'lvm_pv_size', \
              'lvm_pe_total', 'lvm_pe_alloced', 'capabilities', 'forihostid', \
              'forilvgid', 'disk_or_part_device_path'


def get_disk_uuid_mapping(conn, forihostid):
    # return map of idisk uuid indexed by device_node
    with conn.cursor(cursor_factory=DictCursor) as cur:
        sql = "SELECT uuid, device_node FROM i_idisk WHERE forihostid = %s;"
        cur.execute(sql, (forihostid, ))
        vals = cur.fetchall()
        mappings = {}
        for val in vals:
            pair = {val["device_node"]: val["uuid"]}
            mappings.update(pair)
        return mappings


def get_idisks(forihostid, uuid_mapping):
    do = Disk.DiskOperator()
    disks = do.idisk_get()
    idisks = []
    now = datetime.now()
    disk_additions = {
        "created_at": now,
        "updated_at": now,
        "deleted_at": None,
        "forihostid": forihostid,
        # foripvid will be populated when updating i_pv table
        "foripvid": None,
        # ToDo missing foristorid
        "foristorid": None,
    }

    for disk in disks:
        # find uuid
        device_node = disk["device_node"]
        if device_node in uuid_mapping:
            disk_additions["uuid"] = uuid_mapping[device_node]
        else:
            # this is not good, but it could be a new disk
            LOG.warn("Found disk %s that is not inventoried" % device_node)
            new_uuid = "%s" % uuid.uuid4()
            disk_additions["uuid"] = new_uuid
            LOG.info("Assign uuid %s to %s" % (new_uuid, device_node))
        disk.update(disk_additions)

        idisk = []
        # the IDISK_COLUMNS is the order of insert statement,
        # sort the values in the same order below to form
        # SQL insert statement
        for col in IDISK_COLUMNS:
            if col == "capabilities":
                if disk[col] is None:
                    idisk.append(None)
                else:
                    idisk.append(json.dumps(disk[col]))
            else:
                idisk.append(disk[col])
        idisks.append(idisk)
    return idisks


def get_ihostid(conn):
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute("SELECT system_mode FROM i_system;")
        system = cur.fetchone()
        upgrade_controller = "controller-1"
        if system["system_mode"] == "simplex":
            upgrade_controller = "controller-0"

        cur.execute("SELECT id FROM i_host WHERE hostname = %s;",
                    (upgrade_controller,))
        instance = cur.fetchone()
        if instance is not None:
            return instance["id"]
        else:
            raise Exception("Failed to retrieve host id for controller-1")


def update_disks(conn, idisks):
    new_disks = []
    forihostid = None
    idx = IDISK_COLUMNS.index("forihostid")
    dp_idx = IDISK_COLUMNS.index("device_path")
    uuid_idx = IDISK_COLUMNS.index("uuid")
    with conn.cursor(cursor_factory=DictCursor) as cur:
        for idisk in idisks:
            device_path = idisk[dp_idx]
            if forihostid is None:
                forihostid = idisk[idx]
            elif forihostid != idisk[idx]:
                raise Exception("Bug: can only handle disks for 1 host at"
                                "a time")

            setters = ", ".join(["%s=%%s"] * len(IDISK_COLUMNS))
            sql_tmp = "UPDATE i_idisk SET %s where forihostid=%s and " \
                "device_path=%s" % (setters, "%%s", "%%s")
            sql = sql_tmp % IDISK_COLUMNS

            params = tuple(idisk) + (forihostid, device_path)
            cur.execute(sql, params)
            if cur.rowcount == 0:
                LOG.debug("new disk %s" % device_path)
                new_disks.append(idisk)
            else:
                LOG.debug("update %s" % device_path)

        for idisk in new_disks:
            # TODO: untest path
            device_path = idisk[dp_idx]
            col_fmt = ", ".join(["%s"] * len(IDISK_COLUMNS))
            values_fmt = ", ".join(["%%s"] * len(IDISK_COLUMNS))
            sql_fmt = "INSERT INTO i_idisk (%s) VALUES(%s)" % \
                      (col_fmt, values_fmt)
            sql = sql_fmt % IDISK_COLUMNS
            cur.execute(sql, idisk)
            if cur.rowcount == 1:
                LOG.info("Add new disk %s, %s" %
                         (device_path, idisk[uuid_idx]))

        device_paths = [d[dp_idx] for d in idisks]
        # delete the disks that no longer exist
        in_list = ', '.join(['%s'] * len(device_paths))
        sql = "DELETE FROM i_idisk where forihostid = %s and " \
              "not device_path in (%s)" % (forihostid, in_list)
        device_paths = tuple(device_paths)
        cur.execute(sql, device_paths)
        count = cur.rowcount
        if count > 0:
            LOG.info("%s disks no longer exist" % count)

        sql = "SELECT id, uuid, device_node, device_path FROM i_idisk " \
              "WHERE forihostid = %s"
        cur.execute(sql, (forihostid, ))
        disks = [{"id": d[0], "uuid": d[1], "device_node": d[2],
                  "device_path": d[3], "type": "disk"}
                 for d in cur.fetchall()]
        return disks


def get_disk_by_device_node(disks, device_path):
    for disk in disks:
        if disk["device_path"] in device_path:
            return disk
        elif constants.DEVICE_NAME_MPATH in disk["device_node"]:
            path_split = disk["device_node"].split(constants.DEVICE_NAME_MPATH)
            if path_split[0] in device_path and path_split[1] in device_path:
                return disk

    raise Exception("Cannot locate the disk for %s" % device_path)


def get_ipartitions(forihostid, disks):
    po = Partition.PartitionOperator()
    partitions = po.ipartition_get(skip_gpt_check=True)
    now = datetime.now()
    ipartitions = []

    partition_additions = {
        "created_at": now,
        "updated_at": now,
        "deleted_at": None,
        "forihostid": forihostid,
        # foripvid will be populated when updating i_pv table
        "foripvid": None,
        # TODO: check to load capabilities
        "capabilities": None,
        # TODO: check to load status
        "status": 1
    }

    for partition in partitions:
        # regenerate uuid
        partition_additions["uuid"] = "%s" % uuid.uuid4()
        partition.update(partition_additions)

        disk = get_disk_by_device_node(disks, partition["device_path"])
        partition["idisk_id"] = disk["id"]
        partition["idisk_uuid"] = disk["uuid"]

        ipartition = []
        # the IPARTITION_COLUMNS is the order of insert statement,
        # sort the values in the same order below to form
        # SQL statements
        ipartition = [partition[col] for col in IPARTITION_COLUMNS]
        ipartitions.append(ipartition)

    return ipartitions


def update_partition(conn, ipartitions):
    new_partitions = []
    forihostid = None
    idx = IPARTITION_COLUMNS.index("forihostid")
    dp_idx = IPARTITION_COLUMNS.index("device_path")
    uuid_idx = IPARTITION_COLUMNS.index("uuid")
    with conn.cursor(cursor_factory=DictCursor) as cur:
        for ipartition in ipartitions:
            device_path = ipartition[dp_idx]
            if forihostid is None:
                forihostid = ipartition[idx]
            elif forihostid != ipartition[idx]:
                raise Exception("Bug: can only handle partitions for"
                                " one host at a time")

            setters = ", ".join(["%s=%%s"] * len(IPARTITION_COLUMNS))
            sql_tmp = "UPDATE partition SET %s where forihostid=%s and " \
                "device_path=%s" % (setters, "%%s", "%%s")
            sql = sql_tmp % IPARTITION_COLUMNS

            params = tuple(ipartition) + (forihostid, device_path)
            cur.execute(sql, params)
            if cur.rowcount == 0:
                LOG.debug("new partition %s" % device_path)
                new_partitions.append(ipartition)
            else:
                LOG.debug("update %s" % device_path)

        for ipartition in new_partitions:
            device_path = ipartition[dp_idx]
            col_fmt = ", ".join(["%s"] * len(IPARTITION_COLUMNS))
            values_fmt = ", ".join(["%%s"] * len(IPARTITION_COLUMNS))
            sql_fmt = "INSERT INTO partition (%s) VALUES(%s)" % \
                      (col_fmt, values_fmt)
            sql = sql_fmt % IPARTITION_COLUMNS
            cur.execute(sql, ipartition)
            if cur.rowcount == 1:
                LOG.info("Add new partition %s, %s" %
                         (device_path, ipartition[uuid_idx]))

        device_paths = [d[dp_idx] for d in ipartitions]
        # delete the disks that no longer exist
        in_list = ', '.join(['%s'] * len(device_paths))
        sql = "DELETE FROM partition where forihostid = %s " \
            "and not device_path in (%s)" % (forihostid, in_list)
        device_paths = tuple(device_paths)
        cur.execute(sql, device_paths)
        count = cur.rowcount
        if count > 0:
            LOG.info("%s partitions no longer exist" % count)

        sql = "SELECT id, uuid, device_node, device_path " \
            "FROM partition WHERE forihostid = %s"
        cur.execute(sql, (forihostid, ))
        partitions = [{"id": d[0], "uuid": d[1], "device_node": d[2],
                       "device_path": d[3], "type": "partition"}
                      for d in cur.fetchall()]
        return partitions


def get_pvs(forihostid, lvgs, disk_or_part):
    # IPV_COLUMNS = 'created_at', 'updated_at', 'deleted_at', 'uuid',
    #               'pv_state', 'pv_type', 'disk_or_part_uuid',
    #               'disk_or_part_device_node', 'lvm_pv_name',
    #               'lvm_vg_name', 'lvm_pv_uuid', 'lvm_pv_size',
    #               'lvm_pe_total', 'lvm_pe_alloced', 'capabilities',
    #               'forihostid', 'forilvgid', 'disk_or_part_device_path'
    #
    # ipv_get() data
    #               'lvm_pv_name', 'lvm_vg_name', 'lvm_pv_uuid',
    #               'lvm_pv_size', 'lvm_pe_total', 'lvm_pe_alloced',
    # adding        'created_at', 'updated_at', 'deleted_at', 'uuid',
    #               'forihostid', 'forilvgid', 'capabilities', 'pv_state',
    #               'disk_or_part_device_node', 'disk_or_part_device_path',
    #               'pv_type', 'disk_or_part_uuid'

    pvo = Pv.PVOperator()
    pvs = pvo.ipv_get()
    now = datetime.now()
    ipvs = []

    pv_additions = {
        "created_at": now,
        "updated_at": now,
        "deleted_at": None,
        "forihostid": forihostid,
        # TODO: check to load capabilities
        "capabilities": None,
        # TODO: check to load pv_state
        "pv_state": "provisioned"
    }

    for pv in pvs:
        # regenerate uuid
        pv_additions["uuid"] = "%s" % uuid.uuid4()
        pv.update(pv_additions)

        # find forilvgid from matching lvg
        for lvg in lvgs:
            if lvg["lvm_vg_name"] == pv["lvm_vg_name"]:
                pv["forilvgid"] = lvg["id"]
                break
        else:
            raise Exception("no lvg matches pv %s %s" %
                            (pv["lvm_vg_name"], pv["lvm_pv_name"]))

        for dop in disk_or_part:
            if dop["device_node"] == pv["lvm_pv_name"]:
                pv["disk_or_part_device_node"] = dop["device_node"]
                pv["disk_or_part_device_path"] = dop["device_path"]
                pv["pv_type"] = dop["type"]
                pv["disk_or_part_uuid"] = dop["uuid"]
                break
        else:
            raise Exception("no disk or partition matches pv %s %s" %
                            (pv["lvm_vg_name"], pv["lvm_pv_name"]))

        ipv = []
        # the IPV_COLUMNS is the order of insert and update statement,
        # sort the values in the same order below to form
        # SQL statements
        ipv = [pv[col] for col in IPV_COLUMNS]
        ipvs.append(ipv)

    return ipvs


def update_pvs(conn, forihostid, ipvs):
    new_pvs = []
    uuid_idx = IPV_COLUMNS.index("uuid")
    device_path_idx = IPV_COLUMNS.index("disk_or_part_device_path")
    pv_name_idx = IPV_COLUMNS.index("lvm_pv_name")
    with conn.cursor(cursor_factory=DictCursor) as cur:
        for ipv in ipvs:
            device_path = ipv[device_path_idx]
            pv_name = ipv[pv_name_idx]
            setters = ", ".join(["%s=%%s"] * len(IPV_COLUMNS))
            sql_tmp = "UPDATE i_pv SET %s where forihostid=%s and " \
                      "disk_or_part_device_path=%s" % (setters, "%%s", "%%s")
            sql = sql_tmp % IPV_COLUMNS

            params = tuple(ipv) + (forihostid, device_path)
            cur.execute(sql, params)
            if cur.rowcount == 0:
                LOG.debug("new pv %s" % pv_name)
                new_pvs.append(ipv)
            else:
                LOG.debug("update pv %s" % pv_name)

        for ipv in new_pvs:
            pv_name = ipv[pv_name_idx]
            col_fmt = ", ".join(["%s"] * len(IPV_COLUMNS))
            values_fmt = ", ".join(["%%s"] * len(IPV_COLUMNS))
            sql_fmt = "INSERT INTO i_pv (%s) VALUES(%s)" % \
                      (col_fmt, values_fmt)
            sql = sql_fmt % IPV_COLUMNS
            cur.execute(sql, ipv)
            if cur.rowcount == 1:
                LOG.info("Add new pv %s, %s" % (pv_name, ipv[uuid_idx]))

        pv_names = [p[pv_name_idx] for p in ipvs]
        # delete the lvgs that no longer exist
        in_list = ', '.join(['%s'] * len(pv_names))
        sql = "DELETE FROM i_pv where forihostid = %s and " \
              "not lvm_pv_name in (%s)" % (forihostid, in_list)
        pv_names = tuple(pv_names)
        cur.execute(sql, pv_names)
        count = cur.rowcount
        if count > 0:
            LOG.info("%s pv no longer exist" % count)

        sql = "SELECT id, uuid, lvm_pv_name, pv_type, disk_or_part_uuid " \
              "FROM i_pv WHERE forihostid = %s"
        cur.execute(sql, (forihostid, ))
        pvs = [{"id": d[0], "uuid": d[1], "lvm_pv_name": d[2], "pv_type":
                d[3], "disk_or_part_uuid": d[4]} for d in cur.fetchall()]
        return pvs


def get_lvgs(forihostid):
    # LVG_COLUMNS = 'created_at', 'updated_at', 'deleted_at', 'uuid',
    #               'vg_state', 'lvm_vg_name', 'lvm_vg_uuid', 'lvm_vg_access',
    #               'lvm_max_lv', 'lvm_cur_lv', 'lvm_max_pv', 'lvm_cur_pv',
    #               'lvm_vg_size', 'lvm_vg_total_pe', 'lvm_vg_free_pe',
    #               'capabilities', 'forihostid'
    #
    # ilvg_get():   'lvm_vg_name', 'lvm_vg_uuid', 'lvm_vg_access',
    #               'lvm_max_lv', 'lvm_cur_lv', 'lvm_max_pv',
    #               'lvm_cur_pv', 'lvm_vg_size', 'lvm_vg_total_pe',
    #               'lvm_vg_free_pe',
    #  adding       'created_at', 'updated_at', 'deleted_at', 'uuid',
    #               'forihostid', vg_state, capabilities for db
    lvgo = Lvg.LVGOperator()
    lvgs = lvgo.ilvg_get()
    now = datetime.now()
    ilvgs = []

    lvg_additions = {
        "created_at": now,
        "updated_at": now,
        "deleted_at": None,
        "forihostid": forihostid,
        # TODO: check to load capabilities
        "capabilities": None,
        # vg_state can only be provisioned during upgrade
        "vg_state": "provisioned"
    }

    for lvg in lvgs:
        # regenerate uuid
        lvg_additions["uuid"] = "%s" % uuid.uuid4()
        lvg.update(lvg_additions)

        ilvg = []
        # the LVG_COLUMNS is the order of insert statement,
        # sort the values in the same order below to form
        # SQL statements
        ilvg = [lvg[col] for col in LVG_COLUMNS]
        ilvgs.append(ilvg)

    return ilvgs


def update_lvgs(conn, forihostid, ilvgs):
    new_lvgs = []
    uuid_idx = LVG_COLUMNS.index("uuid")
    lvgname_idx = LVG_COLUMNS.index("lvm_vg_name")
    with conn.cursor(cursor_factory=DictCursor) as cur:
        for ilvg in ilvgs:
            lvg_name = ilvg[lvgname_idx]
            setters = ", ".join(["%s=%%s"] * len(LVG_COLUMNS))
            sql_tmp = "UPDATE i_lvg SET %s where forihostid=%s and " \
                      "lvm_vg_name=%s" % (setters, "%%s", "%%s")
            sql = sql_tmp % LVG_COLUMNS

            params = tuple(ilvg) + (forihostid, lvg_name)
            cur.execute(sql, params)
            if cur.rowcount == 0:
                LOG.debug("new lvg %s" % lvg_name)
                new_lvgs.append(ilvg)
            else:
                LOG.debug("update lvg %s" % lvg_name)

        for ilvg in new_lvgs:
            lvg_name = ilvg[lvgname_idx]
            col_fmt = ", ".join(["%s"] * len(LVG_COLUMNS))
            values_fmt = ", ".join(["%%s"] * len(LVG_COLUMNS))
            sql_fmt = "INSERT INTO i_lvg (%s) VALUES(%s)" % \
                      (col_fmt, values_fmt)
            sql = sql_fmt % LVG_COLUMNS
            cur.execute(sql, ilvg)
            if cur.rowcount == 1:
                LOG.info("Add new lvg %s, %s" % (lvg_name, ilvg[uuid_idx]))

        lvg_names = [l[lvgname_idx] for l in ilvgs]
        # delete the lvgs that no longer exist
        in_list = ', '.join(['%s'] * len(lvg_names))
        sql = "DELETE FROM i_lvg where forihostid = %s and " \
              "not lvm_vg_name in (%s)" % (forihostid, in_list)
        lvg_names = tuple(lvg_names)
        cur.execute(sql, lvg_names)
        count = cur.rowcount
        if count > 0:
            LOG.info("%s lvg no longer exist" % count)

        sql = "SELECT id, uuid, lvm_vg_name FROM i_lvg WHERE forihostid = %s"
        cur.execute(sql, (forihostid, ))
        lvgs = [{"id": d[0], "uuid": d[1], "lvm_vg_name": d[2]}
                for d in cur.fetchall()]
        return lvgs


def update_ipvid(conn, ipvs):
    with conn.cursor(cursor_factory=DictCursor) as cur:
        for ipv in ipvs:
            if ipv["pv_type"] == "disk":
                sql = "UPDATE i_idisk SET foripvid = %s where uuid=%s"
            else:
                sql = "UPDATE partition SET foripvid = %s where uuid=%s"

            cur.execute(sql, (ipv["id"], ipv["disk_or_part_uuid"]))
            count = cur.rowcount
            if count == 0:
                raise Exception("Cannot update foripvid. %" % ipv)


def do_update():
    res = 0
    conn = psycopg2.connect("dbname=sysinv user=postgres")
    try:
        hostid = get_ihostid(conn)
        disk_uuid_mapping = get_disk_uuid_mapping(conn, hostid)
        idisks = get_idisks(hostid, disk_uuid_mapping)
        disks = update_disks(conn, idisks)

        partitions = get_ipartitions(hostid, disks)
        partitions = update_partition(conn, partitions)

        disk_or_partition = disks + partitions

        ilvgs = get_lvgs(hostid)
        lvgs = update_lvgs(conn, hostid, ilvgs)

        ipvs = get_pvs(hostid, lvgs, disk_or_partition)
        pvs = update_pvs(conn, hostid, ipvs)

        update_ipvid(conn, pvs)

    except psycopg2.Error as ex:
        LOG.exception(ex)
        res = 1
    except Exception as ex:
        LOG.exception(ex)
        res = 1
    finally:
        LOG.info("Committing all changes into database")
        conn.commit()
        conn.close()

    return res

if __name__ == "__main__":
    sys.exit(main())
