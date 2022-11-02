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
import operator
from psycopg2.extras import DictCursor
import uuid

from sysinv.common import constants
from sysinv.common import utils as cutils
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


def get_ihost(conn):
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute("SELECT system_mode FROM i_system;")
        system = cur.fetchone()
        upgrade_controller = "controller-1"
        if system["system_mode"] == "simplex":
            upgrade_controller = "controller-0"

        cur.execute("SELECT id, boot_device FROM i_host WHERE hostname = %s;",
                    (upgrade_controller,))
        instance = cur.fetchone()
        if instance is None:
            raise Exception("Failed to retrieve host id for %s" %
                            upgrade_controller)
        return instance


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


def get_rootdisk_partitions(conn, forihostid):
    # get partitions on root disk of N release configuration
    # the corresponding vg name is ammended to the end of each partition.
    col_fmt = "p." + ", p.".join(IPARTITION_COLUMNS)
    sql_fmt = "select %s, pv.lvm_vg_name " \
              "from partition as p left join i_pv pv on pv.id = foripvid " \
              "where idisk_uuid in" \
              "    (select d.uuid from i_host join i_idisk d on" \
              "        d.device_node = boot_device or" \
              "        d.device_path = boot_device" \
              "        where d.forihostid = %%s and i_host.id = %%s) " \
              "order by start_mib;" % col_fmt
    sql = sql_fmt % (forihostid, forihostid)
    partitions = []
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute(sql, (forihostid, forihostid))
        for rec in cur.fetchall():
            partition = []
            for idx in range(len(rec)):
                partition.append(rec[idx])
            partitions.append(partition)

        return partitions


def get_ipartitions(forihostid, disks):
    # return ipartitions list sorted by physical order (start_mib)
    po = Partition.PartitionOperator()
    partitions = po.ipartition_get(skip_gpt_check=True)

    # sort by start_mib
    partitions = sorted(partitions, key=operator.itemgetter('start_mib'))
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
        # These are the partitions that have already created
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


def build_device_node_path(disk_device_node, disk_device_path, device_idx):
    """Builds the partition device path and device node based on last
       partition number and assigned disk.
    """
    if constants.DEVICE_NAME_NVME in disk_device_node:
        device_node = "%sp%s" % (disk_device_node, device_idx)
    else:
        device_node = "%s%s" % (disk_device_node, device_idx)
    device_path = cutils.get_part_device_path(disk_device_path,
                                              str(device_idx))
    return device_node, device_path


def is_device_path_on_disk(device_path, disk_device_path, disk_device_node):
    if disk_device_path in device_path:
        return True
    elif constants.DEVICE_NAME_MPATH in disk_device_node:
        path_split = disk_device_node.split(constants.DEVICE_NAME_MPATH)
        if path_split[0] in device_path and path_split[1] in device_path:
            return True
    return False


def append_additional_partitions(conn, ipartitions_all, forihostid, rootdisk):
    # append user created partitions on rootdisk from the N release
    rootdisk_partitions = get_rootdisk_partitions(conn, forihostid)

    start_mib_idx = IPARTITION_COLUMNS.index("start_mib")
    end_mib_idx = IPARTITION_COLUMNS.index("end_mib")
    device_node_idx = IPARTITION_COLUMNS.index("device_node")
    device_path_idx = IPARTITION_COLUMNS.index("device_path")
    status_idx = IPARTITION_COLUMNS.index('status')
    foripvid_idx = IPARTITION_COLUMNS.index('foripvid')

    disk_device_node_idx = IDISK_COLUMNS.index("device_node")
    disk_device_path_idx = IDISK_COLUMNS.index("device_path")

    rootdisk_device_node = rootdisk[disk_device_node_idx]
    rootdisk_device_path = rootdisk[disk_device_path_idx]

    ipartitions_rootdisk = []
    LOG.debug("ipartitions_all %s" % ipartitions_all)
    for ipartition in ipartitions_all:
        part_device_path = ipartition[device_path_idx]
        if is_device_path_on_disk(part_device_path, rootdisk_device_path,
                                  rootdisk_device_node):
            ipartitions_rootdisk.append(ipartition)
    LOG.debug("ipartitions on root disk %s \n%s" %
              (rootdisk_device_path, ipartitions_rootdisk))

    # get the end mib for the last default partition from release N+1
    new_end_mib = ipartitions_all[-1][end_mib_idx]

    end_mib_default_cgts_vg = None
    foripvid = None

    # old and new device_path mapping.
    # device_path_mapping = {}

    for ipartition in rootdisk_partitions:
        if end_mib_default_cgts_vg is None:
            # the cgts-vg 1st pv is the end of default partition. Partitions
            # created before it will be replaced with new default partitions
            # in N+1 release. The N+1 default partitions and partitions on
            # the other disk (non-root disk) are retrieved from
            # get_ipartitions.

            # in get_rootdisk_partitions, lvm_vg_name column is appended
            # to the end of all partition column.
            LOG.info("DEBUG: partition %s is for lvm_vg %s" %
                     (ipartition[device_node_idx], ipartition[-1]))
            if ipartition[-1] == "cgts-vg":
                # this is the end mib for the last default partition
                # from release N
                end_mib_default_cgts_vg = ipartition[end_mib_idx]
                mib_offset = int(new_end_mib) - int(end_mib_default_cgts_vg)

                # the last partition kickstart creates is the first cgts-vg pv.
                foripvid = ipartition[foripvid_idx]
                ipartitions_all[-1][foripvid_idx] = foripvid
        else:
            device_node, device_path = \
                build_device_node_path(rootdisk_device_node,
                                       rootdisk_device_path,
                                       len(ipartitions_rootdisk) + 1)

            # device_path_mapping[ipartition[device_path_idx] = device_path
            ipartition[device_node_idx] = device_node
            ipartition[device_path_idx] = device_path
            ipartition[start_mib_idx] = \
                int(ipartition[start_mib_idx]) + mib_offset
            ipartition[end_mib_idx] = int(ipartition[end_mib_idx]) + mib_offset
            ipartition[status_idx] = \
                constants.PARTITION_CREATE_ON_UNLOCK_STATUS
            # copy partition data into ipartitions_rootdisk array, i.e, remove
            # ending lvm_vg_name column
            ipartitions_rootdisk.append(ipartition[0: len(IPARTITION_COLUMNS)])
            LOG.info("DEBUG: recreating partition %s" % ipartition)
    LOG.info("DEBUG: new list of partitions %s" % ipartitions_rootdisk)
    return ipartitions_rootdisk


def update_partition(conn, ipartitions, forihostid, rootdisk):
    dp_idx = IPARTITION_COLUMNS.index("device_path")
    # uuid_idx = IPARTITION_COLUMNS.index("uuid")
    disk_uuid_idx = IDISK_COLUMNS.index("uuid")
    partition_disk_uuid_idx = IPARTITION_COLUMNS.index("idisk_uuid")
    rootdisk_uuid = rootdisk[disk_uuid_idx]

    with conn.cursor(cursor_factory=DictCursor) as cur:
        # 1. delete all partitions on rootdisk
        sql = "DELETE FROM partition where idisk_uuid = %s;"
        LOG.info("Delete partition records on root disk: uuid(%s)" %
                 rootdisk_uuid)
        cur.execute(sql, (rootdisk_uuid, ))
        count = cur.rowcount
        LOG.info("%s partition records are deleted" % count)

        # 2. recreate records for the partitions on created root disk
        LOG.info("recreate partition record on root disk %s" % rootdisk_uuid)
        for ipartition in ipartitions:
            if ipartition[partition_disk_uuid_idx] != rootdisk_uuid:
                # skip non-rootdisk partitions
                continue

            device_path = ipartition[dp_idx]
            col_fmt = ", ".join(["%s"] * len(IPARTITION_COLUMNS))
            values_fmt = ", ".join(["%%s"] * len(IPARTITION_COLUMNS))
            sql_fmt = "INSERT INTO partition (%s) VALUES(%s)" % \
                      (col_fmt, values_fmt)
            sql = sql_fmt % IPARTITION_COLUMNS
            cur.execute(sql, ipartition)
            if cur.rowcount == 1:
                LOG.info("Create new partition %s, %s" %
                         (device_path, ipartition[partition_disk_uuid_idx]))

        LOG.info("Done recreate partitions on root disk")

        sql = "SELECT id, uuid, device_node, device_path, foripvid " \
            "FROM partition WHERE forihostid = %s"
        cur.execute(sql, (forihostid, ))
        partitions = [{"id": d[0], "uuid": d[1], "device_node": d[2],
                       "device_path": d[3], "foripvid": d[4],
                       "type": "partition"}
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
            if dop["foripvid"] == pv["id"]:
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


def update_pvs(conn, forihostid):
    LOG.info("update PVs")

    with conn.cursor(cursor_factory=DictCursor) as cur:
        # partition records are pointing to i_pv, but the i_pv reference
        # to partition uuid (disk_or_part_uuid) and device_node
        # (disk_or_part_device_node) needs to relink.
        # this is a double link

        # update primary cgts-vg pv, this pv and partition have been
        # provisioned
        sql = "UPDATE i_pv " \
              "SET disk_or_part_uuid = p.uuid, " \
              "disk_or_part_device_node = p.device_node, " \
              "disk_or_part_device_path = p.device_path, " \
              "lvm_pv_name = p.device_node " \
              "FROM i_pv AS v JOIN partition AS p ON p.foripvid = v.id " \
              "WHERE v.forihostid = %s AND p.forihostid = %s AND" \
              "      i_pv.id = v.id AND p.status <> %s"
        cur.execute(sql, (forihostid, forihostid,
                          constants.PARTITION_CREATE_ON_UNLOCK_STATUS))
        LOG.info("Updated %s PVs" % cur.rowcount)

        # update additional PVs, these pv and partitions have not been
        # provisioned
        sql = "UPDATE i_pv " \
              "SET disk_or_part_uuid = p.uuid, " \
              "disk_or_part_device_node = p.device_node, " \
              "disk_or_part_device_path = p.device_path, " \
              "lvm_pv_name = p.device_node, " \
              "pv_state = %s " \
              "FROM i_pv AS v JOIN partition AS p ON p.foripvid = v.id " \
              "WHERE v.forihostid = %s AND p.forihostid = %s AND" \
              "      i_pv.id = v.id AND p.status = %s"
        cur.execute(sql, (constants.PV_ADD, forihostid, forihostid,
                          constants.PARTITION_CREATE_ON_UNLOCK_STATUS))
        LOG.info("Update %s PVs" % cur.rowcount)

        sql = "SELECT id, uuid, lvm_pv_name, pv_type, pv_state, " \
              "disk_or_part_uuid " \
              "FROM i_pv WHERE forihostid = %s"
        cur.execute(sql, (forihostid, ))
        pvs = [{"id": d[0], "uuid": d[1], "lvm_pv_name": d[2], "pv_type":
               d[3], "pv_state": d[4], "disk_or_part_uuid": d[5]}
               for d in cur.fetchall()]
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
        in_list = ', '.join(['%s'] * len(lvg_names))
        # for the LVGs that are not created, (not retrieved from system),
        # mark them to be recreated during host unlock
        sql = "UPDATE i_lvg SET vg_state = '%s' " \
              "FROM (SELECT vg.id FROM i_lvg vg JOIN i_pv pv ON " \
              "      pv.forilvgid = vg.id " \
              "      WHERE vg.forihostid = %s AND " \
              "          vg.lvm_vg_name not IN (%s)) AS filter " \
              "WHERE i_lvg.id = filter.id;" % \
              (constants.LVG_ADD, forihostid, in_list)

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


def get_disk_or_partition(conn, hostid):
    sql = "SELECT uuid, device_node, device_path, foripvid, 'disk' as type " \
          "FROM i_idisk WHERE forihostid = %s UNION " \
          "SELECT uuid, device_node, device_path, foripvid, " \
          "'partition' as type FROM partition WHERE forihostid = %s;"
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute(sql, (hostid, hostid))
        dops = [{"uuid": d[0], "device_node": d[1], "device_path": d[2],
                 "foripvid": d[3], "type": d[4]}
                for d in cur.fetchall()]
        return dops


def get_rootdisk(idisks, boot_device):
    dn_idx = IDISK_COLUMNS.index("device_node")
    dp_idx = IDISK_COLUMNS.index("device_path")
    # The boot_device from i_host can be either device_node or device_path
    for idisk in idisks:
        if boot_device in (idisk[dp_idx], idisk[dn_idx]):
            return idisk
    raise Exception("Cannot find root disk %s" % boot_device)


def do_update():
    res = 0
    conn = psycopg2.connect("dbname=sysinv user=postgres")

    try:
        ihost = get_ihost(conn)
        hostid = ihost["id"]
        boot_device = ihost["boot_device"]

        LOG.info("Upgrade hostid %s, boot_device %s" % (hostid, boot_device))
        disk_uuid_mapping = get_disk_uuid_mapping(conn, hostid)
        idisks = get_idisks(hostid, disk_uuid_mapping)
        rootdisk = get_rootdisk(idisks, boot_device)
        disks = update_disks(conn, idisks)

        ipartitions = get_ipartitions(hostid, disks)
        ipartitions = append_additional_partitions(conn, ipartitions,
                                                   hostid, rootdisk)
        ipartitions = update_partition(conn, ipartitions, hostid, rootdisk)

        ilvgs = get_lvgs(hostid)
        lvgs = update_lvgs(conn, hostid, ilvgs)

        pvs = update_pvs(conn, hostid)

        LOG.info("partition migration summary:")
        LOG.info("=========================================================")
        LOG.info("new list of lvgs:")
        for lvg in lvgs:
            LOG.info("%s" % lvg)

        LOG.info("new list of pvs:")
        for pv in pvs:
            LOG.info("%s" % pv)

        LOG.info("new list of partitions:")
        for ip in ipartitions:
            LOG.info(ip)
        LOG.info("=========================================================")

    except psycopg2.Error as ex:
        conn.rollback()
        LOG.exception(ex)
        LOG.warning("Rollback changes")
        res = 1
    except Exception as ex:
        conn.rollback()
        LOG.exception(ex)
        LOG.warning("Rollback changes")
        res = 1
    else:
        LOG.info("All good, committing all changes into database")
        conn.commit()
    finally:
        conn.close()

    return res

if __name__ == "__main__":
    sys.exit(main())
