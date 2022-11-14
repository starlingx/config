#!/usr/bin/env python
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This is a data migration script to pickup the partition changes during
# upgrade to Debian OS.
# The migration refreshes the partition, i_pv and i_lvg tables
# with the new partition configuration on filessytem of Debian StarlingX
# after controller-1 is upgraded.
#
import copy
import sys
import psycopg2
from controllerconfig.common import log
from datetime import datetime
import operator
from psycopg2.extras import DictCursor
import uuid

from sysinv.common import constants
from sysinv.common import utils as cutils
from sysinv.agent import partition as Partition

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


IPARTITION_COLUMNS = 'created_at', 'updated_at', 'deleted_at', 'uuid', \
                     'start_mib', 'end_mib', 'size_mib', 'device_path', \
                     'type_guid', 'type_name', 'idisk_id', 'idisk_uuid', \
                     'capabilities', 'status', 'foripvid', 'forihostid', \
                     'device_node'

# worker node partition template
WORKER_PARTITION_LIST = [
    {'start_mib': '1', 'end_mib': '2', 'size_mib': '1',
     'type_guid': '21686148-6449-6e6f-744e-656564454649',
     'type_name': 'BIOS boot partition'},
    {'start_mib': '2', 'end_mib': '302', 'size_mib': '300',
     'type_guid': 'c12a7328-f81f-11d2-ba4b-00a0c93ec93b',
     'type_name': 'EFI system partition'},
    {'start_mib': '302', 'end_mib': '2350', 'size_mib': '2048',
     'type_guid': '0fc63daf-8483-4772-8e79-3d69d8477de4',
     'type_name': 'Linux filesystem'},
    {'start_mib': '2350', 'end_mib': '113966', 'size_mib': '111616',
     'type_guid': 'e6d6d379-f507-44c2-a23c-238f2a3df928',
     'type_name': 'Linux LVM'}]


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


def get_idisks(conn, forihostid):
    # do not consider disk change (replace, remove, or add new disk)
    # during upgrade
    sql = "SELECT * FROM i_idisk WHERE forihostid = %s;"
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute(sql, (forihostid, ))
        idisks = cur.fetchall()
        return idisks


def get_cur_host(conn):
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
        partitions = cur.fetchall()
        return partitions


def get_controller_partition_template(rootdisk):
    # return list of partitions created on rootdisk, sorted by physical
    # order (start_mib)

    root_device_path = rootdisk["device_path"]
    root_device_node = rootdisk["device_node"]
    po = Partition.PartitionOperator()
    partitions = po.ipartition_get(skip_gpt_check=True)

    # sort by start_mib
    now = datetime.now()

    partition_additions = {
        "created_at": now,
        "updated_at": now,
        "deleted_at": None,
        # foripvid will be populated when updating i_pv table
        "foripvid": None,
        # TODO: check to load capabilities
        "capabilities": None,
        # These are the partitions that have already created
        "status": 1
    }

    bootdisk_partitions = []
    for partition in partitions:
        partition.update(partition_additions)
        part_device_path = partition["device_path"]
        if is_device_path_on_disk(part_device_path, root_device_path,
                                  root_device_node):
            partition["device_path"] = None
            partition["device_node"] = None
            bootdisk_partitions.append(partition)
    return sorted(bootdisk_partitions, key=operator.itemgetter('start_mib'))


def get_node_partition_template(part_list):
    # create a partition template from a list of partitions
    template = copy.deepcopy(part_list)

    now = datetime.now()
    partition_additions = {
        "created_at": now,
        "updated_at": now,
        "deleted_at": None,
        # foripvid will be populated when updating i_pv table
        "foripvid": None,
        # TODO: check to load capabilities
        "capabilities": None,
        # These are the partitions that have already created
        "status": 1,
        "device_path": None,
        "device_node": None
    }

    for partition in template:
        partition.update(partition_additions)

    return template


def get_ipartitions(forihostid, template, rootdisk):
    # localize default partitions on rootdisk
    partitions = copy.deepcopy(template)

    rootdisk_device_node = rootdisk["device_node"]
    rootdisk_device_path = rootdisk["device_path"]
    idx = 1
    for partition in partitions:
        # regenerate uuid
        partition["uuid"] = "%s" % uuid.uuid4()
        partition["idisk_id"] = rootdisk["id"]
        partition["idisk_uuid"] = rootdisk["uuid"]
        partition["forihostid"] = forihostid
        device_node, device_path = \
            build_device_node_path(rootdisk_device_node, rootdisk_device_path,
                                   idx)
        partition["device_node"] = device_node
        partition["device_path"] = device_path
        idx += 1

    return partitions


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


def append_additional_partitions(conn, new_rootdisk_partitions,
                                 host, rootdisk):
    # append user created partitions on rootdisk from the N release
    # new_rootdisk_partitions is new default partitions on root disk
    # will append additional user partitions on root disk to the list
    # to form the entier partition list on root disk

    forihostid = host["id"]
    personality = host["personality"]
    # get partitions on rootdisk from N db
    rootdisk_partitions = get_rootdisk_partitions(conn, forihostid)

    rootdisk_device_node = rootdisk["device_node"]
    rootdisk_device_path = rootdisk["device_path"]

    LOG.info("Previous release ipartitions on root disk %s \n%s" %
             (rootdisk_device_path, rootdisk_partitions))

    # get the end mib for the last default partition from release N+1
    new_end_mib = new_rootdisk_partitions[-1]["end_mib"]

    end_mib_default_partition = None
    foripvid = None

    # find the last default partition in ordered list. All default
    # partitions will be replaced with new default partitions.
    last_default_partition_idx = -1
    for idx in range(0, len(rootdisk_partitions)):
        partition = rootdisk_partitions[idx]
        if partition["lvm_vg_name"] == "cgts-vg":
            # found the 1st cgts-vg.
            # In pre Debian load, it is the last default partition on
            # controller and storage nodes. It is the 2nd last default
            # partition on worker nodes.
            # TODO: bqian: in Debian load (as N release), the first cgts-vg
            # partition is the last default partition for all node types
            if personality == "controller":
                last_default_partition_idx = idx
            elif personality == "worker":
                last_default_partition_idx = idx + 1
            elif personality == "storage":
                last_default_partition_idx = idx

            foripvid = partition["foripvid"]
            new_rootdisk_partitions[-1]["foripvid"] = foripvid
            break

    if last_default_partition_idx < 0:
        # something we don't understand
        raise Exception("Cannot determine the partition layout in N release")

    last_default_partition = rootdisk_partitions[last_default_partition_idx]
    end_mib_default_partition = last_default_partition["end_mib"]
    mib_offset = int(new_end_mib) - int(end_mib_default_partition)

    next_partition_idx = last_default_partition_idx + 1
    for idx in range(next_partition_idx, len(rootdisk_partitions)):
        partition = rootdisk_partitions[idx]
        device_node, device_path = \
            build_device_node_path(rootdisk_device_node,
                                   rootdisk_device_path,
                                   len(new_rootdisk_partitions) + 1)

        partition["device_node"] = device_node
        partition["device_path"] = device_path
        partition["start_mib"] = int(partition["start_mib"]) + mib_offset
        partition["end_mib"] = int(partition["end_mib"]) + mib_offset
        partition["status"] = constants.PARTITION_CREATE_ON_UNLOCK_STATUS
        new_rootdisk_partitions.append(partition)
        LOG.info("To recreate partition %s" % partition)

    ipartitions = []
    for partition in new_rootdisk_partitions:
        ipartition = [partition[key] for key in IPARTITION_COLUMNS]
        ipartitions.append(ipartition)
    return ipartitions


def update_partition(conn, ipartitions, forihostid, rootdisk):
    dp_idx = IPARTITION_COLUMNS.index("device_path")
    partition_disk_uuid_idx = IPARTITION_COLUMNS.index("idisk_uuid")
    rootdisk_uuid = rootdisk["uuid"]

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


def update_pvs(conn, forihostid):
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
        LOG.info("Update %s PVs on partitions" % cur.rowcount)

        sql = "SELECT id, uuid, lvm_pv_name, pv_type, pv_state, " \
              "disk_or_part_uuid " \
              "FROM i_pv WHERE forihostid = %s"
        cur.execute(sql, (forihostid, ))
        pvs = [{"id": d[0], "uuid": d[1], "lvm_pv_name": d[2], "pv_type":
               d[3], "pv_state": d[4], "disk_or_part_uuid": d[5]}
               for d in cur.fetchall()]
        return pvs


def update_lvgs(conn, forihostid):
    with conn.cursor(cursor_factory=DictCursor) as cur:
        # mark lvgs to be recreated during host unlock
        sql = "UPDATE i_lvg SET vg_state = %s " \
              "WHERE lvm_vg_name <> 'cgts-vg' AND forihostid = %s;"
        cur.execute(sql, (constants.LVG_ADD, forihostid))
        count = cur.rowcount
        if count > 0:
            LOG.info("%s lvg will be recreated" % count)

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


def get_rootdisk(conn, hostid, boot_device):
    # return device_node and device_path of rootdisk
    sql = "SELECT id, uuid, device_node, device_path " \
          "FROM i_idisk " \
          "WHERE (device_node = %s OR device_path = %s) AND forihostid = %s"
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute(sql, (boot_device, boot_device, hostid))
        rootdisk = cur.fetchone()
    return rootdisk


def get_hosts(conn):
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute("SELECT id, hostname, personality, boot_device "
                    "FROM i_host WHERE personality "
                    "IN ('controller', 'worker', 'storage');")
        nodes = cur.fetchall()
        return nodes


def update_host(conn, host, partition_template):
    hostid = host["id"]
    hostname = host["hostname"]

    rootdisk = get_rootdisk(conn, hostid, host["boot_device"])
    ipartitions = get_ipartitions(hostid,
                                  partition_template, rootdisk)

    ipartitions = append_additional_partitions(conn, ipartitions,
                                               host, rootdisk)
    ipartitions = update_partition(conn, ipartitions, hostid, rootdisk)

    lvgs = update_lvgs(conn, hostid)

    pvs = update_pvs(conn, hostid)

    LOG.info("partition migration summary %s:" % hostname)
    LOG.info("=" * 60)
    LOG.info("new list of lvgs:")
    for lvg in lvgs:
        LOG.info("%s" % lvg)

    LOG.info("new list of pvs:")
    for pv in pvs:
        LOG.info("%s" % pv)

    LOG.info("new list of partitions:")
    for ip in ipartitions:
        LOG.info(ip)
    LOG.info("=" * 60)


def do_update():
    res = 0
    conn = psycopg2.connect("dbname=sysinv user=postgres")

    try:
        cur_host = get_cur_host(conn)
        rootdisk = get_rootdisk(conn, cur_host["id"], cur_host["boot_device"])
        controller_partitions = get_controller_partition_template(rootdisk)
        worker_partitions = get_node_partition_template(WORKER_PARTITION_LIST)

        # migrate hosts with the partition template
        hosts = get_hosts(conn)
        for host in hosts:
            personality = host["personality"]
            if personality == "worker":
                partition_template = worker_partitions
            elif personality == "controller":
                partition_template = controller_partitions
            elif personality == "storage":
                # nothing to migrate on storage node, as no user partitions
                # are allowed on root disk
                continue

            update_host(conn, host, partition_template)

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
