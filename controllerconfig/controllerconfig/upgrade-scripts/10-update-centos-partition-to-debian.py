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

# set partition end_mib to END_OF_DISK_MIB to indicate
# that the partition will take all the remaining disk spaces
END_OF_DISK_MIB = "-1"
ONE_GIB = 1024 * 1024 * 1024


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
    if action == "migrate" and (from_release in ['22.06', '21.12'] and
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
    {'start_mib': '2350', 'end_mib': END_OF_DISK_MIB, 'size_mib': '0',
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
    sorted_list = sorted(bootdisk_partitions,
                         key=operator.itemgetter('start_mib'))

    # the last partition takes all the rest of disk spaces
    sorted_list[-1]["end_mib"] = END_OF_DISK_MIB
    return sorted_list


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
        if partition["end_mib"] == END_OF_DISK_MIB:
            # get all the rest of disk spaces
            end_mib = int(rootdisk["size_mib"]) + 1
            partition["end_mib"] = str(end_mib)
            partition["size_mib"] = str(end_mib - int(partition["start_mib"]))
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
    # get partitions on rootdisk from N db
    rootdisk_partitions = get_rootdisk_partitions(conn, forihostid)

    rootdisk_device_node = rootdisk["device_node"]
    LOG.info("Previous release ipartitions on root disk %s \n%s" %
             (rootdisk_device_node, rootdisk_partitions))

    # find the last default partition in ordered list. All default
    # partitions will be replaced with new default partitions.
    for partition in rootdisk_partitions:
        if partition["lvm_vg_name"] == "cgts-vg":
            # found the 1st cgts-vg.
            # cgts-vg in new load will replace the existing cgts-vg partition
            # on the node as PV of cgts-vg
            new_rootdisk_partitions[-1]["foripvid"] = partition["foripvid"]
            break
    else:
        # a cgts-vg is not found on root disk... game over
        raise Exception("cgts-vg partition is not found on rootdisk")

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

        # Delete the PVs that link to user partition on boot disk.
        # As the user partitions on boot disk are deleted during
        # update_partition, the orphan partition PVs are to be deleted.
        sql = "DELETE FROM i_pv " \
              "WHERE pv_type = 'partition' AND forihostid = %s AND id NOT IN" \
              " (SELECT foripvid FROM partition WHERE forihostid = %s AND " \
              "foripvid IS NOT Null)"
        cur.execute(sql, (forihostid, forihostid))
        count = cur.rowcount
        if count > 0:
            LOG.info("Deleted %s PVs on user partition" % cur.rowcount)

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
        # delete the lvgs that don't have any PVs.
        # PVs can be deleted in update_pvs when associated partition is
        # deleted as root disk space is reallocated to cgts-vg.
        # nova-local can be deleted if all nova-local PVs are partitions
        # on root disk. In this case all partitions and PVs are deleted
        # in update_partition and update_pvs.
        sql = "DELETE FROM i_lvg " \
              "WHERE forihostid = %s AND id NOT IN " \
              "(SELECT forilvgid FROM i_pv WHERE forihostid = %s AND " \
              "forilvgid IS NOT Null);"
        cur.execute(sql, (forihostid, forihostid))
        count = cur.rowcount
        if count > 0:
            LOG.info("Deleted %s unused lvg" % count)

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
    sql = "SELECT id, uuid, device_node, device_path, size_mib " \
          "FROM i_idisk " \
          "WHERE (device_node = %s OR device_path = %s) AND forihostid = %s"
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute(sql, (boot_device, boot_device, hostid))
        rootdisk = cur.fetchone()
    return rootdisk


def get_hosts(conn):
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute("SELECT id, hostname, personality, boot_device, "
                    "subfunctions "
                    "FROM i_host WHERE personality "
                    "IN ('controller', 'worker');")
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

    pvs = update_pvs(conn, hostid)
    lvgs = update_lvgs(conn, hostid)

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


def get_nova_local_pvs(conn, hostid):
    sql = "SELECT pv_type, lvm_vg_name, lvm_pv_size, disk_or_part_uuid " \
          "FROM i_pv WHERE forihostid = %s AND lvm_vg_name='nova-local';"
    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute(sql, (hostid,))
        pvs = cur.fetchall()
        return pvs


def create_instances_lv(conn, host, rootdisk_nova_local_size):
    # size_gib is rounded up to nearest Gib
    sql = "INSERT INTO host_fs" \
          "(created_at, uuid, name, size, logical_volume, forihostid) " \
          "VALUES(%s, %s, %s, %s, %s, %s);"

    created_at = datetime.now()
    fs_uuid = "%s" % uuid.uuid4()
    name = constants.FILESYSTEM_NAME_INSTANCES
    # round up
    size_gib = int((rootdisk_nova_local_size + ONE_GIB - 1) / ONE_GIB)
    lv_name = constants.FILESYSTEM_LV_DICT[name]
    forihostid = host["id"]

    with conn.cursor(cursor_factory=DictCursor) as cur:
        cur.execute(sql, (created_at, fs_uuid, name, size_gib,
                          lv_name, forihostid))
        if cur.rowcount == 1:
            LOG.info("%s: created cgts-vg:%s %sGib" %
                     (host["hostname"], lv_name, size_gib))


def migrate_nova_local(conn, host, rootdisk):
    # Migrate nova-local on boot disk
    # This only needs to do on nodes with worker subfunction
    # The migration rules:
    # 1. if nova-local only exists on boot disk as a partition,
    #    the nova-local partition will be dropped, replaced with
    #    same size will be allocated to cgts-vg:instances-lv,
    # 2. if nova-local only exists on separated disk, then no
    #    migration operation is needed
    # 3. if nova-local exists on both boot disk partition and
    #    separated disk, nova-local partition on boot disk will
    #    be dropped, and with no other compensation. This will
    #    result total nova-local space reduced.
    pvs = get_nova_local_pvs(conn, host["id"])
    if len(pvs) > 0:
        LOG.info("Found nova-local pvs on rootdisk: %s", pvs)

    rootdisk_partitions = get_rootdisk_partitions(conn, host["id"])
    rootdisk_part_uuids = [p["uuid"] for p in rootdisk_partitions]

    rootdisk_nova_local_size = 0
    pv_on_other_disk = False
    for pv in pvs:
        pv_type = pv["pv_type"]
        dop_uuid = pv["disk_or_part_uuid"]
        if (pv_type == "partition" and dop_uuid in rootdisk_part_uuids):
            rootdisk_nova_local_size += int(pv["lvm_pv_size"])
        else:
            pv_on_other_disk = True

    if rootdisk_nova_local_size > 0:
        if not pv_on_other_disk:
            create_instances_lv(conn, host, rootdisk_nova_local_size)
        else:
            msg = "Total nova-local is reduced by %s bytes"
            LOG.info(msg % rootdisk_nova_local_size)


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

            if personality == constants.WORKER:
                partition_template = worker_partitions
            elif personality == constants.CONTROLLER:
                partition_template = controller_partitions
            else:
                # nothing to migrate on storage node, as no user partitions
                # are allowed on root disk
                continue

            if "worker" in host["subfunctions"]:
                migrate_nova_local(conn, host, rootdisk)
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
