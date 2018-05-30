#!/usr/bin/env python
# Copyright (c) 2017-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will update the partition schema for controller-1.

import collections
import json
import math
import psycopg2
import re
import sys
import subprocess
import parted
from sysinv.openstack.common import uuidutils

from sysinv.common import constants
from psycopg2.extras import RealDictCursor
from controllerconfig.common import log
from controllerconfig import utils

from tsconfig.tsconfig import system_mode

LOG = log.get_logger(__name__)

Partition_Tuple = collections.namedtuple(
    'partition', 'uuid idisk_id idisk_uuid size_mib device_node device_path '
                 'status type_guid forihostid foripvid start_mib end_mib')
uefi_cgts_pv_1_partition_number = 4
bios_cgts_pv_1_partition_number = 5


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
            create_user_partitions()
        except Exception as ex:
            LOG.exception(ex)
            return 1


def get_partitions(device_path):
    """Obtain existing partitions from a disk."""
    try:
        device = parted.getDevice(device_path)
        disk = parted.newDisk(device)
    except Exception as e:
        LOG.info("No partition info for disk %s - %s" % (device_path, e))
        return None

    ipartitions = []

    partitions = disk.partitions

    for partition in partitions:
        part_size_mib = partition.getSize()
        part_device_node = partition.path
        part_device_path = '{}-part{}'.format(device_path,
                                              partition.number)
        start_mib = math.ceil(float(partition.geometry.start) / 2048)
        end_mib = math.ceil(float(partition.geometry.end) / 2048)

        part_attrs = {
            'size_mib': part_size_mib,
            'device_node': part_device_node,
            'device_path': part_device_path,
            'start_mib': start_mib,
            'end_mib': end_mib
        }
        ipartitions.append(part_attrs)

    return ipartitions


def get_disk_available_mib(device_node):
    # Get sector size command.
    sector_size_bytes_cmd = '{} {}'.format('blockdev --getss', device_node)

    # Get total free space in sectors command.
    avail_space_sectors_cmd = '{} {} {}'.format(
        'sgdisk -p', device_node, "| grep \"Total free space\"")

    # Get the sector size.
    sector_size_bytes_process = subprocess.Popen(
        sector_size_bytes_cmd, stdout=subprocess.PIPE, shell=True)
    sector_size_bytes = sector_size_bytes_process.stdout.read().rstrip()

    # Get the free space.
    avail_space_sectors_process = subprocess.Popen(
        avail_space_sectors_cmd, stdout=subprocess.PIPE, shell=True)
    avail_space_sectors_output = avail_space_sectors_process.stdout.read()
    avail_space_sectors = re.findall('\d+',
                                     avail_space_sectors_output)[0].rstrip()

    # Free space in MiB.
    avail_space_mib = (int(sector_size_bytes) * int(avail_space_sectors) /
                       (1024 ** 2))

    # Keep 2 MiB for partition table.
    if avail_space_mib >= 2:
        avail_space_mib = avail_space_mib - 2

    return avail_space_mib


def build_partition_device_node(disk_device_node, partition_number):
    if constants.DEVICE_NAME_NVME in disk_device_node:
        partition_device_node = '{}p{}'.format(
            disk_device_node, partition_number)
    else:
        partition_device_node = '{}{}'.format(
            disk_device_node, partition_number)

    LOG.info("partition_device_node: %s" % partition_device_node)

    return partition_device_node


def update_db_pv(cur, part_device_path, part_device_node, part_uuid,
                 lvm_pv_name, pv_id):
    cur.execute("update i_pv set disk_or_part_device_path=%s,"
                "disk_or_part_device_node=%s, disk_or_part_uuid=%s,"
                "lvm_pv_name=%s where id=%s",
                (part_device_path, part_device_node, part_uuid,
                 lvm_pv_name, pv_id))


def create_partition(cur, partition):
    cur.execute(
        "insert into partition(uuid, idisk_id, idisk_uuid, size_mib,"
        "device_node, device_path, status, type_guid, "
        "forihostid, foripvid, start_mib, end_mib) "
        "values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        partition)


def get_storage_backend(cur):
    cur.execute("select storage_backend.id, storage_backend.backend, "
                "storage_backend.state, "
                "storage_backend.forisystemid, storage_backend.services, "
                "storage_backend.capabilities from storage_backend")
    storage_backend = cur.fetchone()
    if not storage_backend:
        LOG.exception("No storage backend present, exiting.")
        raise

    backend = storage_backend['backend']
    LOG.info("storage_backend: %s" % str(storage_backend))

    return backend


def cgts_vg_extend(cur, disk, partition4, pv_cgts_vg, partition_number,
                   part_size_mib):
    part_device_node = '{}{}'.format(disk.get('device_node'),
                                     partition_number)
    part_device_path = '{}-part{}'.format(disk.get('device_path'),
                                          partition_number)

    LOG.info("Extra cgts-vg partition size: %s device node: %s "
             "device path: %s" %
             (part_size_mib, part_device_node, part_device_path))

    part_uuid = uuidutils.generate_uuid()

    new_partition = Partition_Tuple(
        uuid=part_uuid, idisk_id=disk.get('id'),
        idisk_uuid=disk.get('uuid'), size_mib=part_size_mib,
        device_node=part_device_node, device_path=part_device_path,
        status=constants.PARTITION_CREATE_ON_UNLOCK_STATUS,
        type_guid=constants.USER_PARTITION_PHYSICAL_VOLUME,
        forihostid=disk['forihostid'], foripvid=None,
        start_mib=None, end_mib=None)

    create_partition(cur, new_partition)

    pv_uuid = uuidutils.generate_uuid()
    cur.execute(
        "insert into i_pv(uuid, pv_state, pv_type, disk_or_part_uuid, "
        "disk_or_part_device_node, disk_or_part_device_path, lvm_pv_name, "
        "lvm_vg_name, forihostid, forilvgid) "
        "values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
        (pv_uuid, constants.PV_ADD, constants.PV_TYPE_PARTITION, part_uuid,
         part_device_node, part_device_path, part_device_node,
         constants.LVG_CGTS_VG, disk.get('forihostid'),
         pv_cgts_vg.get('forilvgid')))

    # Get the PV.
    cur.execute("select i_pv.id from i_pv where uuid=%s",
                (pv_uuid,))
    pv = cur.fetchone()

    # Update partition.
    cur.execute(
        "update partition set foripvid=%s where uuid=%s",
        (pv.get('id'), part_uuid))


def update_ctrl0_cinder_partition_pv(cur):
    # Get controller-0 id.
    hostname = constants.CONTROLLER_0_HOSTNAME
    cur.execute("select i_host.id, i_host.rootfs_device from i_host "
                "where hostname=%s;", (hostname,))
    row = cur.fetchone()
    if row is None:
        LOG.exception("Failed to fetch %s host_id" % hostname)
        raise
    ctrl0_id = row['id']

    # Controller-0 has only one partition added, the cinder partition.
    cur.execute("select partition.id, partition.uuid, "
                "partition.status, partition.device_node, "
                "partition.device_path, partition.size_mib,"
                "partition.idisk_uuid, partition.foripvid "
                "from partition where forihostid = %s",
                (ctrl0_id,))
    ctrl0_cinder_partition = cur.fetchone()
    if not ctrl0_cinder_partition:
        LOG.exception("Failed to get ctrl0 cinder volumes partition")
        raise

    # Obtain the cinder PV for controller-0.
    cur.execute("select i_pv.id, i_pv.disk_or_part_uuid, "
                "i_pv.disk_or_part_device_node, "
                "i_pv.disk_or_part_device_path, i_pv.lvm_pv_size,"
                "i_pv.lvm_pv_name, i_pv.lvm_vg_name, i_pv.forilvgid,"
                "i_pv.pv_type from i_pv where forihostid=%s and "
                "lvm_vg_name=%s",
                (ctrl0_id, constants.LVG_CINDER_VOLUMES))
    ctrl0_cinder_pv = cur.fetchone()
    if not ctrl0_cinder_pv:
        LOG.exception("Failed to get ctrl0 cinder physical volume")
        raise

    # Update the cinder PV with the partition info.
    update_db_pv(cur, ctrl0_cinder_partition['device_path'],
                 ctrl0_cinder_partition['device_node'],
                 ctrl0_cinder_partition['uuid'],
                 ctrl0_cinder_partition['device_node'],
                 ctrl0_cinder_pv['id'])

    # Mark the cinder partition in use.
    cur.execute("update partition set foripvid=%s, status=%s "
                "where id=%s",
                (ctrl0_cinder_pv['id'], constants.PARTITION_IN_USE_STATUS,
                 ctrl0_cinder_partition['id']))


def update_partition_pv(cur, pvs, partitions, disks):
    backend = get_storage_backend(cur)
    if system_mode != constants.SYSTEM_MODE_SIMPLEX and backend != "ceph":
        update_ctrl0_cinder_partition_pv(cur)

    for pv in pvs:
        if (pv['pv_type'] == constants.PV_TYPE_PARTITION and
                '-part' not in pv['disk_or_part_device_path']):
            if "drbd" in pv['lvm_pv_name']:
                partition_number = '1'
            else:
                partition_number = (
                    re.match('.*?([0-9]+)$', pv['lvm_pv_name']).group(1))
            # Update disk foripvid to null.
            disk = next((
                d for d in disks
                if d['device_path'] == pv['disk_or_part_device_path']), None)
            if disk:
                LOG.info("Set foripvid to null for disk %s" % disk['id'])
                cur.execute(
                    "update i_idisk set foripvid=null where id=%s",
                    (disk['id'],))

            # Update partition device path and device path for the current PV.
            part_device_path = "{}{}{}".format(
                pv['disk_or_part_device_path'],
                '-part',
                partition_number)

            if constants.DEVICE_NAME_NVME in pv['disk_or_part_device_node']:
                part_device_node = "{}p{}".format(
                    pv['disk_or_part_device_node'],
                    partition_number)
            else:
                part_device_node = "{}{}".format(
                    pv['disk_or_part_device_node'],
                    partition_number)

            LOG.info("Old PV device path: %s New PV device path: %s" %
                     (pv['disk_or_part_device_path'], part_device_path))
            LOG.info("Old PV device node: %s New PV device node: %s" %
                     (pv['disk_or_part_device_node'], part_device_node))

            lvm_pv_name = part_device_node
            # Do not use constant here yet since this may change due to
            # cinder removal from cfg ctrl US.
            if "drbd" in pv['lvm_pv_name']:
                lvm_pv_name = pv['lvm_pv_name']

            part = next((
                p for p in partitions
                if p['device_path'] == part_device_path), None)

            if not part:
                LOG.info("No %s partition, returning" % part_device_path)
                continue

            # Update the PV DB entry.
            update_db_pv(cur, part_device_path, part_device_node,
                         part['uuid'], lvm_pv_name, pv['id'])

            # Update the PV DB entry.
            cur.execute(
                "update partition set foripvid=%s, status=%s "
                "where id=%s",
                (pv['id'], constants.PARTITION_IN_USE_STATUS,
                 part['id']))


def create_ctrl0_cinder_partition(cur, stors, part_size):
    hostname = constants.CONTROLLER_0_HOSTNAME
    cur.execute("select i_host.id, i_host.rootfs_device from i_host "
                "where hostname=%s;", (hostname,))
    row = cur.fetchone()
    if row is None:
        LOG.exception("Failed to fetch %s host_id" % hostname)
        raise

    controller_id = row['id']

    # Get the disks for controller-0.
    cur.execute("select i_idisk.forihostid, i_idisk.uuid, "
                "i_idisk.device_node, i_idisk.device_path, "
                "i_idisk.id, i_idisk.size_mib from i_idisk where "
                "forihostid = %s", (controller_id,))

    disks_ctrl0 = cur.fetchall()

    # Obtain the cinder disk for controller-0.
    cinder_disk_ctrl0 = next((
        d for d in disks_ctrl0
        if d['uuid'] in [s['idisk_uuid'] for s in stors]), None)
    LOG.info("cinder_disk_ctrl0: %s" % str(cinder_disk_ctrl0))
    if not cinder_disk_ctrl0:
        LOG.exception("Failed to get cinder disk for host %s" %
                      controller_id)
        raise

    # Fill in partition info.
    new_part_size = part_size
    new_part_device_node = "%s1" % cinder_disk_ctrl0['device_node']
    new_part_device_path = ('%s-part1' %
                            cinder_disk_ctrl0['device_path'])
    LOG.info("New partition: %s - %s" %
             (new_part_device_node, new_part_device_path))
    new_part_uuid = uuidutils.generate_uuid()

    new_partition = Partition_Tuple(
        uuid=new_part_uuid,
        idisk_id=cinder_disk_ctrl0.get('id'),
        idisk_uuid=cinder_disk_ctrl0.get('uuid'),
        size_mib=new_part_size,
        device_node=new_part_device_node,
        device_path=new_part_device_path,
        status=constants.PARTITION_IN_USE_STATUS,
        type_guid=constants.USER_PARTITION_PHYSICAL_VOLUME,
        forihostid=controller_id,
        foripvid=None,
        start_mib=None,
        end_mib=None)

    create_partition(cur, new_partition)


def create_db_partition_entries(cur, disks):
    # Get the stors with the cinder function.
    cur.execute("select i_istor.id, i_istor.idisk_uuid, "
                "i_istor.function, i_istor.forihostid "
                "from i_istor where function = %s",
                (constants.STOR_FUNCTION_CINDER,))
    stors = cur.fetchall()

    cinder_partition = False
    for disk in disks:
        partitions = get_partitions(disk['device_path'])

        LOG.info("partitions: %s" % str(partitions))
        # Create the DB entries for all disk partitions on controller-1.
        # For controller-0 we will only create the cinder partition, as the
        # rest will be reported by sysinv-agent once the host is upgraded.
        if not partitions:
            continue

        for part in partitions:
            part_disk = next((
                d for d in disks if d['device_path'] in part['device_path']
            ))

            crt_stor = next((s for s in stors
                             if s['idisk_uuid'] == part_disk['uuid']), None)

            part_type_guid = constants.LINUX_LVM_PARTITION
            if crt_stor:
                part_type_guid = constants.USER_PARTITION_PHYSICAL_VOLUME

            part_size = part['size_mib']
            part_device_node = part['device_node']
            part_device_path = part['device_path']

            LOG.info("New partition size: %s part device node: %s "
                     "part device path: %s" %
                     (part_size, part_device_node, part_device_path))

            part_uuid = uuidutils.generate_uuid()
            new_partition = Partition_Tuple(
                uuid=part_uuid, idisk_id=part_disk.get('id'),
                idisk_uuid=part_disk.get('uuid'), size_mib=part_size,
                device_node=part_device_node, device_path=part_device_path,
                status=constants.PARTITION_IN_USE_STATUS,
                type_guid=part_type_guid,
                forihostid=disk['forihostid'], foripvid=None,
                start_mib=part['start_mib'], end_mib=part['end_mib'])

            create_partition(cur, new_partition)

            # If this is the cinder disk, also create partition for the other
            # controller.
            if not crt_stor:
                LOG.info("Disk %s is not a cinder disk for host %s" %
                         (part_disk['device_path'], part_disk['forihostid']))
                continue

            if system_mode == constants.SYSTEM_MODE_SIMPLEX:
                cinder_partition = True
                continue

            # Also create the cinder partition for controller-0.
            create_ctrl0_cinder_partition(cur, stors, part_size)
            cinder_partition = True

    # If somehow the cinder disk was also wiped and the partition was lost,
    # we need to retrieve it in another way.
    if not cinder_partition:
        LOG.info("Cinder partition was wiped so we need to create it")
        for disk in disks:
            d_json_dict = json.loads(disk['capabilities'])
            if (constants.IDISK_DEV_FUNCTION in d_json_dict and
                    d_json_dict['device_function'] == 'cinder_device'):
                if 'cinder_gib' in d_json_dict:
                    LOG.info("cinder_gib: %s" % d_json_dict['cinder_gib'])

                    # Partition size calculated from the size of cinder_gib.
                    part_size = int(d_json_dict['cinder_gib'])

                    # Actual disk size in MiB.
                    device = parted.getDevice(disk['device_path'])
                    disk_size = device.length * device.sectorSize / (1024 ** 2)

                    part_size = min(part_size, disk_size - 2)

                    if constants.DEVICE_NAME_NVME in disk['device_node']:
                        part_device_node = "%sp1" % disk['device_node']
                    else:
                        part_device_node = "%s1" % disk['device_node']
                    part_device_path = "%s-part1" % disk['device_path']
                    part_start_mib = 2
                    part_end_mib = 2 + part_size

                    LOG.info("New partition size: %s part device node: %s "
                             "part device path: %s part_end_mib: %s" %
                             (part_size, part_device_node, part_device_path,
                              part_end_mib))

                    part_uuid = uuidutils.generate_uuid()
                    new_partition = Partition_Tuple(
                        uuid=part_uuid,
                        idisk_id=disk.get('id'),
                        idisk_uuid=disk.get('uuid'), size_mib=part_size,
                        device_node=part_device_node,
                        device_path=part_device_path,
                        status=constants.PARTITION_IN_USE_STATUS,
                        type_guid=constants.USER_PARTITION_PHYSICAL_VOLUME,
                        forihostid=disk['forihostid'], foripvid=None,
                        start_mib=part_start_mib, end_mib=part_end_mib)
                    create_partition(cur, new_partition)
                    if system_mode != constants.SYSTEM_MODE_SIMPLEX:
                        create_ctrl0_cinder_partition(cur, stors, part_size)
                    break


def create_user_partitions():
    conn = psycopg2.connect("dbname=sysinv user=postgres")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            hostname = constants.CONTROLLER_1_HOSTNAME
            if system_mode == constants.SYSTEM_MODE_SIMPLEX:
                hostname = constants.CONTROLLER_0_HOSTNAME

            cur.execute("select i_host.id, i_host.rootfs_device from i_host "
                        "where hostname=%s;", (hostname,))
            row = cur.fetchone()
            if row is None:
                LOG.exception("Failed to fetch %s host_id" % hostname)
                raise

            controller_id = row['id']
            controller_rootfs = row['rootfs_device']

            # Get the disks for the controller.
            cur.execute("select i_idisk.forihostid, i_idisk.uuid, "
                        "i_idisk.device_node, i_idisk.device_path, "
                        "i_idisk.capabilities, "
                        "i_idisk.id, i_idisk.size_mib from i_idisk where "
                        "forihostid = %s", (controller_id,))

            disks = cur.fetchall()

            # Get the PVs for the controller.
            cur.execute(
                "select i_pv.id, i_pv.disk_or_part_uuid, "
                "i_pv.disk_or_part_device_node, "
                "i_pv.disk_or_part_device_path, i_pv.lvm_pv_size,"
                "i_pv.lvm_pv_name, i_pv.lvm_vg_name, i_pv.forilvgid,"
                "i_pv.pv_type from i_pv where forihostid = %s",
                (controller_id,))
            pvs = cur.fetchall()

            # Obtain the rootfs disk. This is for handling the case when
            # rootfs is not on /dev/sda.
            controller_rootfs_disk = next((
                d for d in disks
                if (d.get('device_path') == controller_rootfs or
                    controller_rootfs in d.get('device_node'))), None)
            LOG.info("controller_rootfs_disk: %s" % controller_rootfs_disk)

            create_db_partition_entries(cur, disks)

            # Get the PVs for the controller.
            cur.execute(
                "select partition.id, partition.uuid, "
                "partition.status, partition.device_node, "
                "partition.device_path, partition.size_mib,"
                "partition.idisk_uuid, partition.foripvid "
                "from partition where forihostid = %s",
                (controller_id,))
            partitions = cur.fetchall()

            update_partition_pv(cur, pvs, partitions, disks)

            # If this is not an AIO setup, we must return, as we already have
            # all the needed information.
            if utils.get_system_type() != constants.TIS_AIO_BUILD:
                LOG.info("This is not an AIO setup, nothing to do here.")
                return

            # Get the PVs for cgts-vg from the root fs disk, present in the DB.
            # This list can have max 2 elements.
            cgts_vg_pvs = [pv for pv in pvs
                           if pv['lvm_vg_name'] == constants.LVG_CGTS_VG and
                           (controller_rootfs_disk['device_path'] in
                            pv['disk_or_part_device_path'])]

            LOG.info("cgts-vg pvs: %s" % str(cgts_vg_pvs))

            # Build the PV name of the initial PV for cgts-vg.
            R5_cgts_pv_1_name = build_partition_device_node(
                controller_rootfs_disk['device_node'],
                uefi_cgts_pv_1_partition_number)

            # Get the initial PV of cgts-vg. If it's not present with the
            # provided name, then we're probably on a BIOS setup.
            R5_cgts_pv_1 = next((
                pv for pv in cgts_vg_pvs
                if pv['lvm_pv_name'] == R5_cgts_pv_1_name), None)

            # Get the device used by R5_cgts_pv_1.
            R5_cgts_pv_1_part = next((
                p for p in partitions
                if p['device_node'] == R5_cgts_pv_1_name),
                None)

            # On an R4 AIO installed with BIOS, we won't have 6 partitions
            # right after install, but only 4.
            # R4 PV /dev/sda5 thus should become PV /dev/sda4 in R5.
            if not R5_cgts_pv_1:
                LOG.info("Probably bios here, we need to update the DB for "
                         "cgts-vg partitions and pv")
                R4_cgts_pv_1_name = build_partition_device_node(
                    controller_rootfs_disk['device_node'],
                    bios_cgts_pv_1_partition_number)
                R5_cgts_pv_1 = next((
                    pv for pv in pvs
                    if pv['lvm_pv_name'] == R4_cgts_pv_1_name),
                    None)

                cur.execute(
                    "update partition set foripvid=%s, status=%s "
                    "where device_path=%s and forihostid=%s",
                    (R5_cgts_pv_1.get('id'), constants.PARTITION_IN_USE_STATUS,
                     R5_cgts_pv_1_part['device_path'], controller_id))

                update_db_pv(cur, R5_cgts_pv_1_part['device_path'],
                             R5_cgts_pv_1_part['device_node'],
                             R5_cgts_pv_1_part['uuid'],
                             R5_cgts_pv_1_part['device_node'],
                             R5_cgts_pv_1.get('id'))

            cgts_vg_pvs.remove(R5_cgts_pv_1)

            # There is a high chance that the current R5 /dev/sda4 partition is
            # too small for the R4 cgts-vg. In this case, we need to create
            # an extra partition & PV for cgts-vg.
            part_number = 5

            extra_cgts_part_size = math.ceil(
                float(R5_cgts_pv_1.get('lvm_pv_size')) / (1024 ** 2) -
                R5_cgts_pv_1_part.get('size_mib'))
            if extra_cgts_part_size > 0:
                LOG.info("/dev/sda4 is not enough for R4 cgts-vg")
                cgts_vg_extend(cur, controller_rootfs_disk, R5_cgts_pv_1_part,
                               R5_cgts_pv_1,
                               part_number, extra_cgts_part_size)
                part_number = part_number + 1
            else:
                extra_cgts_part_size = 0

            # If the remaining space was used by either nova-local or cgts-vg,
            # then the R4 partition must be specifically created.
            if cgts_vg_pvs:
                last_rootfs_pv = cgts_vg_pvs[0]
                LOG.info("Extra rootfs disk space used by cgts-vg")
            else:
                # Get the nova-local PV from the rootfs disk.
                last_rootfs_pv = next((
                    pv for pv in pvs
                    if (pv['lvm_vg_name'] == constants.LVG_NOVA_LOCAL and
                        controller_rootfs_disk['device_node'] in
                        pv['lvm_pv_name'])),
                    None)

                if last_rootfs_pv:
                    LOG.info("Extra rootfs disk space used by nova-local")

            # If the remaining space is not used, return.
            if not last_rootfs_pv:
                LOG.info("Extra rootfs disk space not used, return")
                return

            # Create the partition DB entry and update the associated
            # physical volume.
            disk_available_mib = get_disk_available_mib(
                controller_rootfs_disk['device_node']) - extra_cgts_part_size
            LOG.info("Available mib: %s" % disk_available_mib)

            part_size = disk_available_mib
            part_device_node = '{}{}'.format(
                controller_rootfs_disk.get('device_node'),
                part_number)
            part_device_path = '{}-part{}'.format(
                controller_rootfs_disk.get('device_path'),
                part_number)

            LOG.info("Partition size: %s part device node: %s "
                     "part device path: %s" %
                     (part_size, part_device_node, part_device_path))

            part_uuid = uuidutils.generate_uuid()

            new_partition = Partition_Tuple(
                uuid=part_uuid,
                idisk_id=controller_rootfs_disk.get('id'),
                idisk_uuid=controller_rootfs_disk.get('uuid'),
                size_mib=part_size,
                device_node=part_device_node,
                device_path=part_device_path,
                status=constants.PARTITION_CREATE_ON_UNLOCK_STATUS,
                type_guid=constants.USER_PARTITION_PHYSICAL_VOLUME,
                forihostid=controller_id,
                foripvid=last_rootfs_pv.get('id'),
                start_mib=None,
                end_mib=None)

            create_partition(cur, new_partition)

            update_db_pv(cur, part_device_path, part_device_node,
                         part_uuid, part_device_node, last_rootfs_pv.get('id'))


if __name__ == "__main__":
    sys.exit(main())
