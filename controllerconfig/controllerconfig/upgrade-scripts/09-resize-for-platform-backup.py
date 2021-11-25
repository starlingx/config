#!/usr/bin/env python
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import math
import psycopg2
import sys
import subprocess

from controllerconfig.common import log
from operator import itemgetter
from psycopg2.extras import RealDictCursor

LOG = log.get_logger(__name__)

BACKUP_GUID = 'ba5eba11-0000-1111-2222-000000000002'
SYSINV_GUID = 'ba5eba11-0000-1111-2222-000000000001'


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
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log.configure()

    LOG.debug("%s invoked with from_release = %s to_release = %s action = %s"
              % (sys.argv[0], from_release, to_release, action))
    if from_release == "21.05" and action == "migrate":
        try:
            adjust_backup_partition()
        except Exception as ex:
            LOG.exception(ex)
            return 1


def adjust_backup_partition():
    installed_backup_size = get_backup_size()
    conn = psycopg2.connect("dbname=sysinv user=postgres")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("select i_host.id, i_host.rootfs_device from i_host "
                        "where personality='controller'")
            controllers = cur.fetchall()
            if not controllers:
                LOG.exception("Failed to fetch controller host information")
                raise

            for controller in controllers:
                controller_rootfs_disk = get_host_rootfs(cur, controller)
                db_partitions = get_db_partitions(
                    cur, controller, controller_rootfs_disk)
                LOG.info("Database partition data: %s" % db_partitions)

                backup_partition = next(p for p in db_partitions if
                                        p['type_guid'].lower() == BACKUP_GUID)
                original_backup_size = backup_partition['size_mib']
                if installed_backup_size == original_backup_size:
                    LOG.info("Backup partition size unchanged, nothing to do. "
                             "Installed: %s DB: %s" %
                             (installed_backup_size, original_backup_size))
                    continue

                backup_change = installed_backup_size - original_backup_size
                adjusted_partitions = move_partitions(
                    db_partitions, backup_partition, backup_change)

                # Ensure the last partition will fit on the disk
                disk_size = controller_rootfs_disk['size_mib'] - 1
                last_partition = adjusted_partitions[-1]
                required_space = max(0, last_partition['end_mib'] - disk_size)

                if required_space == 0:
                    update_partitions(cur, adjusted_partitions)
                    LOG.info("Adjusted partitions fit rootfs, can continue. "
                             "Partitions: %s " % adjusted_partitions)
                    continue

                added_partitions = [p for p in db_partitions if
                                    p['type_guid'].lower() == SYSINV_GUID]
                unassigned_partitions = [p for p in added_partitions if
                                         p['foripvid'] is None]

                if not added_partitions:
                    # This is not an AIO system, we'll resize the last partiton
                    added_partitions.append(last_partition)

                partitions = unassigned_partitions if unassigned_partitions else added_partitions  # noqa
                partition = max(partitions, key=itemgetter('size_mib'))

                if partition['size_mib'] < required_space:
                    LOG.exception(
                        "Insufficient space to resize partition %s - %s" %
                        (partition, required_space))
                    raise

                reduced_partitions = move_partitions(
                    adjusted_partitions, partition, required_space * -1)
                final_partitions = adjusted_partitions[:adjusted_partitions.index(partition)]  # noqa
                final_partitions.extend(reduced_partitions)
                update_partitions(cur, final_partitions)

                host_pvs = get_pvs(cur, controller)
                partition_vg_name = get_vg_name(partition, host_pvs)

                if partition_vg_name == 'cgts-vg':
                    resize_cgts_vg(cur, controller, required_space)


def get_host_rootfs(cursor, host):
    disk_query = "select * from i_idisk where forihostid=%s and capabilities like %s"  # noqa: E501
    cursor.execute(disk_query, (host['id'], '%rootfs%',))
    return cursor.fetchone()


def get_db_partitions(cursor, host, rootfs):
    partition_query = "select * from partition where forihostid = %s and idisk_uuid = %s"  # noqa: E501
    cursor.execute(partition_query, (host['id'], rootfs['uuid'],))
    return cursor.fetchall()


def get_backup_size():
    lsblk_command = 'lsblk -pno PKNAME $(findmnt -n / -o SOURCE)'
    lsblk = subprocess.Popen(lsblk_command, stdout=subprocess.PIPE, shell=True)
    root_disk_path = lsblk.stdout.read()
    part_info = get_sgdisk_info(root_disk_path)

    backup_size = next(part['size_mib'] for part in part_info if
                       part['type_guid'].lower() == BACKUP_GUID)

    return int(backup_size)


def get_sgdisk_info(device_path):
    """Obtain partition info: type GUID, type name, UUID, start, end, size.
    :param:   device_path: the disk's device path
    :returns: list of partition info
    """
    sgdisk_part_info = []
    fields = ['part_number', 'device_node', 'type_guid', 'type_name', 'uuid',
              'start_mib', 'end_mib', 'size_mib']
    sgdisk_command = '{} {}'.format('/usr/bin/partition_info.sh',
                                    device_path)

    try:
        sgdisk_process = subprocess.Popen(sgdisk_command,
                                          stdout=subprocess.PIPE,
                                          shell=True)
    except Exception as e:
        LOG.exception("Could not retrieve partition information: %s" % e)
        raise

    sgdisk_output = sgdisk_process.stdout.read()

    rows = [row for row in sgdisk_output.split(';') if row.strip()]

    for row in rows:
        values = row.split()
        partition = dict(zip(fields, values))

        if 'part_number' in partition.keys():
            partition['part_number'] = int(partition['part_number'])

        sgdisk_part_info.append(partition)

    return sgdisk_part_info


def move_partitions(db_values, start, size):
    """
    Updates the list of partitions based on the new size of a given partition
    :param:   db_values: A list of partitions to adjust
    :param:   start: The partition being adjusted
    :param:   size: The change in size of the partition
    :returns: A sorted list of updated partitions
    """
    partitions = sorted(db_values, key=itemgetter('start_mib'))
    partitions = partitions[partitions.index(start):]
    # Update the specified partition size and end_mib
    partitions[0]['size_mib'] += size
    partitions[0]['end_mib'] += size
    # Shift the rest of the partitions
    for partition in partitions[1:]:
        partition['start_mib'] += size
        partition['end_mib'] += size

    return partitions


def update_partitions(cursor, updated_partitions):
    LOG.info("Updating partitions to: %s" % updated_partitions)
    update_query = "update partition set start_mib=%s, end_mib=%s, size_mib=%s where id=%s"  # noqa: E501
    for partition in updated_partitions:
        cursor.execute(update_query,
                       (partition['start_mib'], partition['end_mib'],
                        partition['size_mib'], partition['id']))


def get_pvs(cursor, host):
    query = "select * from i_pv where forihostid=%s"
    cursor.execute(query, (host['id'],))
    return cursor.fetchall()


def get_vg_name(partition, pvs):
    pv_id = partition['foripvid']
    if not pv_id:
        return None
    return next(pv['lvm_vg_name'] for pv in pvs if pv['id'] == pv_id)


def resize_cgts_vg(cursor, host, required_space):
    cgts_vg = get_cgts_vg(cursor, host)
    cgts_vg_free_space = int(cgts_vg['lvm_vg_size'] / cgts_vg['lvm_vg_total_pe']) * cgts_vg['lvm_vg_free_pe']  # noqa: E501

    # There may be available space in the cgts_vg
    if cgts_vg_free_space >= required_space:
        LOG.info("cgts_vg has sufficient space, can continue. "
                 "cgts_vg: %s " % cgts_vg)
        return

    # Otherwise we'll reduce the backup fs by up to 15GB and remove
    # the rest from the docker fs
    required_space -= cgts_vg_free_space
    required_gb = int(math.ceil(required_space / 1024.0))
    backup_fs_reduction = min(15, required_gb)
    update_host_fs(cursor, host, 'backup', backup_fs_reduction)

    required_gb -= backup_fs_reduction
    if required_gb > 0:
        update_host_fs(cursor, host, 'docker', required_gb)


def get_cgts_vg(cursor, host):
    query = "select * from i_lvg where lvm_vg_name='cgts-vg' and forihostid=%s"
    cursor.execute(query, (host['id'],))
    return cursor.fetchone()


def update_host_fs(cursor, host, fs_name, reduction):
    size_query = "select size from host_fs where name=%s and forihostid=%s"
    cursor.execute(size_query, (fs_name, host['id']))
    original_size = cursor.fetchone()['size']

    new_size = original_size - reduction
    LOG.info("Updating %s host fs to %s" % (fs_name, new_size))
    update_query = "update host_fs set size=%s where name=%s and forihostid=%s"
    cursor.execute(update_query, (new_size, fs_name, host['id']))


if __name__ == "__main__":
    sys.exit(main())
