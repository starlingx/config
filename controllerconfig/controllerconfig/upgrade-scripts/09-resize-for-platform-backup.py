#!/usr/bin/env python
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

import math
import operator
import psycopg2
import sys
import subprocess

from sysinv.common import constants
from psycopg2.extras import RealDictCursor
from controllerconfig.common import log

LOG = log.get_logger(__name__)

BACKUP_GUID = 'ba5eba11-0000-1111-2222-000000000002'


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

                installed_partitions = get_partitions(
                    controller_rootfs_disk['device_path'],
                    controller_rootfs_disk['device_node'])
                installed_partition_map = {
                    p['device_node']: p for p in installed_partitions}
                LOG.info("Installed partitions: %s" % installed_partitions)

                backup_partition = next(p for p in db_partitions if
                                        p['type_guid'].lower() == BACKUP_GUID)
                backup_device_node = backup_partition['device_node']
                original_backup_size = backup_partition['size_mib']
                installed_backup_size = int(installed_partition_map[backup_device_node]['size_mib'])  # noqa: E501
                if installed_backup_size == original_backup_size:
                    LOG.info("Backup partition size unchanged, nothing to do. "
                             "Installed: %s DB: %s" %
                             (installed_backup_size, original_backup_size))
                    continue

                backup_change = installed_backup_size - original_backup_size
                adjusted_partitions = move_partitions(
                    db_partitions, backup_partition, backup_change)

                # Ensure the last partition will fit on the disk
                disk_size = get_disk_size(controller_rootfs_disk['device_node']) - 1  # noqa: E501
                last_partition = adjusted_partitions[-1]
                required_space = max(0, last_partition['end_mib'] - disk_size)
                if required_space > 0:
                    LOG.info("Reducing partition: %s by %s" %
                             (last_partition['device_node'], required_space))
                    last_partition['end_mib'] -= required_space
                    last_partition['size_mib'] -= required_space

                if last_partition['size_mib'] < 0:
                    raise Exception("Invalid partition configuration. Partitions: %s" % adjusted_partitions)  # noqa: E501

                update_partitions(cur, adjusted_partitions)

                if required_space == 0:
                    LOG.info("Adjusted partitions fit rootfs, can continue. "
                             "Partitions: %s " % adjusted_partitions)
                    continue

                cgts_vg = get_cgts_vg(cur, controller)
                cgts_vg_free_space = int(cgts_vg['lvm_vg_size'] / cgts_vg['lvm_vg_total_pe']) * cgts_vg['lvm_vg_free_pe']  # noqa: E501

                # There may be available space in the cgts_vg
                if cgts_vg_free_space >= required_space:
                    LOG.info("cgts_vg has sufficient space, can continue. "
                             "cgts_vg: %s " % cgts_vg)
                    continue

                # Otherwise we'll reduce the backup fs by up to 15GB and remove
                # the rest from the docker fs
                required_space -= cgts_vg_free_space
                required_gb = int(math.ceil(required_space / 1024.0))
                backup_fs_reduction = min(15, required_gb)
                update_host_fs(cur, controller, 'backup', backup_fs_reduction)

                required_gb -= backup_fs_reduction
                if required_gb > 0:
                    update_host_fs(cur, controller, 'docker', required_gb)


def get_host_rootfs(cursor, host):
    disk_query = "select * from i_idisk where forihostid=%s and capabilities like %s"  # noqa: E501
    cursor.execute(disk_query, (host['id'], '%rootfs%',))
    return cursor.fetchone()


def get_db_partitions(cursor, host, rootfs):
    partition_query = "select * from partition where forihostid = %s and idisk_uuid = %s"  # noqa: E501
    cursor.execute(partition_query, (host['id'], rootfs['uuid'],))
    return cursor.fetchall()


def get_partitions(device_path, device_node):
    """Obtain existing partitions from a disk."""
    partitions = []
    sgdisk_part_info = get_sgdisk_info(device_path)

    for partition in sgdisk_part_info:
        partition_number = partition.get('part_number')
        type_name = partition.get('type_name')
        part_size_mib = partition.get('size_mib')
        part_device_node = build_partition_device_node(
            device_node, partition_number)
        part_device_path = build_partition_device_path(
            device_path, partition_number)
        start_mib = partition.get('start_mib')
        end_mib = partition.get('end_mib')

        part_attrs = {
            'partition_number': partition_number,
            'device_path': part_device_path,
            'device_node': part_device_node,
            'type_name': type_name,
            'start_mib': start_mib,
            'end_mib': end_mib,
            'size_mib': part_size_mib,
        }
        partitions.append(part_attrs)

    return partitions


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


def build_partition_device_node(disk_device_node, partition_number):
    if constants.DEVICE_NAME_NVME in disk_device_node:
        partition_device_node = '{}p{}'.format(
            disk_device_node, partition_number)
    else:
        partition_device_node = '{}{}'.format(
            disk_device_node, partition_number)

    LOG.debug("partition_device_node: %s" % partition_device_node)

    return partition_device_node


def build_partition_device_path(disk_device_path, partition_number):
    partition_device_path = '{}-part{}'.format(
        disk_device_path, partition_number)

    LOG.debug("partition_device_path: %s" % partition_device_path)

    return partition_device_path


def move_partitions(db_values, start, size):
    """
    Updates the list of partitions based on the new size of the platform backup
    partition
    :param:   db_values: A list of partitions to adjust
    :param:   start: The platform-backup partition
    :param:   size: The new size of the platform-backup partition
    :returns: A sorted list of updated partitions
    """
    partitions = sorted(db_values, key=operator.itemgetter('start_mib'))
    partitions = partitions[partitions.index(start):]
    # Update the platform backup size and end_mib
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


def get_disk_size(rootfs):
    disk_size_cmd = '{} {}'.format('blockdev --getsize64', rootfs)
    disk_size_process = subprocess.Popen(
        disk_size_cmd, stdout=subprocess.PIPE, shell=True)
    disk_size = int(disk_size_process.stdout.read().rstrip())

    # Return in mib
    return int(disk_size / (1024 * 1024))


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
