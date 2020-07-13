#!/usr/bin/env python
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will update the partition schema for partitions on the root disk
# of AIO controllers. This is required as the default LVM partiton grew in the
# N+1 release.

import psycopg2
import sys
import six
import subprocess

from sysinv.common import constants
from psycopg2.extras import RealDictCursor
from controllerconfig.common import log

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

    LOG.debug("%s invoked with from_release = %s to_release = %s action = %s"
              % (sys.argv[0], from_release, to_release, action))
    if to_release == "20.06" and action == "migrate":
        try:
            adjust_user_partitions()
        except Exception as ex:
            LOG.exception(ex)
            return 1


def _command(arguments1, arguments2=None):
    """Execute a command and capture stdout, stderr & return code."""
    LOG.debug("Executing command: '%s'" % " ".join(arguments1))
    process = subprocess.Popen(
        arguments1,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE)

    if arguments2:
        process2 = subprocess.Popen(
            arguments2,
            stdin=process.stdout,
            stdout=subprocess.PIPE,
            shell=False)
        process.stdout.close()
        process = process2

    out, err = process.communicate()

    return out, err, process.returncode


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


def get_partitions(device_path, device_node):
    """Obtain existing partitions from a disk."""
    partitions = []
    sgdisk_part_info = get_sgdisk_info(device_path)

    for partition in sgdisk_part_info:
        partition_number = partition.get('part_number')
        type_name = partition.get('type_name')
        part_size_mib = partition.get('size_mib')
        if constants.DEVICE_NAME_NVME in device_node:
            part_device_node = '{}p{}'.format(device_node, partition_number)
        else:
            part_device_node = '{}{}'.format(device_node, partition_number)
        part_device_path = '{}-part{}'.format(device_path,
                                              partition_number)
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


def is_aio_system_type():
    conn = psycopg2.connect("dbname='sysinv' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * from i_system")
            system = cur.fetchone()
            return system['system_type'] == 'All-in-one'


def adjust_user_partitions():
    if not is_aio_system_type:
        LOG.info("This is not an AIO system. No partition changes required.")
        return

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
                # Get the root disk for the controller.
                cur.execute(
                    "select * from i_idisk where forihostid=%s and "
                    "capabilities like %s", (controller['id'], '%rootfs%',))
                controller_rootfs_disk = cur.fetchone()
                if not controller_rootfs_disk:
                    LOG.exception("Could not locate controller root disk.")
                    raise
                LOG.debug("controller_rootfs_disk: %s" %
                          controller_rootfs_disk)

                # Get the partitions for the controller root disk.
                cur.execute(
                    "select partition.id, partition.device_node, "
                    "partition.device_path, partition.start_mib, "
                    "partition.end_mib, partition.size_mib "
                    "from partition where forihostid = %s",
                    (controller['id'],))
                db_partitions = cur.fetchall()
                LOG.debug("DB partitions: %s" % db_partitions)

                # Create a map
                partition_map = {p['device_node']: p for p in db_partitions}
                LOG.debug("DB partition map: %s" % partition_map)

                installed_partitions = get_partitions(
                    controller_rootfs_disk['device_path'],
                    controller_rootfs_disk['device_node'])
                LOG.debug("installed partitions: %s" % installed_partitions)

                update_db_partitions = []    # Requires DB updates
                installed_lvm_device = None  # LVM device that needs adjusting
                adjustments = {}             # LVM device partition adjustments

                # Go through the installed partitions and determine any changes
                for i in installed_partitions:
                    # Grab the partition from the db map
                    d = partition_map[i['device_node']]
                    if ((int(i['start_mib']) != int(d['start_mib'])) or
                            (int(i['end_mib']) != int(d['end_mib'])) or
                            (int(i['size_mib']) != int(d['size_mib']))):
                        LOG.info("MISMATCH:installed part: %s %s %s %s" % (
                            i['device_node'], i['start_mib'],
                            i['end_mib'], i['size_mib']))
                        LOG.info("MISMATCH:       db part: %s %s %s %s" % (
                            d['device_node'], d['start_mib'],
                            d['end_mib'], d['size_mib']))
                        if i['type_name'] == 'Linux.LVM':
                            # This is key partition that will be used to adjust
                            # any additional user created partitions, identify
                            # and save the adjustments
                            installed_lvm_device = i['device_node']
                            adjustments['start_mib'] = (int(i['start_mib']) -
                                                        int(d['start_mib']))
                            adjustments['end_mib'] = (int(i['end_mib']) -
                                                      int(d['end_mib']))
                            adjustments['size_mib'] = (int(i['size_mib']) -
                                                       int(d['size_mib']))
                        else:
                            # Adjust the non-LVM partitions to match what is
                            # installed
                            d['start_mib'] = i['start_mib']
                            d['end_mib'] = i['end_mib']
                            d['size_mib'] = i['size_mib']

                            # Save the new partition for updating
                            update_db_partitions.append(d)

                            # Remove the partition from the db map
                            del partition_map[i['device_node']]
                    else:
                        # Partition is the same. No changes needed
                        # Remove the partition from the db map
                        del partition_map[i['device_node']]

                if installed_lvm_device:
                    # Found a difference in the installed partition map for the
                    # primary LVM partition
                    LOG.debug("DB unhandled part map: %s" % partition_map)

                    # Update the primary installed LVM partition based on
                    # calculated adjustments.
                    d = partition_map[installed_lvm_device]
                    d['start_mib'] = (int(d['start_mib']) +
                                      adjustments['start_mib'])
                    d['end_mib'] = (int(d['end_mib']) +
                                    adjustments['end_mib'])
                    d['size_mib'] = (int(d['size_mib']) +
                                     adjustments['size_mib'])
                    update_db_partitions.append(d)
                    del partition_map[installed_lvm_device]

                    # Adjust the start/end of user created partitions. Size
                    # will not be changed.
                    for device, partition in six.iteritems(partition_map):
                        partition['start_mib'] = (int(partition['start_mib']) +
                                                  adjustments['end_mib'])
                        partition['end_mib'] = (int(partition['end_mib']) +
                                                adjustments['end_mib'])
                        update_db_partitions.append(partition)

                if update_db_partitions:
                    # Found partitions that need updating
                    LOG.info("Required partition adjustments: %s" %
                             update_db_partitions)
                    for partition in update_db_partitions:
                        cur.execute(
                            "update partition set start_mib=%s, end_mib=%s, "
                            "size_mib=%s where id=%s", (partition['start_mib'],
                                                        partition['end_mib'],
                                                        partition['size_mib'],
                                                        partition['id']),)

if __name__ == "__main__":
    sys.exit(main())
