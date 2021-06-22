#!/usr/bin/python
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script will remove snmp related data (icommunity and
# itrapdest) in dcorch database according to the host based
# SNMP removal in preparation for upgrade from release 20.06.
#


import psycopg2
import sys
from controllerconfig.common import log
from psycopg2.extras import RealDictCursor

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

    LOG.debug("%s invoked with from_release = %s to_release = %s action = %s"
              % (sys.argv[0], from_release, to_release, action))

    if from_release == "20.06" and action == "migrate":
        try:
            if is_system_controller():
                LOG.info("Performing dcorch snmp data removal...")
                remove_snmp_record()
        except Exception as ex:
            LOG.exception(ex)
            print(ex)
            return 1


def is_system_controller():
    with open('/etc/platform/platform.conf', 'r') as f:
        lines = f.readlines()

    for line in lines:
        if line.strip() == 'distributed_cloud_role=systemcontroller':
            return True

    return False


def remove_snmp_in_orch_request(cur, job_id):
    # Check if the record exists in orch_request
    cur.execute("select * from orch_request where orch_job_id = '%d'" %
                job_id)
    orch_request = cur.fetchall()
    if orch_request:
        cur.execute("delete from orch_request where orch_job_id = '%d'" %
                    job_id)
        LOG.info("icommunity/itrapdest is removed in orch_request.")
    else:
        LOG.info("There is no icommunity/itrapdest in orch_request.")


def remove_snmp_in_orch_job(cur, master_id):
    # Check if the record exists in orch_job
    cur.execute("select * from orch_job where source_resource_id = '%s'" %
                master_id)
    orch_job = cur.fetchall()
    if orch_job:
        for orch_job_record in orch_job:
            remove_id = orch_job_record['id']
            remove_snmp_in_orch_request(cur, remove_id)
            cur.execute("delete from orch_job where id = %d" % (remove_id))
            LOG.info("icommunity is removed in orch_job.")
    else:
        LOG.info("There is no icommunity/itrapdest in orch_job.")


def remove_snmp_in_subcloud_resource(cur, master_id):
    # Check if the record exists in subcloud_resource
    cur.execute("select * from subcloud_resource "
                "where subcloud_resource_id = '%s'" % (master_id))
    resource_subcloud = cur.fetchall()
    if resource_subcloud:
        cur.execute("delete from subcloud_resource "
                    "where subcloud_resource_id = '%s'" % (master_id))
        LOG.info("icommunity is removed in subcloud_resource.")
    else:
        LOG.info("There is no icommunity/itrapdest in subcloud_resource.")


def remove_snmp_record():
    conn = psycopg2.connect("dbname='dcorch' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Check if any icommunity or itrapdest record exists
            cur.execute("select * from resource  where resource_type in "
                        "('icommunity','itrapdest')")
            resource_records = cur.fetchall()
            if not resource_records:
                LOG.info("Nothing to do - "
                         "there is no icommunity/itrapdest in resource.")
                return
            for data_resource in resource_records:
                master_id = data_resource['master_id']
                remove_snmp_in_subcloud_resource(cur, master_id)
                remove_snmp_in_orch_job(cur, master_id)
                cur.execute("delete from resource "
                            "where master_id = '%s'" % (master_id))
                LOG.info("icommunity/itrapdest is removed from resource.")
    LOG.info("snmp community and trapdest data removal completed.")


if __name__ == "__main__":
    sys.exit(main())
