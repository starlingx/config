#!/usr/bin/env python
# Copyright (c) 2018 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
# This migration script copies the inode capabilities reserved
# field, which contain tpm_data to the tpm_data field in the
# tpmdevices DB table

import sys

import psycopg2
from controllerconfig.common import log
from psycopg2.extras import RealDictCursor

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

    if from_release == "17.06" and action == "migrate":
        try:
            LOG.info("performing sysinv TPM Device migration from release "
                     "%s to %s with action: %s" %
                     (from_release, to_release, action))
            copy_sysinv_tpm_data()
        except Exception as ex:
            LOG.exception(ex)
            print ex
            return 1


# We will update for all controller hosts.
# We stow the TPM data in R4, in the inode.capabilities
# field since that is the only JSONEncodedDict field thats
# organized by hostid and vacant in R4.
def copy_sysinv_tpm_data():
    conn = psycopg2.connect("dbname='sysinv' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id FROM i_host WHERE "
                        "personality='controller';")
            ctrhosts = cur.fetchall()
            if ctrhosts is None or len(ctrhosts) == 0:
                LOG.exception(
                    "Failed to fetch controller host information")
                raise
            for ctrhost in ctrhosts:
                # we may have multiple nodes per host, and
                # we only populate one of them (per host) with
                # the tpm_data.
                cur.execute("SELECT capabilities FROM i_node WHERE "
                            "forihostid='%s' AND capabilities!='{}';" %
                            ctrhost['id'])
                tpm_data = cur.fetchone()
                if tpm_data and 'capabilities' in tpm_data:
                    tpm_data = tpm_data['capabilities']
                    LOG.info("Updating tpm_data for host '%s'" % ctrhost['id'])
                    cur.execute("UPDATE tpmdevice SET tpm_data='%s' WHERE "
                                "host_id='%s' AND tpm_data is null ;" %
                                (tpm_data, ctrhost['id']))
            # clear the capabilities field for all hosts
            cur.execute("UPDATE i_node SET capabilities='{}';")


if __name__ == "__main__":
    sys.exit(main())
