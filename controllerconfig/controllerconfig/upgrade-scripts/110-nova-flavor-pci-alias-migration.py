#!/usr/bin/env python
# Copyright (c) 2018 Wind River Systems, Inc.
#
# The right to copy, distribute, modify, or otherwise make use
# of this software may be licensed only pursuant to the terms
# of an applicable Wind River license agreement.
#
# This migration script renames the qat devices from qat-vf to
# qat-dh895xcc-vf in the flavor extra specs that contains pci passthrough alias

import sys

import psycopg2
from controllerconfig.common import log
from psycopg2.extras import RealDictCursor
from sysinv.common import constants

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
            LOG.info("performing nova flavor extra specs migration "
                     "from release %s to %s with action: %s" %
                     (from_release, to_release, action))
            update_nova_flavor_pci_alias_data()
        except Exception as ex:
            LOG.exception(ex)
            print ex
            return 1


# In R4, only the Coleto Creek (qat-vf) is supported.
# In R5, the qat devices are exposed more explicitly as qat-dh895xcc-vf
# The pci passthrough alias name 'qat-vf' is replaced with 'qat-dh895xcc-vf'.
def update_nova_flavor_pci_alias_data():
    conn = psycopg2.connect("dbname='nova_api' user='postgres'")
    with conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("UPDATE flavor_extra_specs SET value = regexp_replace("
                        "value, '\mqat-vf\M', '%s', 'gi') WHERE "
                        "key='pci_passthrough:alias'" %
                        constants.NOVA_PCI_ALIAS_QAT_DH895XCC_VF_NAME)


if __name__ == "__main__":
    sys.exit(main())
