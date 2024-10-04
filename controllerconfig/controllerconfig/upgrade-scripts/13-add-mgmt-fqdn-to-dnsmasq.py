#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import logging as LOG
import sys
import os
import subprocess


DEFAULT_POSTGRES_PORT = 5432
LOG_FILE = "/var/log/software.log"


def main():
    action = None
    from_release = None
    to_release = None
    postgres_port = DEFAULT_POSTGRES_PORT
    arg = 1

    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]
        elif arg == 2:
            to_release = sys.argv[arg]
        elif arg == 3:
            action = sys.argv[arg]
        elif arg == 4:
            # optional port parameter for USM upgrade
            postgres_port = sys.argv[arg]
            pass
        else:
            print("Invalid option %s." % sys.argv[arg])
            return 1
        arg += 1

    log_format = ('%(asctime)s: ' + '[%(process)s]: '
                  '%(filename)s(%(lineno)s): %(levelname)s: %(message)s')
    LOG.basicConfig(filename=LOG_FILE, format=log_format, level=LOG.INFO,
                    datefmt="%FT%T")

    res = 0

    # Create the basic MGMT FQDN entries in the following file:
    # /opt/platform/config/<to_release>/dnsmasq.addn_hosts.
    # The entries are:
    #  x.x.x.x controller.internal controller registry.local
    #          controller-platform-nfs
    #  x.x.x.x controller-0.internal controller-0
    #  x.x.x.x controller-1.internal controller-1
    #
    # During the upgrade process, the sysinv-conductor updates the
    # dnsmasq.addn_hosts file.
    # However, if an error occurs during the controller boot for <to_release>
    # (e.g., Puppet errors and reboot), some services might attempt to use
    # FQDNs before the sysinv-conductor has added the necessary FQDN entries
    # to dnsmasq.
    # Therefore, it is important to ensure that the MGMT FQDNs are added to
    # dnsmasq before booting with the <to_release> ISO.

    if action == "migrate" and from_release == "22.12":
        LOG.info("Creating basic MGMT FQDN entries in dnsmasq.")

        try:
            add_mgmt_entries_to_dnsmasq_addn_hosts(postgres_port, to_release)
        except Exception as ex:
            LOG.exception("Error: {}".format(ex))
            print(ex)
            res = 1

    return res


# Retrieve the management IP addresses for the controller nodes.
def get_mgmt_address_from_db(postgres_port):
    query = "select addresses.name, addresses.address from addresses " \
            "inner join networks on networks.type = 'mgmt' " \
            "and networks.address_pool_id = addresses.address_pool_id;"

    mgmt_addresses = db_query(postgres_port, query)

    # mgmt addresses
    LOG.info("MGMT addresses: {}".format(mgmt_addresses))

    # Converting the list of lists to list of dictionaries
    keys = ["name", "address"]
    mgmt_addr_dict = [dict(zip(keys, mgmt_addr))
                      for mgmt_addr in mgmt_addresses]

    return mgmt_addr_dict


def add_mgmt_entries_to_dnsmasq_addn_hosts(postgres_port, to_release):
    addresses = get_mgmt_address_from_db(postgres_port)

    entries = ""
    for address in addresses:
        line = ""
        if address["name"] == "controller-mgmt":
            line = "{} controller.internal controller registry.local " \
                   "controller-platform-nfs".format(address["address"])
        elif address["name"] == "controller-0-mgmt":
            line = "{} controller-0.internal controller-0".format(
                address["address"])
        elif address["name"] == "controller-1-mgmt":
            line = "{} controller-1.internal controller-1".format(
                address["address"])
        else:
            LOG.info("Unexpected entry in the addresses table: name:{} IP: {}"
                     .format(address["name"], address["address"]))
            continue
        entries += line + "\n"

    dnsmasq_file = "/opt/platform/config/{}/dnsmasq.addn_hosts".format(
        to_release)

    with open(dnsmasq_file, 'a') as file:
        file.write(entries)

    LOG.info("dnsmasq.addn_hosts filled with basic FQDN entries")


def db_query(postgres_port, query):
    env = os.environ.copy()
    sub_sel = subprocess.Popen(
        ['sudo', '-u', 'postgres',
         'psql', '-p', f'{postgres_port}',
         '-d', 'sysinv', '-c', query],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        universal_newlines=True)

    result = []
    stdout, stderr = sub_sel.communicate()
    if sub_sel.returncode == 0 and stdout:
        rows = [item for item in stdout.split('\n') if '|' in item]
        # Remove header from sql stdout
        rows.pop(0)
        for row in rows:
            records = [v.strip() for v in row.split('|')]
            result.append(records)
    else:
        LOG.error('Failed to connect to sysinv database:'
                  '\n%s. \n%s.' % (stdout, stderr))
        raise Exception(stderr)
    return result


if __name__ == "__main__":
    sys.exit(main())
