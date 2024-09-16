#!/usr/bin/python
# Copyright (c) 2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0

import logging as LOG
import sys
import os
import subprocess
import yaml

DEFAULT_POSTGRES_PORT = 5432
LOG_FILE = "/var/log/software.log"


def main():
    action = None
    from_release = None  # noqa
    to_release = None  # noqa
    postgres_port = DEFAULT_POSTGRES_PORT
    arg = 1
    while arg < len(sys.argv):
        if arg == 1:
            from_release = sys.argv[arg]  # noqa
        elif arg == 2:
            to_release = sys.argv[arg]  # noqa
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

    if to_release == "24.09" and action == "activate":
        try:
            LOG.info("Starting pxeboot DHCP lease renewal")
            do_pxeboot_lease_renew(postgres_port)
        except Exception as ex:
            LOG.exception(ex)
            print(ex)
            return 1


def execute_system_cmd(api_cmd, exc_msg):
    cmd = f'source /etc/platform/openrc && {api_cmd}'

    sub = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    stdout, stderr = sub.communicate()
    if sub.returncode == 0:
        return stdout.decode('utf-8').rstrip('\n')
    else:
        LOG.error('Command failed:\n %s\n. %s\n%s\n'
                  % (cmd, stdout.decode('utf-8'),
                     stderr.decode('utf-8')))
        raise Exception(exc_msg)


def get_sysadmin_password():
    cmd = 'echo $OS_PASSWORD'
    exc_msg = 'Cannot retrieve sysadmin password.'

    passwd = execute_system_cmd(cmd, exc_msg)
    if passwd == '':
        raise Exception('Failed to retrieve sysadmin credentials.')

    return passwd


def do_pxeboot_lease_renew(port):
    passwd = get_sysadmin_password()
    ifaces = get_host_interface_list(port)

    if not ifaces:
        return

    hosts_dict = {iface["hostname"]: {"ansible_connection": "ssh"}
                  for iface in ifaces}

    inventory_dict = {
        "all": {
            "vars": {
                "ansible_ssh_user": "sysadmin",
                "ansible_ssh_pass": passwd,
                "ansible_become_pass": passwd
            },
            "hosts": hosts_dict
        }
    }

    inventory_file = "/tmp/ansible_adhoc_inventory.yaml"

    with open(inventory_file, "w") as out:
        try:
            yaml.dump(inventory_dict, out, default_flow_style=False)
        except Exception as e:
            LOG.error("Failed to create inventory file %s. Error %s" %
                      (inventory_file, e))
            raise

    for iface in ifaces:
        cmd = 'ansible %s -i %s -B 300 -P 0 --become -m ansible.builtin.' \
              'shell -a "/usr/bin/dhcp-renew.sh %s"' % \
              (iface["hostname"], inventory_file, iface["kernel_iface"])

        LOG.info("Sending DHCP renew command to interface %s on host %s: %s" %
                 (iface['ifname'], iface["hostname"], cmd))

        sub = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        stdout, stderr = sub.communicate()
        if sub.returncode != 0:
            LOG.error('Command failed:\n %s\n%s\n' %
                      (stdout.decode('utf-8'), stderr.decode('utf-8')))
            raise Exception("Failed to send DHCP renew command to interface "
                            "%s on host %s" % (iface['ifname'],
                                               iface["hostname"]))

    os.remove(inventory_file)


def get_host_interface_list(port):
    pxeboot_id = get_pxeboot_network_id(port)
    ifaces = []
    iface_records = get_pxeboot_interfaces(port)
    for iface in iface_records:
        if iface["iftype"] == "ethernet":
            kernel_iface = get_pxeboot_port(port, iface["interface_id"])
            ifname = "%s(%s)" % (iface["ifname"], kernel_iface)
        elif iface["iftype"] == "ae":
            kernel_iface = iface["ifname"]
            ifname = iface["ifname"]
        else:
            LOG.info("Unexpected type %s for interface %s on host %s" %
                     (iface["iftype"], iface["ifname"], iface["hostname"]))
            continue
        kernel_iface = get_interface_label(port, iface, kernel_iface,
                                           pxeboot_id)
        ifaces.append({"hostname": iface["hostname"], "ifname": ifname,
                       "kernel_iface": kernel_iface})
    return ifaces


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


def get_pxeboot_interfaces(postgres_port):
    query = "select interfaces.id,interfaces.iftype,interfaces.ifname," \
            "i_host.hostname,networks.id,networks.type from networks inner " \
            "join interface_networks on interface_networks.network_id = " \
            "networks.id and (networks.type = 'pxeboot' or networks.type = " \
            "'mgmt') inner join interfaces on " \
            "interface_networks.interface_id = interfaces.id inner join " \
            "i_host on interfaces.forihostid = i_host.id and " \
            "i_host.personality != 'controller';"
    values = db_query(postgres_port, query)
    iface_dict = dict()
    for value in values:
        records = iface_dict.setdefault(value[3], {})
        records[value[5]] = {'interface_id': value[0],
                             'iftype': value[1],
                             'ifname': value[2],
                             'hostname': value[3],
                             'network_id': value[4],
                             'network_type': value[5]}
    record_list = []
    for records in iface_dict.values():
        record = records.get("pxeboot", None)
        if record:
            record_list.append(record)
        else:
            mgmt_record = records["mgmt"]
            if mgmt_record["iftype"] != "vlan":
                record_list.append(mgmt_record)
    return record_list


def get_pxeboot_port(postgres_port, interface_id):
    query = f"select name,type from ports where interface_id = {interface_id};"
    values = db_query(postgres_port, query)
    return values[0][0]


def get_interface_label(postgres_port, iface, kernel_iface, pxeboot_id):
    if iface["network_type"] == "mgmt":
        return f"{kernel_iface}:{pxeboot_id}"
    query = "select * from interface_networks where interface_id = %s;" % \
            iface['interface_id']
    values = db_query(postgres_port, query)
    if len(values) > 1:
        return f"{kernel_iface}:{pxeboot_id}"
    return kernel_iface


def get_pxeboot_network_id(postgres_port):
    query = "select id,type from networks where type = 'pxeboot';"
    values = db_query(postgres_port, query)
    return values[0][0]


if __name__ == "__main__":
    sys.exit(main())
