"""
Copyright (c) 2017-2021 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from __future__ import print_function
import json
import netaddr
import os
import subprocess
import sys
import time

import controllerconfig.common.exceptions as exeptions
import controllerconfig.utils as utils
from six.moves import input


def is_valid_management_address(ip_address, management_subnet):
    """Determine whether a management address is valid."""
    if ip_address == management_subnet.network:
        print("Cannot use network address")
        return False
    elif ip_address == management_subnet.broadcast:
        print("Cannot use broadcast address")
        return False
    elif ip_address.is_multicast():
        print("Invalid address - multicast address not allowed")
        return False
    elif ip_address.is_loopback():
        print("Invalid address - loopback address not allowed")
        return False
    elif ip_address not in management_subnet:
        print("Address must be in the management subnet")
        return False
    else:
        return True


def configure_management():
    interface_list = list()
    lldp_interface_list = list()

    print("Enabling interfaces... ", end=' ')
    ip_link_output = subprocess.check_output(['ip', '-o', 'link'],
                                             universal_newlines=True)

    for line in ip_link_output.splitlines():
        interface = line.split()[1].rstrip(':')
        if interface != 'lo':
            interface_list.append(interface)
        subprocess.call(['ip', 'link', 'set', interface, 'up'])
    print('DONE')

    wait_seconds = 120
    delay_seconds = 5
    print("Waiting %d seconds for LLDP neighbor discovery" % wait_seconds,
          end=' ')
    while wait_seconds > 0:
        sys.stdout.write('.')
        sys.stdout.flush()
        time.sleep(delay_seconds)
        wait_seconds -= delay_seconds
    print(' DONE')

    print("Retrieving neighbor details... ", end=' ')
    lldpcli_show_output = subprocess.check_output(
        ['sudo', 'lldpcli', 'show', 'neighbors', 'summary', '-f', 'json'],
        universal_newlines=True)
    try:
        lldp_interfaces = json.loads(
            lldpcli_show_output)['lldp'][0]['interface']
    except Exception as e:
        lldp_interfaces = {}
    print("DONE")

    print("\nAvailable interfaces:")
    print("%-20s %s" % ("local interface", "remote port"))
    print("%-20s %s" % ("---------------", "-----------"))
    for interface in lldp_interfaces:
        print("%-20s %s" % (interface['name'],
                            interface['port'][0]['id'][0]['value']))
        lldp_interface_list.append(interface['name'])
    for interface in interface_list:
        if interface not in lldp_interface_list:
            print("%-20s %s" % (interface, 'unknown'))

    print('')
    while True:
        user_input = input("Enter management interface name: ")
        if user_input in interface_list:
            management_interface = user_input
            break
        else:
            print("Invalid interface name")
            continue

    while True:
        user_input = input("Enter management IP address in CIDR "
                           "notation, ie. ip/prefix_length: ")
        try:
            management_cidr = netaddr.IPNetwork(user_input)
            management_ip = management_cidr.ip
            management_network = netaddr.IPNetwork(
                "%s/%s" % (str(management_cidr.network),
                           str(management_cidr.prefixlen)))
            if not is_valid_management_address(management_ip,
                                               management_network):
                continue
            break
        except (netaddr.AddrFormatError, ValueError):
            print("Invalid CIDR - "
                  "please enter a valid management IP address in "
                  "CIDR notation.")

    while True:
        user_input = input("Enter management gateway IP address [" +
                           str(management_network[1]) + "]: ")
        if user_input == "":
            user_input = management_network[1]

        try:
            ip_input = netaddr.IPAddress(user_input)
            if not is_valid_management_address(ip_input,
                                               management_network):
                continue
            management_gateway_address = ip_input
            break
        except (netaddr.AddrFormatError, ValueError):
            print("Invalid address - "
                  "please enter a valid management gateway IP address")

    min_addresses = 8
    while True:
        user_input = input("Enter System Controller subnet in "
                           "CIDR notation: ")
        try:
            system_controller_subnet = utils.validate_network_str(
                user_input, min_addresses)
            break
        except exeptions.ValidateFail as e:
            print("{}".format(e))

    print("Disabling non-management interfaces... ", end=' ')
    for interface in interface_list:
        if interface != management_interface:
            subprocess.call(['ip', 'link', 'set', interface, 'down'])
    print('DONE')

    print("Configuring management interface... ", end=' ')
    subprocess.call(['ip', 'addr', 'add', str(management_cidr), 'dev',
                     management_interface])
    print("DONE")

    print("Adding route to System Controller... ", end=' ')
    subprocess.call(['ip', 'route', 'add', str(system_controller_subnet),
                     'dev', management_interface, 'via',
                     str(management_gateway_address)])
    print("DONE")


def main():
    if not os.geteuid() == 0:
        print("%s must be run with root privileges" % sys.argv[0])
        exit(1)
    try:
        configure_management()
    except KeyboardInterrupt:
        print("\nAborted")
