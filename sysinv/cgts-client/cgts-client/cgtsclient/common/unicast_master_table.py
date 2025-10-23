########################################################################
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from dataclasses import dataclass
from dataclasses import field
import ipaddress
import re


def check_ip_version(ip_string):
    try:
        return ipaddress.ip_address(ip_string).version
    except ValueError:
        return None


def is_valid_mac_address(mac_address_str):
    pattern = r"^([0-9A-Fa-f]{2}:){5}([0-9A-Fa-f]{2})$"
    return bool(re.match(pattern, mac_address_str))


@dataclass
class UnicastMasterTable:
    table_id: list[int] = field(default_factory=list)
    logQueryInterval: list[int] = field(default_factory=list)
    peer_address: list[str] = field(default_factory=list)
    L2: list[str] = field(default_factory=list)
    UDPv4: list[str] = field(default_factory=list)
    UDPv6: list[str] = field(default_factory=list)

    def add(self, param_name, param_value):
        # checks if the param_value is of right format or not
        # before adding to the list
        # table_id=<+ number>, UDPv4=<IPv4>, UDPv6=<IPv6>, L2=<MAC>,
        # peer_address=<IPv4/6>, logQueryInterval=<number>
        err_msg = None
        if param_name == "table_id":
            # check if param_value is positive integer.
            try:
                param_value_int = int(param_value)
                if param_value_int > 0:
                    self.table_id.append(param_value_int)
                else:
                    err_msg = "not positive integer"
            except ValueError:
                err_msg = "not positive integer"
        elif param_name == "logQueryInterval":
            # check if param_value is +/- integer
            try:
                param_value_int = int(param_value)
                self.logQueryInterval.append(param_value_int)
            except ValueError:
                err_msg = "not integer"
        elif param_name == "peer_address":
            # check if param_value is either IPv4 or IPv6
            if check_ip_version(param_value) in [4, 6]:
                self.peer_address.append(param_value)
            else:
                err_msg = "not IPv4/6 address"
        elif param_name == "L2":
            # check if param_value is MAC address
            if is_valid_mac_address(param_value):
                self.L2.append(param_value)
            else:
                err_msg = "not MAC address"
        elif param_name == "UDPv4":
            # check if param_value is IPv4
            if check_ip_version(param_value) == 4:
                self.UDPv4.append(param_value)
            else:
                err_msg = "not IPv4 address"
        elif param_name == "UDPv6":
            # check if param_value is IPv6
            if check_ip_version(param_value) == 6:
                self.UDPv6.append(param_value)
            else:
                err_msg = "not IPv6 address"
        else:
            # not valid param_name
            err_msg = "not valid parameter key"

        return err_msg

    def comply(self):
        # Checks single key-value pair for table_id, logQueryInterval and peer_address
        # Multiple key-value pair supported for L2, UDPv4, UDPv6
        # L2 or UPPv4 or UDPv6, can not be mixed
        #
        def _is_mixed(a, b, c):
            # check a | b | c
            # when one of argument is > 0, others must be 0,
            # otherwise it is mixed.
            if (
                (a > 0 and not (b == 0 and c == 0)) or
                (b > 0 and not (a == 0 and c == 0)) or
                (c > 0 and not (a == 0 and b == 0))
            ):
                return True

            return False

        repetition_err = "Repetition/Duplication not supported for parameter:"
        if len(self.table_id) > 1:
            return f"{repetition_err} table_id"
        if len(self.logQueryInterval) > 1:
            return f"{repetition_err} logQueryInterval"
        if len(self.peer_address) > 1:
            return f"{repetition_err} peer_address"

        if _is_mixed(len(self.L2), len(self.UDPv4), len(self.UDPv6)):
            return "L2 or UPPv4 or UDPv6, these parameters can not be mixed"

        return None
