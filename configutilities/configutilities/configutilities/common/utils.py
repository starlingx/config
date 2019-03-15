"""
Copyright (c) 2015-2016 Wind River Systems, Inc.

SPDX-License-Identifier: Apache-2.0

"""

from six.moves import configparser
import re
import six
from netaddr import IPNetwork
from netaddr import IPAddress
from netaddr import AddrFormatError
from netaddr import valid_ipv4
from netaddr import valid_ipv6

from configutilities.common.exceptions import ValidateFail

EXPECTED_SERVICE_NAME_AND_TYPE = (
    {"KEYSTONE_SERVICE_NAME": "keystone",
     "KEYSTONE_SERVICE_TYPE": "identity",
     "SYSINV_SERVICE_NAME": "sysinv",
     "SYSINV_SERVICE_TYPE": "platform",
     "PATCHING_SERVICE_NAME": "patching",
     "PATCHING_SERVICE_TYPE": "patching",
     "NFV_SERVICE_NAME": "vim",
     "NFV_SERVICE_TYPE": "nfv",
     "FM_SERVICE_NAME": "fm",
     "FM_SERVICE_TYPE": "faultmanagement",
     "BARBICAN_SERVICE_NAME": "barbican",
     "BARBICAN_SERVICE_TYPE": "key-manager",
     })


def is_valid_vlan(vlan):
    """Determine whether vlan is valid."""
    try:
        if 0 < int(vlan) < 4095:
            return True
        else:
            return False
    except (ValueError, TypeError):
        return False


def is_mtu_valid(mtu):
    """Determine whether a mtu is valid."""
    try:
        if int(mtu) < 576:
            return False
        elif int(mtu) > 9216:
            return False
        else:
            return True
    except (ValueError, TypeError):
        return False


def is_valid_hostname(hostname):
    """Determine whether a hostname is valid as per RFC 1123."""

    # Maximum length of 255
    if not hostname or len(hostname) > 255:
        return False
    # Allow a single dot on the right hand side
    if hostname[-1] == ".":
        hostname = hostname[:-1]
    # Create a regex to ensure:
    # - hostname does not begin or end with a dash
    # - each segment is 1 to 63 characters long
    # - valid characters are A-Z (any case) and 0-9
    valid_re = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(valid_re.match(x) for x in hostname.split("."))


def is_valid_mac(mac):
    """Verify the format of a MAC addres."""
    if not mac:
        return False
    m = "[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$"
    return isinstance(mac, six.string_types) and re.match(m, mac.lower())


def validate_network_str(network_str, minimum_size,
                         existing_networks=None, multicast=False):
    """Determine whether a network is valid."""
    try:
        network = IPNetwork(network_str)
        if network.ip != network.network:
            raise ValidateFail("Invalid network address")
        elif network.size < minimum_size:
            raise ValidateFail("Subnet too small - must have at least %d "
                               "addresses" % minimum_size)
        elif network.version == 6 and network.prefixlen < 64:
            raise ValidateFail("IPv6 minimum prefix length is 64")
        elif existing_networks:
            if any(network.ip in subnet for subnet in existing_networks):
                raise ValidateFail("Subnet overlaps with another "
                                   "configured subnet")
        elif multicast and not network.is_multicast():
            raise ValidateFail("Invalid subnet - must be multicast")
        return network
    except AddrFormatError:
        raise ValidateFail(
            "Invalid subnet - not a valid IP subnet")


def is_valid_filename(filename):
    return '\0' not in filename


def is_valid_by_path(filename):
    return "/dev/disk/by-path" in filename and "-part" not in filename


def is_valid_url(url_str):
    # Django URL validation patterns
    r = re.compile(
        r'^(?:http|ftp)s?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)'  # domain...
        r'+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    url = r.match(url_str)
    if url:
        return True
    else:
        return False


def is_valid_domain(url_str):
    r = re.compile(
        r'^(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)'  # domain...
        r'+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'
        r'[A-Za-z0-9-_]*)'  # localhost, hostname
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    url = r.match(url_str)
    if url:
        return True
    else:
        return False


def is_valid_ipv4(address):
    """Verify that address represents a valid IPv4 address."""
    try:
        return valid_ipv4(address)
    except Exception:
        return False


def is_valid_ipv6(address):
    try:
        return valid_ipv6(address)
    except Exception:
        return False


def is_valid_domain_or_ip(url_str):
    if url_str:
        if is_valid_domain(url_str):
            return True
        ip_with_port = url_str.split(':')
        if len(ip_with_port) <= 2:
            # check ipv4 or ipv4 with port
            return is_valid_ipv4(ip_with_port[0])
        else:
            # check ipv6 with port
            if '[' in url_str:
                try:
                    bkt_idx = url_str.index(']')
                    if bkt_idx + 1 == len(url_str):
                        # brackets without port
                        return False
                    else:
                        return is_valid_ipv6(url_str[1:bkt_idx])
                except Exception:
                    return False
            else:
                # check ipv6 without port
                return is_valid_ipv6(url_str)
    else:
        return False


def is_valid_bool_str(val):
    """Check if the provided string is a valid bool string or not."""
    boolstrs = ('true', 'false')
    return str(val).lower() in boolstrs


def validate_address_str(ip_address_str, network):
    """Determine whether an address is valid."""
    try:
        ip_address = IPAddress(ip_address_str)
        if ip_address.version != network.version:
            msg = ("Invalid IP version - must match network version " +
                   ip_version_to_string(network.version))
            raise ValidateFail(msg)
        elif ip_address == network:
            raise ValidateFail("Cannot use network address")
        elif ip_address == network.broadcast:
            raise ValidateFail("Cannot use broadcast address")
        elif ip_address not in network:
            raise ValidateFail(
                "Address must be in subnet %s" % str(network))
        return ip_address
    except AddrFormatError:
        raise ValidateFail(
            "Invalid address - not a valid IP address")


def ip_version_to_string(ip_version):
    """Determine whether a nameserver address is valid."""
    if ip_version == 4:
        return "IPv4"
    elif ip_version == 6:
        return "IPv6"
    else:
        return "IP"


def validate_nameserver_address_str(ip_address_str, subnet_version=None):
    """Determine whether a nameserver address is valid."""
    try:
        ip_address = IPAddress(ip_address_str)
        if subnet_version is not None and ip_address.version != subnet_version:
            msg = ("Invalid IP version - must match OAM subnet version " +
                   ip_version_to_string(subnet_version))
            raise ValidateFail(msg)
        return ip_address
    except AddrFormatError:
        msg = "Invalid address - "
        "not a valid %s address" % ip_version_to_string(subnet_version)
        raise ValidateFail(msg)


def validate_address(ip_address, network):
    """Determine whether an address is valid."""
    if ip_address.version != network.version:
            msg = ("Invalid IP version - must match network version " +
                   ip_version_to_string(network.version))
            raise ValidateFail(msg)
    elif ip_address == network:
        raise ValidateFail("Cannot use network address")
    elif ip_address == network.broadcast:
        raise ValidateFail("Cannot use broadcast address")
    elif ip_address not in network:
        raise ValidateFail("Address must be in subnet %s" % str(network))


def check_network_overlap(new_network, configured_networks):
    """ Validate that new_network does not overlap any configured_networks.
    """
    if any(new_network.ip in subnet for subnet in
           configured_networks):
        raise ValidateFail(
            "Subnet %s overlaps with another configured subnet" % new_network)


def lag_mode_to_str(lag_mode):
    if lag_mode == 0:
        return "balance-rr"
    if lag_mode == 1:
        return "active-backup"
    elif lag_mode == 2:
        return "balance-xor"
    elif lag_mode == 3:
        return "broadcast"
    elif lag_mode == 4:
        return "802.3ad"
    elif lag_mode == 5:
        return "balance-tlb"
    elif lag_mode == 6:
        return "balance-alb"
    else:
        raise Exception(
            "Invalid LAG_MODE value of %d. Valid values: 0-6" % lag_mode)


def validate_openstack_password(password, rules_file,
                                section="security_compliance"):
    try:
        config = configparser.RawConfigParser()
        parsed_config = config.read(rules_file)
        if not parsed_config:
            msg = ("Cannot parse rules file: %s" % rules_file)
            raise Exception(msg)
        if not config.has_section(section):
            msg = ("Required section '%s' not found in rules file" % section)
            raise Exception(msg)

        password_regex = get_optional(config, section, 'password_regex')
        password_regex_description = get_optional(config, section,
                                                  'password_regex_description')

        if not password_regex:
            msg = ("Required option 'password_regex' not found in "
                   "rule file: %s" % rules_file)
            raise Exception(msg)
        # Even if regex_description is not found, we will proceed
        # and give a generic failure warning instead
        if not password_regex_description:
            password_regex_description = ("Password does not meet "
                                          "complexity criteria")

        if not isinstance(password, six.string_types):
            msg = ("Password must be a string type")
            raise Exception(msg)
        try:
            # config parser would read in the string as a literal
            # representation which would fail regex matching
            password_regex = password_regex.strip('"')
            if not re.match(password_regex, password):
                return False, password_regex_description
        except re.error:
            msg = ("Unable to validate password due to invalid "
                   "complexity criteria ('password_regex')")
            raise Exception(msg)
    except Exception:
        raise Exception("Password validation failed")
    return True, ""


def extract_openstack_password_rules_from_file(
        rules_file, section="security_compliance"):
    try:
        config = configparser.RawConfigParser()
        parsed_config = config.read(rules_file)
        if not parsed_config:
            msg = ("Cannot parse rules file: %s" % rules_file)
            raise Exception(msg)
        if not config.has_section(section):
            msg = ("Required section '%s' not found in rules file" % section)
            raise Exception(msg)

        rules = config.items(section)
        if not rules:
            msg = ("section '%s' contains no configuration options" % section)
            raise Exception(msg)
        return dict(rules)
    except Exception:
        raise Exception("Failed to extract password rules from file")


def get_optional(conf, section, key):
    if conf.has_option(section, key):
        return conf.get(section, key)
    return None


def get_service(conf, section, key):
    if key in EXPECTED_SERVICE_NAME_AND_TYPE:
        if conf.has_option(section, key):
            value = conf.get(section, key)
            if value != EXPECTED_SERVICE_NAME_AND_TYPE[key]:
                raise ValidateFail("Unsupported %s: %s " % (key, value))
        else:
            value = EXPECTED_SERVICE_NAME_AND_TYPE[key]
        return value
    else:
        return conf.get(section, key)
