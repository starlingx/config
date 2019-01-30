# Copyright (c) 2017-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

import json
import ldap
import ldapurl
import netaddr
import os
import pecan
import re
import rpm
import six
import wsme

from six.moves.urllib.parse import urlparse
from sysinv.common import constants
from sysinv.common import exception
from sysinv.common.storage_backend_conf import StorageBackendConfig
from sysinv.common import utils as cutils
from sysinv.db import api as db_api
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _

LOG = log.getLogger(__name__)

SERVICE_PARAMETER_DATA_FORMAT_ARRAY = 'array'
SERVICE_PARAMETER_DATA_FORMAT_BOOLEAN = 'boolean'
SERVICE_PARAMETER_DATA_FORMAT_SKIP = 'skip'

IDENTITY_CONFIG_TOKEN_EXPIRATION_MIN = 3600
IDENTITY_CONFIG_TOKEN_EXPIRATION_MAX = 14400

EMC_VNX_CONTROL_NETWORK_TYPES = [
    constants.NETWORK_TYPE_INFRA,
    constants.NETWORK_TYPE_MGMT,
    constants.NETWORK_TYPE_OAM,
]

EMC_VNX_DATA_NETWORK_TYPES = [
    constants.NETWORK_TYPE_INFRA,
    constants.NETWORK_TYPE_MGMT,
]


def _validate_boolean(name, value):
    if value.lower() not in ['true', 'false']:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a boolean value." % name))


def _validate_yes_no(name, value):
    if value.lower() not in ['y', 'n']:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a yes/no value." % name))


def _validate_integer(name, value):
    try:
        int(value)
    except ValueError:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be an integer value." % name))


def _validate_float(name, value):
    try:
        float(value)
    except ValueError:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a float value." % name))


def _validate_not_empty(name, value):
    if not value or value is '':
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must not be an empty value." % name))


def _validate_range(name, value, min, max):
    try:
        if int(value) < min or int(value) > max:
            raise wsme.exc.ClientSideError(_(
                "Parameter '%s' must be between %d and %d.")
                % (name, min, max))
    except ValueError:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be an integer value." % name))


def _validate_zero_or_range(name, value, min, max):
    try:
        if int(value) != 0:
            if int(value) < min or int(value) > max:
                raise wsme.exc.ClientSideError(_(
                    "Parameter '%s' must be zero or between %d and %d.")
                    % (name, min, max))
    except ValueError:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be an integer value." % name))


def _validate_ldap_url(name, value):

    url = urlparse(value)

    if cutils.is_valid_ip(url.hostname):
        try:
            ip_addr = netaddr.IPNetwork(url.hostname)
        except netaddr.core.AddrFormatError:
            raise wsme.exc.ClientSideError(_(
                "Invalid IP address for LDAP url"))
        if ip_addr.is_loopback():
            raise wsme.exc.ClientSideError(_(
                "LDAP server must not be loopback."))
    elif url.hostname:
        if constants.LOCALHOST_HOSTNAME in url.hostname.lower():
            raise wsme.exc.ClientSideError(_(
                "LDAP server must not be localhost."))

    try:
        ldapurl.LDAPUrl(value)
    except ValueError as ve:
        raise wsme.exc.ClientSideError(_(
            "Invalid LDAP url format: %s" % str(ve)))


def _validate_ldap_dn(name, value):
    try:
        ldap.dn.str2dn(value)
    except ldap.DECODING_ERROR:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a valid LDAP DN value" % name))


def _validate_assignment_driver(name, value):
    values = [constants.SERVICE_PARAM_IDENTITY_ASSIGNMENT_DRIVER_SQL]
    if value not in values:
        raise wsme.exc.ClientSideError(_(
            "Identity assignment driver must be one of: %s" % values))


def _validate_identity_driver(name, value):
    values = [constants.SERVICE_PARAM_IDENTITY_IDENTITY_DRIVER_SQL,
              constants.SERVICE_PARAM_IDENTITY_IDENTITY_DRIVER_LDAP]
    if value not in values:
        raise wsme.exc.ClientSideError(_(
            "Identity identity driver must be one of: %s" % values))


def _validate_neutron_ml2_mech(name, value):
    allowed = constants.SERVICE_PARAM_NETWORK_ML2_MECH_DRIVERS
    # can accept multiple comma separated values
    values = value.split(',')
    for item in values:
        if item not in allowed:
            raise wsme.exc.ClientSideError(_(
                "Neutron ML2 mechanism driver must be one of: %s" % allowed))


def _validate_neutron_ml2_ext(name, value):
    allowed = constants.SERVICE_PARAM_NETWORK_ML2_EXT_DRIVERS
    # can accept multiple comma separated values
    values = value.split(',')
    for item in values:
        if item not in allowed:
            raise wsme.exc.ClientSideError(_(
                "Neutron ML2 extension driver must be one of: %s" % allowed))


def _validate_neutron_network_types(name, value):
    allowed = constants.SERVICE_PARAM_NETWORK_ML2_TENANT_TYPES
    # can accept multiple comma separated values
    values = value.split(',')
    for item in values:
        if item not in allowed:
            raise wsme.exc.ClientSideError(_(
                "Neutron tenant network type must be one of: %s" % allowed))


def _validate_neutron_service_plugins(name, value):
    allowed = constants.SERVICE_PARAM_NETWORK_DEFAULT_SERVICE_PLUGINS
    # can accept multiple comma separated values
    values = value.split(',')
    for item in values:
        if item not in allowed:
            raise wsme.exc.ClientSideError(_(
                "Neutron service plugins must be one of: %s" % allowed))


def _validate_odl_connection_uri(name, value):
    url = urlparse(value)

    if cutils.is_valid_ip(url.hostname):
        try:
            ip_addr = netaddr.IPNetwork(url.hostname)
        except netaddr.core.AddrFormatError:
            raise wsme.exc.ClientSideError(_(
                "Invalid IP address for ODL connection URI"))
        if ip_addr.is_loopback():
            raise wsme.exc.ClientSideError(_(
                "SDN controller must not be loopback."))
    elif url.hostname:
        if constants.LOCALHOST_HOSTNAME in url.hostname.lower():
            raise wsme.exc.ClientSideError(_(
                "SDN controller must not be localhost."))


def _validate_value_in_set(name, value, _set):
    if value not in _set:
        raise wsme.exc.ClientSideError(_(
            "Parameter '{}' must be{}: {}".format(
                name,
                " one of" if (len(_set) > 1) else "",
                ", ".join(_set))))


def _validate_token_expiry_time(name, value):
    """Check if timeout value is valid"""
    try:
        if int(value) < IDENTITY_CONFIG_TOKEN_EXPIRATION_MIN \
                or int(value) > IDENTITY_CONFIG_TOKEN_EXPIRATION_MAX:
            raise wsme.exc.ClientSideError(_(
                "Parameter '%s' must be between %d and %d seconds.")
                % (name, IDENTITY_CONFIG_TOKEN_EXPIRATION_MIN,
                   IDENTITY_CONFIG_TOKEN_EXPIRATION_MAX))
    except ValueError:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be an integer value." % name))


def _validate_ip_address(name, value):
    """Check if ip value is valid"""
    if not cutils.is_valid_ip(value):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be an IP address." % name))


def _validate_emc_vnx_iscsi_initiators(name, value):
    """Check if iscsi_initiators value is valid.  An example of valid
       iscsi_initiators string:
       {"worker-0": ["10.0.0.1", "10.0.0.2"], "worker-1": ["10.0.0.3"]}
    """
    try:
        iscsi_initiators = json.loads(value)
        if not isinstance(iscsi_initiators, dict):
            raise ValueError
        for hostname, initiators_ips in iscsi_initiators.items():
            if not isinstance(initiators_ips, list):
                raise ValueError
            else:
                for ip in initiators_ips:
                    if not cutils.is_valid_ip(ip):
                        raise ValueError
    except ValueError:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be an dict of IP addresses lists." % name))


def _validate_emc_vnx_storage_vnx_security_file_dir(name, value):
    """Check if security_file_dir exits"""
    if not os.path.exists(value):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be an existing path" % name))


def _validate_emc_vnx_storage_vnx_authentication_type(name, value):
    _validate_value_in_set(
        name, value,
        ['global', 'local', 'ldap'])


def _validate_read_only(name, value):
    raise wsme.exc.ClientSideError(_(
        "Parameter '%s' is readonly" % name))


def _validate_emc_vnx_control_network_type(name, value):
    _validate_value_in_set(
        name, value, EMC_VNX_CONTROL_NETWORK_TYPES
    )


def _validate_emc_vnx_data_network_type(name, value):
    _validate_value_in_set(
        name, value, EMC_VNX_DATA_NETWORK_TYPES
    )


def _validate_hpe_api_url(name, value):
    url = urlparse(value)

    if cutils.is_valid_ip(url.hostname):
        try:
            ip_addr = netaddr.IPNetwork(url.hostname)
        except netaddr.core.AddrFormatError:
            raise wsme.exc.ClientSideError(_(
                "Invalid URL address '%s' for '%s'" % (value, name)))
        if ip_addr.is_loopback():
            raise wsme.exc.ClientSideError(_(
                "URL '%s' must not be loopback for '%s'" % (value, name)))
    elif url.hostname:
        if constants.LOCALHOST_HOSTNAME in url.hostname.lower():
            raise wsme.exc.ClientSideError(_(
                "URL '%s' must not be localhost for '%s'" % (value, name)))
    else:
        raise wsme.exc.ClientSideError(_(
            "Invalid URL address '%s' for '%s'" % (value, name)))


def _validate_hpe3par_iscsi_ips(name, value):
    """

    Validate list of IP addresses with an optional port number.
    For example:
      "10.10.220.253:3261,10.10.222.234"

    """

    ip_addrs = value.split(',')
    if len(ip_addrs) == 0:
        raise wsme.exc.ClientSideError(_(
            "No IP addresses provided for '%s'" % name))

    for ip_addr in ip_addrs:
        ipstr = ip_addr.split(':')
        if len(ipstr) == 1:
            _validate_ip_address(name, ipstr[0])
        elif len(ipstr) == 2:
            _validate_ip_address(name, ipstr[0])
            #
            # Validate port number
            #
            try:
                port = int(ipstr[1])
            except ValueError:
                raise wsme.exc.ClientSideError(_(
                    "Invalid port number '%s' for '%s'" % (ipstr[1], name)))
            if port < 0 or port > 65535:
                raise wsme.exc.ClientSideError(_(
                    "Port number '%d' must be between 0 and 65535 in '%s'" %
                    (port, name)))
        else:
            raise wsme.exc.ClientSideError(_(
                "Invalid IP address '%s' in '%s'" % (ipstr, name)))
        #
        # Address must be in one of the supported network's pools.
        #
        ip = netaddr.IPAddress(ipstr[0])
        pool = _get_network_pool_from_ip_address(ip, HPE_DATA_NETWORKS)
        if pool is None:
            raise wsme.exc.ClientSideError(_(
                "Invalid IP address '%s' in '%s'" % (ipstr[0], name)))


def _validate_pci_alias(name, value):
    allowed = ['vendor_id', 'product_id', 'class_id', 'name', 'device_id']
    disallowed_names = [constants.NOVA_PCI_ALIAS_QAT_DH895XCC_PF_NAME,
                        constants.NOVA_PCI_ALIAS_QAT_DH895XCC_VF_NAME,
                        constants.NOVA_PCI_ALIAS_QAT_C62X_PF_NAME,
                        constants.NOVA_PCI_ALIAS_QAT_C62X_VF_NAME,
                        constants.NOVA_PCI_ALIAS_GPU_NAME]

    existing_aliases = pecan.request.dbapi.service_parameter_get_all(
        service=constants.SERVICE_TYPE_NOVA,
        section=constants.SERVICE_PARAM_SECTION_NOVA_PCI_ALIAS)

    # Note: the following regex should match that used for the pci_passthrough:alias
    # flavor (metadata) property.
    name_regex = re.compile("^[a-zA-Z-0-9]*")

    for alias in value.rstrip(';').split(';'):
        try:
            alias_dict = dict(x.split('=') for x in alias.split(','))
        except ValueError:
            raise wsme.exc.ClientSideError(_(
                    "Invalid PCI alias. Must be a string of <key>=<value>, pairs."))

        if "name" not in alias_dict:
            raise wsme.exc.ClientSideError(_(
                    "PCI alias must specify a name"))

        for existing in existing_aliases:
            # Allow user to modify an existing name
            if existing.name == name:
                continue

            # Make sure the specified name doesn't exist in any other alias
            for alias in existing.value.rstrip(';').split(';'):
                existing_dict = dict(x.split('=') for x in alias.split(','))
                if alias_dict.get("name") == existing_dict.get("name"):
                    raise wsme.exc.ClientSideError(_(
                        "Duplicate PCI alias name %s") % alias_dict.get("name"))

        if alias_dict.get("name") in disallowed_names:
            raise wsme.exc.ClientSideError(_(
                    "Invalid PCI alias name. Name cannot be one of %r") % disallowed_names)

        if not name_regex.match(alias_dict.get("name")):
            raise wsme.exc.ClientSideError(_(
                    "Invalid PCI alias name. Only alphanumeric characters and '-' are allowed"))

        for k, v in six.iteritems(alias_dict):
            if k not in allowed:
                raise wsme.exc.ClientSideError(_(
                    "Invalid PCI alias parameter.  Must be one of: %s" % allowed))
            elif k in ["device_id", "vendor_id", "product_id"]:
                if not cutils.is_valid_pci_device_vendor_id(v):
                    raise wsme.exc.ClientSideError(_(
                        "Invalid PCI alias parameter '%s'. Must be a 4 digit hex value.") % k)
            elif k == "class_id":
                if not cutils.is_valid_pci_class_id(v):
                    raise wsme.exc.ClientSideError(_(
                        "Invalid PCI alias parameter '%s'. Must be a 6 digit hex value.") % k)


def _get_network_pool_from_ip_address(ip, networks):
    for name in networks:
        try:
            network = pecan.request.dbapi.network_get_by_type(name)
        except exception.NetworkTypeNotFound:
            continue
        pool = pecan.request.dbapi.address_pool_get(network.pool_uuid)
        #
        # IP address in the pool's network?  If so, return the pool.
        #
        ipnet = netaddr.IPNetwork("%s/%u" % (pool["network"], pool["prefix"]))
        if ip in ipnet:
            return pool
    #
    # Pool not found.
    #
    return None


def _emc_vnx_get_param_from_name(param_name):
    try:
        return pecan.request.dbapi.service_parameter_get_one(
            service=constants.SERVICE_TYPE_CINDER,
            section=constants.SERVICE_PARAM_SECTION_CINDER_EMC_VNX,
            name=param_name)
    except exception.NotFound:
        return None


def _emc_vnx_format_address_name_db(name, network_type):
    hostname = 'controller-emc-vnx-' + name.replace('_', '-')
    return cutils.format_address_name(hostname, network_type)


def _emc_vnx_get_address_db(address_name, network_type=None,
                            control_network=True):
    if network_type:
        network_types = [network_type]
    elif control_network:
        network_types = EMC_VNX_CONTROL_NETWORK_TYPES
    else:
        network_types = EMC_VNX_DATA_NETWORK_TYPES

    for n in network_types:
        address_name_db = _emc_vnx_format_address_name_db(address_name, n)
        try:
            address_db = pecan.request.dbapi.address_get_by_name(
                address_name_db)
            return address_db, n
        except exception.AddressNotFoundByName:
            pass
    return None, None


def _emc_vnx_db_destroy_address(address_db):
    if address_db:
        try:
            pecan.request.dbapi.address_destroy(address_db.uuid)
        except exception.AddressNotFound:
            msg = _("Unable to apply service parameters. "
                    "Cannot destroy address '%s'" % address_db.address)
            raise wsme.exc.ClientSideError(msg)


def _emc_vnx_save_address_from_param(address_param_name, network_type, pool):
    ip_db_name = _emc_vnx_format_address_name_db(address_param_name,
                                                 network_type)

    # Now save the new IP address
    ip_param = _emc_vnx_get_param_from_name(address_param_name)
    if ip_param:
        try:
            address = {'address': ip_param.value,
                       'prefix': pool['prefix'],
                       'family': pool['family'],
                       'enable_dad': constants.IP_DAD_STATES[pool['family']],
                       'address_pool_id': pool['id'],
                       'interface_id': None,
                       'name': ip_db_name}
            pecan.request.dbapi.address_create(address)
        except exception.AddressNotFound:
            msg = _("Unable to apply service parameters. "
                    "Unable to save address '%s' ('%s') into "
                    "pool '%s'" % (address_param_name, ip_param.value,
                        pool['name']))
            raise wsme.exc.ClientSideError(msg)


def _emc_vnx_destroy_data_san_address(data_san_addr_param, data_san_db):
    if data_san_db:
        try:
            pecan.request.dbapi.address_destroy(data_san_db.uuid)
        except exception.AddressNotFound:
            msg = _("Unable to apply service parameters. "
                    "Cannot destroy address '%s'" % data_san_db.uuid)
            raise wsme.exc.ClientSideError(msg)

    if data_san_addr_param:
        try:
            pecan.request.dbapi.service_parameter_destroy_uuid(
                data_san_addr_param.uuid)
        except exception.NotFound:
            msg = _("Unable to apply service parameters. "
                    "Cannot delete the service parameter "
                    "data-san-ip '%s'" % data_san_addr_param.uuid)
            raise wsme.exc.ClientSideError(msg)


def _validate_worker_boot_timeout(name, value):
    _validate_range(name, value,
                    SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT_MIN,
                    SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT_MAX)


def _validate_controller_boot_timeout(name, value):
    _validate_range(name, value,
                    SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT_MIN,
                    SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT_MAX)


def _validate_hbs_period(name, value):
    _validate_range(name, value,
                    SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD_MIN,
                    SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD_MAX)


def _validate_hbs_failure_action(name, value):
    error = False
    try:
        if str(value) != SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_FAIL and \
                str(value) != SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_DEGRADE and \
                str(value) != SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_ALARM and \
                str(value) != SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_NONE:
            error = True

    except ValueError:
        error = True

    if error is True:
        raise wsme.exc.ClientSideError(_(
            "Action must be one of '%s', '%s', '%s' or '%s'" %
            (SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_FAIL,
             SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_DEGRADE,
             SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_ALARM,
             SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_NONE)))


def _validate_hbs_failure_threshold(name, value):
    _validate_range(name, value,
                    SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD_MIN,
                    SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD_MAX)


def _validate_hbs_degrade_threshold(name, value):
    _validate_range(name, value,
                    SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD_MIN,
                    SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD_MAX)


def _validate_mnfa_threshold(name, value):
    _validate_range(name, value,
                    SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD_MIN,
                    SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD_MAX)


def _validate_mnfa_timeout(name, value):
    # accept zero (no timeout) or a reasonable/tested specific range
    _validate_zero_or_range(name, value,
                    SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT_MIN,
                    SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT_MAX)


# Validate range of Performance Monitoring Event 'time to live" value
def _validate_event_time_to_live_range(name, value):
    _validate_range(name, value,
                    SERVICE_PARAM_NAME_PANKO_DATABASE_EVENT_TIME_TO_LIVE_MIN,
                    SERVICE_PARAM_NAME_PANKO_DATABASE_EVENT_TIME_TO_LIVE_MAX)


# Validate range of Alarm History 'time to live' value
def _validate_alarm_history_time_to_live_range(name, value):
    _validate_range(name, value,
                    SERVICE_PARAM_NAME_AODH_DATABASE_ALARM_HISTORY_TIME_TO_LIVE_MIN,
                    SERVICE_PARAM_NAME_AODH_DATABASE_ALARM_HISTORY_TIME_TO_LIVE_MAX)


def _validate_ipv4(name, value):
    """Check if router_id value is valid"""
    if not netaddr.valid_ipv4(value):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a valid router_id." % name))


def _validate_mac_address(name, value):
    """Check if a given value is a valid MAC address."""
    try:
        if not netaddr.valid_mac(value):
            raise wsme.exc.ClientSideError(_(
                "Parameter '%s' must be a valid MAC address" % name))
        if not int(netaddr.EUI(value).oui):
            raise wsme.exc.ClientSideError(_(
                "Parameter '%s' must be a MAC address with a non-zero OUI" %
                name))
    except netaddr.core.NotRegisteredError:
        pass  # allow any OUI value regardless of registration


def _rpm_pkg_is_installed(pkg_name):
    ts = rpm.TransactionSet()
    mi = ts.dbMatch()
    mi.pattern('name', rpm.RPMMIRE_GLOB, pkg_name)
    sum = 0
    for h in mi:
        sum += 1
    return (sum > 0)


def _validate_swift_enabled(name, value):
    _validate_boolean(name, value)
    if not value:
        return
    dbapi = db_api.get_instance()
    ceph_backend = StorageBackendConfig.get_backend_conf(
        dbapi, constants.CINDER_BACKEND_CEPH)
    if ceph_backend and ceph_backend.object_gateway:
        raise wsme.exc.ClientSideError(_(
            "Swift API is already supported by Ceph Object Gateway."))


def _validate_docker_proxy_address(name, value):
    """Check if proxy value is valid"""
    if not cutils.is_url(value):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a valid address." % name))


def _validate_docker_no_proxy_address(name, value):
    """Check if no proxy value is valid"""
    values = value.split(',')
    for item in values:
        # will extend to more cases if CIDR notation is supported
        if not cutils.is_valid_domain(item):
            if not cutils.is_valid_ip(item):
                raise wsme.exc.ClientSideError(_(
                    "Parameter '%s' includes an invalid address '%s'." %
                    (name, item)))


# LDAP Identity Service Parameters (mandatory)
SERVICE_PARAM_IDENTITY_LDAP_URL = 'url'

IDENTITY_ASSIGNMENT_PARAMETER_MANDATORY = [
    'driver'
]

IDENTITY_IDENTITY_PARAMETER_MANDATORY = [
    'driver'
]

# LDAP Identity Service Parameters (optional)
IDENTITY_LDAP_PARAMETER_OPTIONAL = [
    'url', 'user', 'password', 'suffix',
    'user_tree_dn', 'user_objectclass',
    'use_dumb_member', 'dumb_member',
    'query_scope', 'page_size', 'debug_level',

    'user_filter', 'user_id_attribute',
    'user_name_attribute', 'user_mail_attribute',
    'user_enabled_attribute', 'user_enabled_mask',
    'user_enabled_default', 'user_enabled_invert',
    'user_attribute_ignore',
    'user_default_project_id_attribute',
    'user_allow_create', 'user_allow_update', 'user_allow_delete',
    'user_pass_attribute', 'user_enabled_emulation',
    'user_enabled_emulation_dn',
    'user_additional_attribute_mapping',

    'group_tree_dn', 'group_filter',
    'group_objectclass', 'group_id_attribute',
    'group_name_attribute', 'group_member_attribute',
    'group_desc_attribute', 'group_attribute_ignore',
    'group_allow_create', 'group_allow_update', 'group_allow_delete',
    'group_additional_attribute_mapping',

    'use_tls', 'tls_cacertdir',
    'tls_cacertfile', 'tls_req_cert',

    'use_pool', 'pool_size',
    'pool_retry_max', 'pool_retry_delay',
    'pool_connection_timeout', 'pool_connection_lifetime',
    'use_auth_pool', 'auth_pool_size',
    'auth_pool_connection_lifetime',
]

# obfuscate these fields on list/show operations
IDENTITY_LDAP_PROTECTED_PARAMETERS = ['password']

IDENTITY_IDENTITY_PARAMETER_DATA_FORMAT = {
    constants.SERVICE_PARAM_IDENTITY_DRIVER: SERVICE_PARAMETER_DATA_FORMAT_SKIP,
}

NETWORK_ODL_PROTECTED_PARAMETERS = [constants.SERVICE_PARAM_NAME_ML2_ODL_PASSWORD]

IDENTITY_ADMIN_ENDPOINT_TYPE_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_PARAMETER_NAME_EXTERNAL_ADMINURL,
]

MURANO_ENGINE_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_MURANO_DISABLE_AGENT,
]

MURANO_ENGINE_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_MURANO_DISABLE_AGENT: _validate_boolean,
}

MURANO_ENGINE_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_MURANO_DISABLE_AGENT: 'openstack::murano::params::disable_murano_agent',
}

MURANO_RABBITMQ_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_MURANO_SSL,
]

MURANO_RABBITMQ_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_MURANO_SSL: _validate_boolean,
}

MURANO_RABBITMQ_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_MURANO_SSL: 'openstack::murano::params::ssl',
}

IRONIC_NEUTRON_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_IRONIC_PROVISIONING_NETWORK,
]

IRONIC_NEUTRON_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_IRONIC_PROVISIONING_NETWORK: _validate_not_empty,
}

IRONIC_NEUTRON_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_IRONIC_PROVISIONING_NETWORK:
        'openstack::ironic::params::provisioning_network',
}

IRONIC_PXE_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_IRONIC_TFTP_SERVER,
    constants.SERVICE_PARAM_NAME_IRONIC_CONTROLLER_0_NIC,
    constants.SERVICE_PARAM_NAME_IRONIC_CONTROLLER_1_NIC,
    constants.SERVICE_PARAM_NAME_IRONIC_NETMASK,
]

IRONIC_PXE_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_IRONIC_TFTP_SERVER: _validate_ip_address,
    constants.SERVICE_PARAM_NAME_IRONIC_CONTROLLER_0_NIC: _validate_not_empty,
    constants.SERVICE_PARAM_NAME_IRONIC_CONTROLLER_1_NIC: _validate_not_empty,
    constants.SERVICE_PARAM_NAME_IRONIC_NETMASK: _validate_integer,
}

IRONIC_PXE_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_IRONIC_TFTP_SERVER:
        'openstack::ironic::params::tftp_server',
    constants.SERVICE_PARAM_NAME_IRONIC_CONTROLLER_0_NIC:
        'openstack::ironic::params::controller_0_if',
    constants.SERVICE_PARAM_NAME_IRONIC_CONTROLLER_1_NIC:
        'openstack::ironic::params::controller_1_if',
    constants.SERVICE_PARAM_NAME_IRONIC_NETMASK:
        'openstack::ironic::params::netmask',
}

NOVA_PCI_ALIAS_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU_PF,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU_VF,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_DH895XCC_PF,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_DH895XCC_VF,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_C62X_PF,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_C62X_VF,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_USER,
]

NOVA_PCI_ALIAS_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU: _validate_pci_alias,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU_PF: _validate_pci_alias,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU_VF: _validate_pci_alias,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_DH895XCC_PF: _validate_pci_alias,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_DH895XCC_VF: _validate_pci_alias,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_C62X_PF: _validate_pci_alias,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_C62X_VF: _validate_pci_alias,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_USER: _validate_pci_alias,
}

NOVA_PCI_ALIAS_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU: 'openstack::nova::params::pci_alias',
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU_PF: 'openstack::nova::params::pci_alias',
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU_VF: 'openstack::nova::params::pci_alias',
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_DH895XCC_PF: 'openstack::nova::params::pci_alias',
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_DH895XCC_VF: 'openstack::nova::params::pci_alias',
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_C62X_PF: 'openstack::nova::params::pci_alias',
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_C62X_VF: 'openstack::nova::params::pci_alias',
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_USER: 'openstack::nova::params::pci_alias',
}

NOVA_PCI_ALIAS_PARAMETER_DATA_FORMAT = {
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU: SERVICE_PARAMETER_DATA_FORMAT_SKIP,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU_PF: SERVICE_PARAMETER_DATA_FORMAT_SKIP,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU_VF: SERVICE_PARAMETER_DATA_FORMAT_SKIP,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_DH895XCC_PF: SERVICE_PARAMETER_DATA_FORMAT_SKIP,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_DH895XCC_VF: SERVICE_PARAMETER_DATA_FORMAT_SKIP,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_C62X_PF: SERVICE_PARAMETER_DATA_FORMAT_SKIP,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_C62X_VF: SERVICE_PARAMETER_DATA_FORMAT_SKIP,
    constants.SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_USER: SERVICE_PARAMETER_DATA_FORMAT_SKIP,
}

IDENTITY_CONFIG_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_IDENTITY_CONFIG_TOKEN_EXPIRATION,
]


# LDAP Identity Service Parameters Validator
IDENTITY_LDAP_PARAMETER_VALIDATOR = {
    'url': _validate_ldap_url,
    'use_dumb_member': _validate_boolean,
    'user_enabled_invert': _validate_boolean,
    'user_enabled_emulation': _validate_boolean,
    'user_allow_create': _validate_boolean,
    'user_allow_update': _validate_boolean,
    'user_allow_delete': _validate_boolean,
    'group_allow_create': _validate_boolean,
    'group_allow_update': _validate_boolean,
    'group_allow_delete': _validate_boolean,
    'use_tls': _validate_boolean,
    'use_pool': _validate_boolean,
    'pool_size': _validate_integer,
    'pool_retry_max': _validate_integer,
    'pool_retry_delay': _validate_float,
    'pool_connection_timeout': _validate_integer,
    'pool_connection_lifetime': _validate_integer,
    'use_auth_pool': _validate_boolean,
    'auth_pool_size': _validate_integer,
    'auth_pool_connection_lifetime': _validate_integer,
    'user': _validate_ldap_dn,
    'suffix': _validate_ldap_dn,
    'dumb_member': _validate_ldap_dn,
    'user_tree_dn': _validate_ldap_dn,
    'user_enabled_emulation_dn': _validate_ldap_dn,
}

IDENTITY_LDAP_PARAMETER_RESOURCE = {
    'url': None,
    'use_dumb_member': None,
    'user_enabled_invert': None,
    'user_enabled_emulation': None,
    'user_allow_create': None,
    'user_allow_update': None,
    'user_allow_delete': None,
    'group_allow_create': None,
    'group_allow_update': None,
    'group_allow_delete': None,
    'use_tls': None,
    'use_pool': None,
    'pool_size': None,
    'pool_retry_max': None,
    'pool_retry_delay': None,
    'pool_connection_timeout': None,
    'pool_connection_lifetime': None,
    'use_auth_pool': None,
    'auth_pool_size': None,
    'auth_pool_connection_lifetime': None,
    'user': None,
    'suffix': None,
    'dumb_member': None,
    'user_tree_dn': None,
    'user_enabled_emulation_dn': None,
}

IDENTITY_ASSIGNMENT_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_ASSIGNMENT_DRIVER: _validate_assignment_driver,
}

IDENTITY_ASSIGNMENT_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_ASSIGNMENT_DRIVER: None,
}

IDENTITY_IDENTITY_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_IDENTITY_DRIVER: _validate_identity_driver,
}

IDENTITY_IDENTITY_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_IDENTITY_DRIVER: 'keystone::ldap::identity_driver',
}

IDENTITY_ADMIN_ENDPOINT_TYPE_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_PARAMETER_NAME_EXTERNAL_ADMINURL: cutils.validate_yes_no,
}

IDENTITY_ADMIN_ENDPOINT_TYPE_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_PARAMETER_NAME_EXTERNAL_ADMINURL: None,
}

IDENTITY_CONFIG_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_IDENTITY_CONFIG_TOKEN_EXPIRATION:
        _validate_token_expiry_time,
}

IDENTITY_CONFIG_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_IDENTITY_CONFIG_TOKEN_EXPIRATION: 'openstack::keystone::params::token_expiration',
}

HORIZON_AUTH_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_HORIZON_AUTH_LOCKOUT_PERIOD_SEC,
    constants.SERVICE_PARAM_HORIZON_AUTH_LOCKOUT_RETRIES,
]

HORIZON_AUTH_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_HORIZON_AUTH_LOCKOUT_PERIOD_SEC: _validate_integer,
    constants.SERVICE_PARAM_HORIZON_AUTH_LOCKOUT_RETRIES: _validate_integer,
}

HORIZON_AUTH_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_HORIZON_AUTH_LOCKOUT_PERIOD_SEC: 'openstack::horizon::params::lockout_period',
    constants.SERVICE_PARAM_HORIZON_AUTH_LOCKOUT_RETRIES: 'openstack::horizon::params::lockout_retries',
}

# Neutron Service Parameters (optional)
NEUTRON_ML2_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_ML2_MECHANISM_DRIVERS,
    constants.SERVICE_PARAM_NAME_ML2_EXTENSION_DRIVERS,
    constants.SERVICE_PARAM_NAME_ML2_TENANT_NETWORK_TYPES,
]

NEUTRON_ML2_ODL_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_ML2_ODL_URL,
    constants.SERVICE_PARAM_NAME_ML2_ODL_USERNAME,
    constants.SERVICE_PARAM_NAME_ML2_ODL_PASSWORD,
    constants.SERVICE_PARAM_NAME_ML2_PORT_BINDING_CONTROLLER,
]

NETWORK_BGP_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_BGP_ROUTER_ID_C0,
    constants.SERVICE_PARAM_NAME_BGP_ROUTER_ID_C1,
]

NETWORK_SFC_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_SFC_QUOTA_FLOW_CLASSIFIER,
    constants.SERVICE_PARAM_NAME_SFC_QUOTA_PORT_CHAIN,
    constants.SERVICE_PARAM_NAME_SFC_QUOTA_PORT_PAIR_GROUP,
    constants.SERVICE_PARAM_NAME_SFC_QUOTA_PORT_PAIR,
    constants.SERVICE_PARAM_NAME_SFC_SFC_DRIVERS,
    constants.SERVICE_PARAM_NAME_SFC_FLOW_CLASSIFIER_DRIVERS,
]

NETWORK_DHCP_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_DHCP_FORCE_METADATA,
]

NETWORK_DEFAULT_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_DEFAULT_SERVICE_PLUGINS,
    constants.SERVICE_PARAM_NAME_DEFAULT_DNS_DOMAIN,
    constants.SERVICE_PARAM_NAME_BASE_MAC,
    constants.SERVICE_PARAM_NAME_DVR_BASE_MAC,
]

NEUTRON_ML2_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_ML2_MECHANISM_DRIVERS:
        _validate_neutron_ml2_mech,
    constants.SERVICE_PARAM_NAME_ML2_EXTENSION_DRIVERS:
        _validate_neutron_ml2_ext,
    constants.SERVICE_PARAM_NAME_ML2_TENANT_NETWORK_TYPES:
        _validate_neutron_network_types,
}

NEUTRON_ML2_ODL_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_ML2_ODL_URL:
        _validate_odl_connection_uri,
    constants.SERVICE_PARAM_NAME_ML2_ODL_USERNAME:
        _validate_not_empty,
    constants.SERVICE_PARAM_NAME_ML2_ODL_PASSWORD:
        _validate_not_empty,
    constants.SERVICE_PARAM_NAME_ML2_PORT_BINDING_CONTROLLER:
        _validate_not_empty,
}

NETWORK_BGP_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_BGP_ROUTER_ID_C0:
        _validate_ipv4,
    constants.SERVICE_PARAM_NAME_BGP_ROUTER_ID_C1:
        _validate_ipv4,
}

NETWORK_SFC_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_SFC_QUOTA_FLOW_CLASSIFIER:
        _validate_integer,
    constants.SERVICE_PARAM_NAME_SFC_QUOTA_PORT_CHAIN:
        _validate_integer,
    constants.SERVICE_PARAM_NAME_SFC_QUOTA_PORT_PAIR_GROUP:
        _validate_integer,
    constants.SERVICE_PARAM_NAME_SFC_QUOTA_PORT_PAIR:
        _validate_integer,
    constants.SERVICE_PARAM_NAME_SFC_SFC_DRIVERS:
        _validate_not_empty,
    constants.SERVICE_PARAM_NAME_SFC_FLOW_CLASSIFIER_DRIVERS:
        _validate_not_empty,
}

NETWORK_DHCP_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_DHCP_FORCE_METADATA:
        _validate_boolean
}

NETWORK_DEFAULT_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_DEFAULT_SERVICE_PLUGINS:
        _validate_neutron_service_plugins,
    constants.SERVICE_PARAM_NAME_DEFAULT_DNS_DOMAIN:
        _validate_not_empty,
    constants.SERVICE_PARAM_NAME_BASE_MAC:
        _validate_mac_address,
    constants.SERVICE_PARAM_NAME_DVR_BASE_MAC:
        _validate_mac_address,
}

NEUTRON_ML2_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_ML2_MECHANISM_DRIVERS: 'neutron::plugins::ml2::mechanism_drivers',
    constants.SERVICE_PARAM_NAME_ML2_EXTENSION_DRIVERS: 'neutron::plugins::ml2::extension_drivers',
    constants.SERVICE_PARAM_NAME_ML2_TENANT_NETWORK_TYPES: 'neutron::plugins::ml2::tenant_network_types',
}

NEUTRON_ML2_ODL_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_ML2_ODL_URL: 'openstack::neutron::odl::params::url',
    constants.SERVICE_PARAM_NAME_ML2_ODL_USERNAME: 'openstack::neutron::odl::params::username',
    constants.SERVICE_PARAM_NAME_ML2_ODL_PASSWORD: 'openstack::neutron::odl::params::password',
    constants.SERVICE_PARAM_NAME_ML2_PORT_BINDING_CONTROLLER: 'openstack::neutron::odl::params::port_binding_controller',
}

NETWORK_BGP_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_BGP_ROUTER_ID_C0: 'openstack::neutron::params::bgp_router_id',
    constants.SERVICE_PARAM_NAME_BGP_ROUTER_ID_C1: 'openstack::neutron::params::bgp_router_id',
}

NETWORK_DHCP_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_DHCP_FORCE_METADATA: 'neutron::agents::dhcp::enable_force_metadata',
}

NETWORK_BGP_PARAMETER_DATA_FORMAT = {
    constants.SERVICE_PARAM_NAME_BGP_ROUTER_ID_C0: SERVICE_PARAMETER_DATA_FORMAT_SKIP,
    constants.SERVICE_PARAM_NAME_BGP_ROUTER_ID_C1: SERVICE_PARAMETER_DATA_FORMAT_SKIP,
}

NETWORK_SFC_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_SFC_QUOTA_FLOW_CLASSIFIER: 'openstack::neutron::sfc::sfc_quota_flow_classifier',
    constants.SERVICE_PARAM_NAME_SFC_QUOTA_PORT_CHAIN: 'openstack::neutron::sfc::sfc_quota_port_chain',
    constants.SERVICE_PARAM_NAME_SFC_QUOTA_PORT_PAIR_GROUP: 'openstack::neutron::sfc::sfc_quota_port_pair_group',
    constants.SERVICE_PARAM_NAME_SFC_QUOTA_PORT_PAIR: 'openstack::neutron::sfc::sfc_quota_port_pair',
    constants.SERVICE_PARAM_NAME_SFC_SFC_DRIVERS: 'openstack::neutron::sfc::sfc_drivers',
    constants.SERVICE_PARAM_NAME_SFC_FLOW_CLASSIFIER_DRIVERS: 'openstack::neutron::sfc::flowclassifier_drivers',
}

NETWORK_DHCP_PARAMETER_DATA_FORMAT = {
    constants.SERVICE_PARAM_NAME_DHCP_FORCE_METADATA: SERVICE_PARAMETER_DATA_FORMAT_BOOLEAN
}

NETWORK_DEFAULT_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_DEFAULT_SERVICE_PLUGINS: 'neutron::service_plugins',
    constants.SERVICE_PARAM_NAME_DEFAULT_DNS_DOMAIN: 'neutron::dns_domain',
    constants.SERVICE_PARAM_NAME_BASE_MAC: 'neutron::base_mac',
    constants.SERVICE_PARAM_NAME_DVR_BASE_MAC: 'neutron::dvr_base_mac',
}

NETWORK_DEFAULT_PARAMETER_DATA_FORMAT = {
    constants.SERVICE_PARAM_NAME_DEFAULT_SERVICE_PLUGINS: SERVICE_PARAMETER_DATA_FORMAT_ARRAY,
}


#
# Cinder DEFAULT service parameters
#

CINDER_DEFAULT_PARAMETER_MANDATORY = [
]

CINDER_DEFAULT_PARAMETER_PROTECTED = []

# If the lists:
#
#   * CINDER_DEFAULT_PARAMETER_PROTECTED
#   * CINDER_DEFAULT_PARAMETER_REQUIRED
#   * CINDER_DEFAULT_PARAMETER_OPTIONAL
#
# are changed, we must update the
# SP_CINDER_DEFAULT_ALL_SUPPORTTED_PARAMS list in
# packstack/plugins/cinder_250.py.

CINDER_DEFAULT_PARAMETER_REQUIRED = []

CINDER_DEFAULT_PARAMETER_OPTIONAL = (
    CINDER_DEFAULT_PARAMETER_REQUIRED +
    CINDER_DEFAULT_PARAMETER_PROTECTED + [
        constants.SERVICE_PARAM_CINDER_DEFAULT_VOLUME_TYPE,
        constants.SERVICE_PARAM_CINDER_DEFAULT_MULTIPATH,
    ]
)

CINDER_DEFAULT_PARAMETER_VALIDATOR = {
    # Mandatory parameters
    # Required parameters
    # Optional parameters
    constants.SERVICE_PARAM_CINDER_DEFAULT_VOLUME_TYPE: _validate_not_empty,
    constants.SERVICE_PARAM_CINDER_DEFAULT_MULTIPATH: _validate_boolean,
}

CINDER_DEFAULT_PARAMETER_RESOURCE = {
    # Mandatory parameters
    # Required parameters
    # Optional parameters
    constants.SERVICE_PARAM_CINDER_DEFAULT_VOLUME_TYPE: None,
    constants.SERVICE_PARAM_CINDER_DEFAULT_MULTIPATH: None,
}

CINDER_EMC_VNX_SAN_IP = 'san_ip'
CINDER_EMC_VNX_SAN_SECONDARY_IP = 'san_secondary_ip'
CINDER_EMC_VNX_DATA_SAN_IP = 'data_san_ip'
CINDER_EMC_VNX_CONTROL_NETWORK = 'control_network'
CINDER_EMC_VNX_DATA_NETWORK = 'data_network'

# Cinder emc_vnx Service Parameters
CINDER_EMC_VNX_PARAMETER_MANDATORY = [
    constants.SERVICE_PARAM_CINDER_EMC_VNX_ENABLED,
]

# If the list CINDER_EMC_VNX_PARAMETER_PROTECTED,
# CINDER_EMC_VNX_PARAMETER_REQUIRED_ON_FEATURE_ENABLED,
# and CINDER_EMC_VNX_PARAMETER_OPTIONAL are changed.  We must
# update the SP_CINDER_EMC_VNX_ALL_SUPPORTTED_PARAMS list in
# packstack/plugins/cinder_250.py as well.

CINDER_EMC_VNX_PARAMETER_REQUIRED_ON_FEATURE_ENABLED = [
    CINDER_EMC_VNX_CONTROL_NETWORK, CINDER_EMC_VNX_DATA_NETWORK,
    CINDER_EMC_VNX_SAN_IP,
]

CINDER_EMC_VNX_PARAMETER_PROTECTED = [
    'san_login', 'san_password',
]

CINDER_EMC_VNX_PARAMETER_OPTIONAL = (
    CINDER_EMC_VNX_PARAMETER_REQUIRED_ON_FEATURE_ENABLED +
    CINDER_EMC_VNX_PARAMETER_PROTECTED + [
        'storage_vnx_pool_names', 'storage_vnx_security_file_dir',
        CINDER_EMC_VNX_SAN_SECONDARY_IP, 'iscsi_initiators',
        'storage_vnx_authentication_type', 'initiator_auto_deregistration',
        'default_timeout', 'ignore_pool_full_threshold',
        'max_luns_per_storage_group', 'destroy_empty_storage_group',
        'force_delete_lun_in_storagegroup', 'io_port_list',
        'check_max_pool_luns_threshold',
        CINDER_EMC_VNX_DATA_SAN_IP,
    ]
)

CINDER_EMC_VNX_PARAMETER_VALIDATOR = {
    # Mandatory parameters
    constants.SERVICE_PARAM_CINDER_EMC_VNX_ENABLED:
        _validate_boolean,
    # Required parameters
    'san_ip': _validate_ip_address,
    # Optional parameters
    'storage_vnx_pool_names': _validate_not_empty,
    'san_login': _validate_not_empty,
    'san_password': _validate_not_empty,
    'storage_vnx_security_file_dir':
        _validate_emc_vnx_storage_vnx_security_file_dir,
    'san_secondary_ip': _validate_ip_address,
    'iscsi_initiators': _validate_emc_vnx_iscsi_initiators,
    'storage_vnx_authentication_type':
        _validate_emc_vnx_storage_vnx_authentication_type,
    'initiator_auto_deregistration': _validate_boolean,
    'default_timeout': _validate_integer,
    'ignore_pool_full_threshold': _validate_boolean,
    'max_luns_per_storage_group': _validate_integer,
    'destroy_empty_storage_group': _validate_boolean,
    'force_delete_lun_in_storagegroup': _validate_boolean,
    'io_port_list': _validate_not_empty,
    'check_max_pool_luns_threshold': _validate_boolean,
    'control_network': _validate_emc_vnx_control_network_type,
    'data_network': _validate_emc_vnx_data_network_type,
    'data_san_ip': _validate_read_only,
}

CINDER_EMC_VNX_PARAMETER_RESOURCE = {
    # Mandatory parameters
    constants.SERVICE_PARAM_CINDER_EMC_VNX_ENABLED: None,
    # Required parameters
    'san_ip': None,
    # Optional parameters
    'storage_vnx_pool_names': None,
    'san_login': None,
    'san_password': None,
    'storage_vnx_security_file_dir': None,
    'san_secondary_ip': None,
    'iscsi_initiators': None,
    'storage_vnx_authentication_type': None,
    'initiator_auto_deregistration': None,
    'default_timeout': None,
    'ignore_pool_full_threshold': None,
    'max_luns_per_storage_group': None,
    'destroy_empty_storage_group': None,
    'force_delete_lun_in_storagegroup': None,
    'io_port_list': None,
    'check_max_pool_luns_threshold': None,
    'control_network': None,
    'data_network': None,
    'data_san_ip': None,
}

HPE_DATA_NETWORKS = [
    constants.NETWORK_TYPE_INFRA,
    constants.NETWORK_TYPE_MGMT,
]

#
# Cinder HPE3PAR Service Parameters
#

CINDER_HPE3PAR_PARAMETER_MANDATORY = [
    constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_ENABLED,
]

CINDER_HPE3PAR_PARAMETER_PROTECTED = [
    'san_login', 'san_password',
]

# If the lists:
#
#   * CINDER_HPE3PAR_PARAMETER_PROTECTED
#   * CINDER_HPE3PAR_PARAMETER_REQUIRED
#   * CINDER_HPE3PAR_PARAMETER_OPTIONAL
#
# are changed, we must update the
# SP_CINDER_HPE3PAR_ALL_SUPPORTTED_PARAMS list in
# packstack/plugins/cinder_250.py.

CINDER_HPE3PAR_PARAMETER_REQUIRED = [
    'hpe3par_api_url', 'hpe3par_username', 'hpe3par_password',
    'hpe3par_cpg', 'hpe3par_cpg_snap', 'hpe3par_snapshot_expiration',
    'hpe3par_iscsi_ips'
]

CINDER_HPE3PAR_PARAMETER_OPTIONAL = (
    CINDER_HPE3PAR_PARAMETER_REQUIRED +
    CINDER_HPE3PAR_PARAMETER_PROTECTED + [
        'hpe3par_debug', 'hpe3par_iscsi_chap_enabled',
        'san_ip'
    ]
)

CINDER_HPE3PAR_PARAMETER_VALIDATOR = {
    # Mandatory parameters
    constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_ENABLED: _validate_boolean,
    # Required parameters
    'hpe3par_api_url': _validate_hpe_api_url,
    'hpe3par_username': _validate_not_empty,
    'hpe3par_password': _validate_not_empty,
    'hpe3par_cpg': _validate_not_empty,
    'hpe3par_cpg_snap': _validate_not_empty,
    'hpe3par_snapshot_expiration': _validate_integer,
    'hpe3par_iscsi_ips': _validate_hpe3par_iscsi_ips,
    # Optional parameters
    'hpe3par_debug': _validate_boolean,
    'hpe3par_scsi_chap_enabled': _validate_boolean,
    'san_login': _validate_not_empty,
    'san_password': _validate_not_empty,
    'san_ip': _validate_ip_address,
}

CINDER_HPE3PAR_PARAMETER_RESOURCE = {
    # Mandatory parameters
    constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_ENABLED: None,
    # Required parameters
    'hpe3par_api_url': None,
    'hpe3par_username': None,
    'hpe3par_password': None,
    'hpe3par_cpg': None,
    'hpe3par_cpg_snap': None,
    'hpe3par_snapshot_expiration': None,
    'hpe3par_iscsi_ips': None,
    # Optional parameters
    'hpe3par_debug': None,
    'hpe3par_scsi_chap_enabled': None,
    'san_login': None,
    'san_password': None,
    'san_ip': None,
}

#
# Cinder HPELEFTHAND Service Parameters
#

CINDER_HPELEFTHAND_PARAMETER_MANDATORY = [
    constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_ENABLED,
]

CINDER_HPELEFTHAND_PARAMETER_PROTECTED = []

# If the lists:
#
#   * CINDER_HPELEFTHAND_PARAMETER_PROTECTED
#   * CINDER_HPELEFTHAND_PARAMETER_REQUIRED
#   * CINDER_HPELEFTHAND_PARAMETER_OPTIONAL
#
# are changed, we must update the
# SP_CINDER_HPELEFTHAND_ALL_SUPPORTTED_PARAMS list in
# packstack/plugins/cinder_250.py.

CINDER_HPELEFTHAND_PARAMETER_REQUIRED = [
    'hpelefthand_api_url', 'hpelefthand_username', 'hpelefthand_password',
    'hpelefthand_clustername'
]

CINDER_HPELEFTHAND_PARAMETER_OPTIONAL = (
    CINDER_HPELEFTHAND_PARAMETER_REQUIRED +
    CINDER_HPELEFTHAND_PARAMETER_PROTECTED + [
        'hpelefthand_debug', 'hpelefthand_ssh_port', 'hpelefthand_iscsi_chap_enabled'
    ]
)

CINDER_HPELEFTHAND_PARAMETER_VALIDATOR = {
    # Mandatory parameters
    constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_ENABLED: _validate_boolean,
    # Required parameters
    'hpelefthand_api_url': _validate_hpe_api_url,
    'hpelefthand_username': _validate_not_empty,
    'hpelefthand_password': _validate_not_empty,
    'hpelefthand_clustername': _validate_not_empty,
    # Optional parameters
    'hpelefthand_debug': _validate_boolean,
    'hpelefthand_ssh_port': _validate_integer,
    'hpelefthand_iscsi_chap_enabled': _validate_boolean
}

CINDER_HPELEFTHAND_PARAMETER_RESOURCE = {
    # Mandatory parameters
    constants.SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_ENABLED: None,
    # Required parameters
    'hpelefthand_api_url': None,
    'hpelefthand_username': None,
    'hpelefthand_password': None,
    'hpelefthand_clustername': None,
    # Optional parameters
    'hpelefthand_debug': None,
    'hpelefthand_ssh_port': None,
    'hpelefthand_iscsi_chap_enabled': None,
}

# Maintenance Service Parameters
PLATFORM_MTCE_PARAMETER_MANDATORY = [
    constants.SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT,
    constants.SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT,
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD,
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION,
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD,
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD,
    constants.SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD,
    constants.SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT,
]

PLATFORM_SYSINV_PARAMETER_PROTECTED = ['firewall_rules_id']

SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT_MIN = 720
SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT_MAX = 1800
SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT_MIN = 1200
SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT_MAX = 1800
SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD_MIN = 100
SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD_MAX = 1000
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD_MIN = 10
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD_MAX = 100
SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD_MIN = 4
SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD_MAX = 100
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_FAIL = 'fail'
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_DEGRADE = 'degrade'
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_ALARM = 'alarm'
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_NONE = 'none'
SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD_MIN = 2
SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD_MAX = 100
SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT_MIN = 100
SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT_MAX = 86400

PLATFORM_MTCE_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT:
        _validate_worker_boot_timeout,
    constants.SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT:
        _validate_controller_boot_timeout,
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD:
        _validate_hbs_period,
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION:
        _validate_hbs_failure_action,
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD:
        _validate_hbs_failure_threshold,
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD:
        _validate_hbs_degrade_threshold,
    constants.SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD:
        _validate_mnfa_threshold,
    constants.SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT:
        _validate_mnfa_timeout,
}

PLATFORM_MTCE_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT: 'platform::mtce::params::worker_boot_timeout',
    constants.SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT: 'platform::mtce::params::controller_boot_timeout',
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD: 'platform::mtce::params::heartbeat_period',
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION: 'platform::mtce::params::heartbeat_failure_action',
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD: 'platform::mtce::params::heartbeat_failure_threshold',
    constants.SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD: 'platform::mtce::params::heartbeat_degrade_threshold',
    constants.SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD: 'platform::mtce::params::mnfa_threshold',
    constants.SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT: 'platform::mtce::params::mnfa_timeout',
}

# Panko Event TTL range from 1 hour to 1 year
SERVICE_PARAM_NAME_PANKO_DATABASE_EVENT_TIME_TO_LIVE_MIN = 3600
SERVICE_PARAM_NAME_PANKO_DATABASE_EVENT_TIME_TO_LIVE_MAX = 31536000

# Panko Service Parameters
PANKO_PARAMETER_MANDATORY = [
    constants.SERVICE_PARAM_NAME_PANKO_DATABASE_EVENT_TIME_TO_LIVE,
]

PANKO_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_PANKO_DATABASE_EVENT_TIME_TO_LIVE:
        _validate_event_time_to_live_range,
}

PANKO_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_PANKO_DATABASE_EVENT_TIME_TO_LIVE:
        'openstack::panko::params::event_time_to_live',
}

# AODH Alarm History TTL range from 1 hour to 1 year
SERVICE_PARAM_NAME_AODH_DATABASE_ALARM_HISTORY_TIME_TO_LIVE_MIN = 3600
SERVICE_PARAM_NAME_AODH_DATABASE_ALARM_HISTORY_TIME_TO_LIVE_MAX = 31536000

# AODH Service Parameters
AODH_PARAMETER_MANDATORY = [
    constants.SERVICE_PARAM_NAME_AODH_DATABASE_ALARM_HISTORY_TIME_TO_LIVE,
]

AODH_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_AODH_DATABASE_ALARM_HISTORY_TIME_TO_LIVE:
        _validate_alarm_history_time_to_live_range,
}

AODH_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_AODH_DATABASE_ALARM_HISTORY_TIME_TO_LIVE:
        'aodh::alarm_history_time_to_live',
}

SWIFT_CONFIG_PARAMETER_MANDATORY = [
    constants.SERVICE_PARAM_NAME_SWIFT_SERVICE_ENABLED,
]

SWIFT_CONFIG_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_SWIFT_FS_SIZE_MB,
]

SWIFT_CONFIG_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_SWIFT_SERVICE_ENABLED: _validate_swift_enabled,
    constants.SERVICE_PARAM_NAME_SWIFT_FS_SIZE_MB: _validate_integer,
}

SWIFT_CONFIG_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_SWIFT_SERVICE_ENABLED:
        'openstack::swift::params::service_enabled',
    constants.SERVICE_PARAM_NAME_SWIFT_FS_SIZE_MB:
        'openstack::swift::params::fs_size_mb',
}

SWIFT_CONFIG_PARAMETER_DATA_FORMAT = {
    constants.SERVICE_PARAM_NAME_SWIFT_SERVICE_ENABLED: SERVICE_PARAMETER_DATA_FORMAT_BOOLEAN,
}

DOCKER_PROXY_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_DOCKER_HTTP_PROXY,
    constants.SERVICE_PARAM_NAME_DOCKER_HTTPS_PROXY,
    constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY,
]

DOCKER_PROXY_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_DOCKER_HTTP_PROXY: _validate_docker_proxy_address,
    constants.SERVICE_PARAM_NAME_DOCKER_HTTPS_PROXY: _validate_docker_proxy_address,
    constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY: _validate_docker_no_proxy_address,
}

DOCKER_PROXY_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_DOCKER_HTTP_PROXY:
        'platform::docker::params::http_proxy',
    constants.SERVICE_PARAM_NAME_DOCKER_HTTPS_PROXY:
        'platform::docker::params::https_proxy',
    constants.SERVICE_PARAM_NAME_DOCKER_NO_PROXY:
        'platform::docker::params::no_proxy',
}

# Service Parameter Schema
SERVICE_PARAM_MANDATORY = 'mandatory'
SERVICE_PARAM_OPTIONAL = 'optional'
SERVICE_PARAM_VALIDATOR = 'validator'
SERVICE_PARAM_RESOURCE = 'resource'
SERVICE_PARAM_DATA_FORMAT = 'format'

SERVICE_PARAM_PROTECTED = 'protected'
SERVICE_VALUE_PROTECTION_MASK = "****"

SERVICE_PARAMETER_SCHEMA = {
    constants.SERVICE_TYPE_CINDER: {
        constants.SERVICE_PARAM_SECTION_CINDER_DEFAULT: {
            SERVICE_PARAM_MANDATORY: CINDER_DEFAULT_PARAMETER_MANDATORY,
            SERVICE_PARAM_PROTECTED: CINDER_DEFAULT_PARAMETER_PROTECTED,
            SERVICE_PARAM_OPTIONAL: CINDER_DEFAULT_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: CINDER_DEFAULT_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: CINDER_DEFAULT_PARAMETER_RESOURCE,
        },

        constants.SERVICE_PARAM_SECTION_CINDER_EMC_VNX: {
            SERVICE_PARAM_MANDATORY: CINDER_EMC_VNX_PARAMETER_MANDATORY,
            SERVICE_PARAM_PROTECTED: CINDER_EMC_VNX_PARAMETER_PROTECTED,
            SERVICE_PARAM_OPTIONAL: CINDER_EMC_VNX_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: CINDER_EMC_VNX_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: CINDER_EMC_VNX_PARAMETER_RESOURCE,
        },

        constants.SERVICE_PARAM_SECTION_CINDER_HPE3PAR: {
            SERVICE_PARAM_MANDATORY: CINDER_HPE3PAR_PARAMETER_MANDATORY,
            SERVICE_PARAM_PROTECTED: CINDER_HPE3PAR_PARAMETER_PROTECTED,
            SERVICE_PARAM_OPTIONAL: CINDER_HPE3PAR_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: CINDER_HPE3PAR_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: CINDER_HPE3PAR_PARAMETER_RESOURCE,
        },

        constants.SERVICE_PARAM_SECTION_CINDER_HPELEFTHAND: {
            SERVICE_PARAM_MANDATORY: CINDER_HPELEFTHAND_PARAMETER_MANDATORY,
            SERVICE_PARAM_PROTECTED: CINDER_HPELEFTHAND_PARAMETER_PROTECTED,
            SERVICE_PARAM_OPTIONAL: CINDER_HPELEFTHAND_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: CINDER_HPELEFTHAND_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: CINDER_HPELEFTHAND_PARAMETER_RESOURCE,
        },
    },
    constants.SERVICE_TYPE_IDENTITY: {
        constants.SERVICE_PARAM_SECTION_IDENTITY_ASSIGNMENT: {
            SERVICE_PARAM_MANDATORY: IDENTITY_ASSIGNMENT_PARAMETER_MANDATORY,
            SERVICE_PARAM_VALIDATOR: IDENTITY_ASSIGNMENT_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: IDENTITY_ASSIGNMENT_PARAMETER_RESOURCE,
        },
        constants.SERVICE_PARAM_SECTION_IDENTITY_IDENTITY: {
            SERVICE_PARAM_MANDATORY: IDENTITY_IDENTITY_PARAMETER_MANDATORY,
            SERVICE_PARAM_VALIDATOR: IDENTITY_IDENTITY_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: IDENTITY_IDENTITY_PARAMETER_RESOURCE,
            SERVICE_PARAM_DATA_FORMAT: IDENTITY_IDENTITY_PARAMETER_DATA_FORMAT,
        },
        constants.SERVICE_PARAM_SECTION_IDENTITY_LDAP: {
            SERVICE_PARAM_OPTIONAL: IDENTITY_LDAP_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: IDENTITY_LDAP_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: IDENTITY_LDAP_PARAMETER_RESOURCE,
            SERVICE_PARAM_PROTECTED: IDENTITY_LDAP_PROTECTED_PARAMETERS,
        },
        constants.SERVICE_PARAM_SECTION_IDENTITY_CONFIG: {
            SERVICE_PARAM_OPTIONAL: IDENTITY_CONFIG_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: IDENTITY_CONFIG_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: IDENTITY_CONFIG_PARAMETER_RESOURCE,
        },
    },
    constants.SERVICE_TYPE_PLATFORM: {
        constants.SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE: {
            SERVICE_PARAM_MANDATORY: PLATFORM_MTCE_PARAMETER_MANDATORY,
            SERVICE_PARAM_VALIDATOR: PLATFORM_MTCE_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: PLATFORM_MTCE_PARAMETER_RESOURCE,
        },
        constants.SERVICE_PARAM_SECTION_PLATFORM_SYSINV: {
            SERVICE_PARAM_PROTECTED: PLATFORM_SYSINV_PARAMETER_PROTECTED,
        },
    },
    constants.SERVICE_TYPE_HORIZON: {
        constants.SERVICE_PARAM_SECTION_HORIZON_AUTH: {
            SERVICE_PARAM_OPTIONAL: HORIZON_AUTH_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: HORIZON_AUTH_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: HORIZON_AUTH_PARAMETER_RESOURCE,
        },
    },
    constants.SERVICE_TYPE_IRONIC: {
        constants.SERVICE_PARAM_SECTION_IRONIC_NEUTRON: {
            SERVICE_PARAM_OPTIONAL: IRONIC_NEUTRON_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: IRONIC_NEUTRON_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: IRONIC_NEUTRON_PARAMETER_RESOURCE,
        },
        constants.SERVICE_PARAM_SECTION_IRONIC_PXE: {
            SERVICE_PARAM_OPTIONAL: IRONIC_PXE_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: IRONIC_PXE_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: IRONIC_PXE_PARAMETER_RESOURCE,
        },
    },
    constants.SERVICE_TYPE_NETWORK: {
        constants.SERVICE_PARAM_SECTION_NETWORK_ML2: {
            SERVICE_PARAM_OPTIONAL: NEUTRON_ML2_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: NEUTRON_ML2_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: NEUTRON_ML2_PARAMETER_RESOURCE,
        },
        constants.SERVICE_PARAM_SECTION_NETWORK_ML2_ODL: {
            SERVICE_PARAM_OPTIONAL: NEUTRON_ML2_ODL_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: NEUTRON_ML2_ODL_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: NEUTRON_ML2_ODL_PARAMETER_RESOURCE,
            SERVICE_PARAM_PROTECTED: NETWORK_ODL_PROTECTED_PARAMETERS,
        },
        constants.SERVICE_PARAM_SECTION_NETWORK_BGP: {
            SERVICE_PARAM_OPTIONAL: NETWORK_BGP_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: NETWORK_BGP_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: NETWORK_BGP_PARAMETER_RESOURCE,
        },
        constants.SERVICE_PARAM_SECTION_NETWORK_SFC: {
            SERVICE_PARAM_OPTIONAL: NETWORK_SFC_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: NETWORK_SFC_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: NETWORK_SFC_PARAMETER_RESOURCE,
        },
        constants.SERVICE_PARAM_SECTION_NETWORK_DHCP: {
            SERVICE_PARAM_OPTIONAL: NETWORK_DHCP_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: NETWORK_DHCP_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: NETWORK_DHCP_PARAMETER_RESOURCE,
            SERVICE_PARAM_DATA_FORMAT: NETWORK_DHCP_PARAMETER_DATA_FORMAT,
        },
        constants.SERVICE_PARAM_SECTION_NETWORK_DEFAULT: {
            SERVICE_PARAM_OPTIONAL: NETWORK_DEFAULT_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: NETWORK_DEFAULT_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: NETWORK_DEFAULT_PARAMETER_RESOURCE,
            SERVICE_PARAM_DATA_FORMAT: NETWORK_DEFAULT_PARAMETER_DATA_FORMAT,
        },

    },
    constants.SERVICE_TYPE_MURANO: {
        constants.SERVICE_PARAM_SECTION_MURANO_ENGINE: {
            SERVICE_PARAM_OPTIONAL: MURANO_ENGINE_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: MURANO_ENGINE_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: MURANO_ENGINE_PARAMETER_RESOURCE,
        },
        constants.SERVICE_PARAM_SECTION_MURANO_RABBITMQ: {
            SERVICE_PARAM_OPTIONAL: MURANO_RABBITMQ_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: MURANO_RABBITMQ_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: MURANO_RABBITMQ_PARAMETER_RESOURCE,
        },
    },
    constants.SERVICE_TYPE_NOVA: {
        constants.SERVICE_PARAM_SECTION_NOVA_PCI_ALIAS: {
            SERVICE_PARAM_OPTIONAL: NOVA_PCI_ALIAS_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: NOVA_PCI_ALIAS_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: NOVA_PCI_ALIAS_PARAMETER_RESOURCE,
            SERVICE_PARAM_DATA_FORMAT: NOVA_PCI_ALIAS_PARAMETER_DATA_FORMAT,
        },
    },
    constants.SERVICE_TYPE_PANKO: {
        constants.SERVICE_PARAM_SECTION_PANKO_DATABASE: {
            SERVICE_PARAM_MANDATORY: PANKO_PARAMETER_MANDATORY,
            SERVICE_PARAM_VALIDATOR: PANKO_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: PANKO_PARAMETER_RESOURCE,
        },
    },
    constants.SERVICE_TYPE_AODH: {
        constants.SERVICE_PARAM_SECTION_AODH_DATABASE: {
            SERVICE_PARAM_MANDATORY: AODH_PARAMETER_MANDATORY,
            SERVICE_PARAM_VALIDATOR: AODH_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: AODH_PARAMETER_RESOURCE,
        },
    },
    constants.SERVICE_TYPE_SWIFT: {
        constants.SERVICE_PARAM_SECTION_SWIFT_CONFIG: {
            SERVICE_PARAM_MANDATORY: SWIFT_CONFIG_PARAMETER_MANDATORY,
            SERVICE_PARAM_OPTIONAL: SWIFT_CONFIG_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: SWIFT_CONFIG_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: SWIFT_CONFIG_PARAMETER_RESOURCE,
            SERVICE_PARAM_DATA_FORMAT: SWIFT_CONFIG_PARAMETER_DATA_FORMAT,
        },
    },
    constants.SERVICE_TYPE_DOCKER: {
        constants.SERVICE_PARAM_SECTION_DOCKER_PROXY: {
            SERVICE_PARAM_OPTIONAL: DOCKER_PROXY_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: DOCKER_PROXY_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: DOCKER_PROXY_PARAMETER_RESOURCE,
        },
    },
}

SERVICE_PARAMETER_MAX_LENGTH = 255


MANAGED_RESOURCES_MAP = None


def map_resource(resource_query):
    global MANAGED_RESOURCES_MAP

    if MANAGED_RESOURCES_MAP is None:
        MANAGED_RESOURCES_MAP = {}
        # Populate the map once and cache it
        for service in SERVICE_PARAMETER_SCHEMA.keys():
            for section, schema in SERVICE_PARAMETER_SCHEMA[service].items():
                for name, resource in schema.get(SERVICE_PARAM_RESOURCE, {}).items():
                    if resource is not None:
                        MANAGED_RESOURCES_MAP[resource] = {
                            'service': service,
                            'section': section,
                            'name': name,
                        }

    return MANAGED_RESOURCES_MAP.get(resource_query)
