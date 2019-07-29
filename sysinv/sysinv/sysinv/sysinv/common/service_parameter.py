# Copyright (c) 2017-2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

import netaddr
import pecan
import rpm
import wsme

from sysinv.common import constants
from sysinv.common import exception
from sysinv.common import utils as cutils
from sysinv.openstack.common import log
from sysinv.openstack.common.gettextutils import _

LOG = log.getLogger(__name__)

SERVICE_PARAMETER_DATA_FORMAT_ARRAY = 'array'
SERVICE_PARAMETER_DATA_FORMAT_BOOLEAN = 'boolean'
SERVICE_PARAMETER_DATA_FORMAT_SKIP = 'skip'

IDENTITY_CONFIG_TOKEN_EXPIRATION_MIN = 3600
IDENTITY_CONFIG_TOKEN_EXPIRATION_MAX = 14400


def _validate_boolean(name, value):
    if value.lower() not in ['true', 'false']:
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a boolean value." % name))


def _validate_no_update(name, value):
    msg = _(
        "Unable to configure service parameter,"
        " %s is disabled." % name)
    raise wsme.exc.ClientSideError(msg)


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


def _validate_read_only(name, value):
    raise wsme.exc.ClientSideError(_(
        "Parameter '%s' is readonly" % name))


def _validate_SAN_list(name, value):
    """
    Validate list of Subject Alternative Name for x509 certificates. Each entry
    must be an IP address or domain name
    For example:
      "localhost.localdomain,192.168.204.2,controller"
    """
    san_entries = value.split(',')
    if len(san_entries) == 0:
        raise wsme.exc.ClientSideError(_(
            "No values provided for '%s'" % name))

    for entry in san_entries:
        if not cutils.is_valid_domain_or_ip(entry):
            raise wsme.exc.ClientSideError(_(
                "The value provided is not a domain name or IP address. (%s)"
                % entry))


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


def _validate_radosgw_enabled(name, value):
    if not cutils.is_valid_boolstr(value):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a valid bool string." % name))


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
        if not cutils.is_valid_domain_or_ip(item):
            raise wsme.exc.ClientSideError(_(
                "Parameter '%s' includes an invalid address '%s'." %
                (name, item)))


def _validate_docker_registry_address(name, value):
    """Check if registry address is valid"""
    if not cutils.is_valid_domain_or_ip(value):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a valid address." % name))


def _validate_docker_insecure_registry_bool(name, value):
    """Check if insecure registry is a valid bool"""
    if not cutils.is_valid_boolstr(value):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' must be a valid bool string." % name))


def _validate_domain(name, value):
    """Check if domain name is valid"""
    if not cutils.is_valid_domain_name(value):
        raise wsme.exc.ClientSideError(_(
            "Parameter '%s' includes an invalid domain name '%s'." %
            (name, value)))


IDENTITY_CONFIG_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_IDENTITY_CONFIG_TOKEN_EXPIRATION,
]

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

RADOSGW_CONFIG_PARAMETER_MANDATORY = [
    constants.SERVICE_PARAM_NAME_RADOSGW_SERVICE_ENABLED,
]

RADOSGW_CONFIG_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_RADOSGW_FS_SIZE_MB,
]

RADOSGW_CONFIG_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_RADOSGW_SERVICE_ENABLED: _validate_radosgw_enabled,
    constants.SERVICE_PARAM_NAME_RADOSGW_FS_SIZE_MB: _validate_integer,
}

RADOSGW_CONFIG_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_RADOSGW_SERVICE_ENABLED:
        'openstack::radosgw::params::service_enabled',
    constants.SERVICE_PARAM_NAME_RADOSGW_FS_SIZE_MB:
        'openstack::radosgw::params::fs_size_mb',
}

RADOSGW_CONFIG_PARAMETER_DATA_FORMAT = {
    constants.SERVICE_PARAM_NAME_RADOSGW_SERVICE_ENABLED: SERVICE_PARAMETER_DATA_FORMAT_BOOLEAN,
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

DOCKER_REGISTRY_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_DOCKER_K8S_REGISTRY,
    constants.SERVICE_PARAM_NAME_DOCKER_GCR_REGISTRY,
    constants.SERVICE_PARAM_NAME_DOCKER_QUAY_REGISTRY,
    constants.SERVICE_PARAM_NAME_DOCKER_DOCKER_REGISTRY,
    constants.SERVICE_PARAM_NAME_DOCKER_REGISTRIES,
    constants.SERVICE_PARAM_NAME_DOCKER_INSECURE_REGISTRY,
]

DOCKER_REGISTRY_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_DOCKER_K8S_REGISTRY: _validate_docker_registry_address,
    constants.SERVICE_PARAM_NAME_DOCKER_GCR_REGISTRY: _validate_docker_registry_address,
    constants.SERVICE_PARAM_NAME_DOCKER_QUAY_REGISTRY: _validate_docker_registry_address,
    constants.SERVICE_PARAM_NAME_DOCKER_DOCKER_REGISTRY: _validate_docker_registry_address,
    constants.SERVICE_PARAM_NAME_DOCKER_REGISTRIES: _validate_docker_registry_address,
    constants.SERVICE_PARAM_NAME_DOCKER_INSECURE_REGISTRY: _validate_docker_insecure_registry_bool,
}

DOCKER_REGISTRY_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_DOCKER_K8S_REGISTRY:
        'platform::docker::params::k8s_registry',
    constants.SERVICE_PARAM_NAME_DOCKER_GCR_REGISTRY:
        'platform::docker::params::gcr_registry',
    constants.SERVICE_PARAM_NAME_DOCKER_QUAY_REGISTRY:
        'platform::docker::params::quay_registry',
    constants.SERVICE_PARAM_NAME_DOCKER_DOCKER_REGISTRY:
        'platform::docker::params::docker_registry',
    constants.SERVICE_PARAM_NAME_DOCKER_REGISTRIES:
        'platform::docker::params::docker_registries',
    constants.SERVICE_PARAM_NAME_DOCKER_INSECURE_REGISTRY:
        'platform::docker::params::insecure_registry',
}

KUBERNETES_CERTIFICATES_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_KUBERNETES_API_SAN_LIST,
]

KUBERNETES_CERTIFICATES_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_KUBERNETES_API_SAN_LIST: _validate_SAN_list,
}

KUBERNETES_CERTIFICATES_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_KUBERNETES_API_SAN_LIST:
        'platform::kubernetes::params::apiserver_cert_san',
}

KUBERNETES_CERTIFICATES_PARAMETER_DATA_FORMAT = {
    constants.SERVICE_PARAM_NAME_KUBERNETES_API_SAN_LIST: SERVICE_PARAMETER_DATA_FORMAT_ARRAY,
}

HTTPD_PORT_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_HTTP_PORT_HTTP,
    constants.SERVICE_PARAM_HTTP_PORT_HTTPS,
]

HTTPD_PORT_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_HTTP_PORT_HTTP: _validate_integer,
    constants.SERVICE_PARAM_HTTP_PORT_HTTPS: _validate_integer,
}

HTTPD_PORT_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_HTTP_PORT_HTTP:
        'openstack::horizon::params::http_port',
    constants.SERVICE_PARAM_HTTP_PORT_HTTPS:
        'openstack::horizon::params::https_port',
}

OPENSTACK_HELM_PARAMETER_OPTIONAL = [
    constants.SERVICE_PARAM_NAME_ENDPOINT_DOMAIN,
]
OPENSTACK_HELM_PARAMETER_VALIDATOR = {
    constants.SERVICE_PARAM_NAME_ENDPOINT_DOMAIN: _validate_domain,
}
OPENSTACK_HELM_PARAMETER_RESOURCE = {
    constants.SERVICE_PARAM_NAME_ENDPOINT_DOMAIN:
        'openstack::helm::params::endpoint_domain',
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
    constants.SERVICE_TYPE_IDENTITY: {
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
    constants.SERVICE_TYPE_RADOSGW: {
        constants.SERVICE_PARAM_SECTION_RADOSGW_CONFIG: {
            SERVICE_PARAM_MANDATORY: RADOSGW_CONFIG_PARAMETER_MANDATORY,
            SERVICE_PARAM_OPTIONAL: RADOSGW_CONFIG_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: RADOSGW_CONFIG_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: RADOSGW_CONFIG_PARAMETER_RESOURCE,
            SERVICE_PARAM_DATA_FORMAT: RADOSGW_CONFIG_PARAMETER_DATA_FORMAT,
        },
    },
    constants.SERVICE_TYPE_DOCKER: {
        constants.SERVICE_PARAM_SECTION_DOCKER_PROXY: {
            SERVICE_PARAM_OPTIONAL: DOCKER_PROXY_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: DOCKER_PROXY_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: DOCKER_PROXY_PARAMETER_RESOURCE,
        },
        constants.SERVICE_PARAM_SECTION_DOCKER_REGISTRY: {
            SERVICE_PARAM_OPTIONAL: DOCKER_REGISTRY_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: DOCKER_REGISTRY_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: DOCKER_REGISTRY_PARAMETER_RESOURCE,
        },
    },
    constants.SERVICE_TYPE_KUBERNETES: {
        constants.SERVICE_PARAM_SECTION_KUBERNETES_CERTIFICATES: {
            SERVICE_PARAM_OPTIONAL: KUBERNETES_CERTIFICATES_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: KUBERNETES_CERTIFICATES_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: KUBERNETES_CERTIFICATES_PARAMETER_RESOURCE,
            SERVICE_PARAM_DATA_FORMAT: KUBERNETES_CERTIFICATES_PARAMETER_DATA_FORMAT,
        },
    },
    constants.SERVICE_TYPE_HTTP: {
        constants.SERVICE_PARAM_SECTION_HTTP_CONFIG: {
            SERVICE_PARAM_OPTIONAL: HTTPD_PORT_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: HTTPD_PORT_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: HTTPD_PORT_PARAMETER_RESOURCE,
        },
    },
    constants.SERVICE_TYPE_OPENSTACK: {
        constants.SERVICE_PARAM_SECTION_OPENSTACK_HELM: {
            SERVICE_PARAM_OPTIONAL: OPENSTACK_HELM_PARAMETER_OPTIONAL,
            SERVICE_PARAM_VALIDATOR: OPENSTACK_HELM_PARAMETER_VALIDATOR,
            SERVICE_PARAM_RESOURCE: OPENSTACK_HELM_PARAMETER_RESOURCE,
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
