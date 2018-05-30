#
# Copyright (c) 2015-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# flake8: noqa
#

from common.validator import validate
from common.configobjects import (Network, DEFAULT_CONFIG, REGION_CONFIG,
                                  DEFAULT_NAMES, HP_NAMES, SUBCLOUD_CONFIG,
                                  MGMT_TYPE, INFRA_TYPE, OAM_TYPE,
                                  NETWORK_PREFIX_NAMES, HOST_XML_ATTRIBUTES,
                                  LINK_SPEED_1G, LINK_SPEED_10G,
                                  DEFAULT_DOMAIN_NAME)
from common.exceptions import ConfigError, ConfigFail, ValidateFail
from common.utils import is_valid_vlan, is_mtu_valid, is_speed_valid, \
    validate_network_str, validate_address_str, validate_address, \
    ip_version_to_string, lag_mode_to_str, \
    validate_openstack_password, extract_openstack_password_rules_from_file
