#
# Copyright (c) 2016-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from sysinv.common import constants as sysinv_constants
from tsconfig import tsconfig


CONFIG_WORKDIR = '/tmp/config'
CGCS_CONFIG_FILE = CONFIG_WORKDIR + '/cgcs_config'
CONFIG_PERMDIR = tsconfig.CONFIG_PATH

HIERADATA_WORKDIR = '/tmp/hieradata'
HIERADATA_PERMDIR = tsconfig.PUPPET_PATH + 'hieradata'

KEYRING_WORKDIR = '/tmp/python_keyring'
KEYRING_PERMDIR = tsconfig.KEYRING_PATH

INITIAL_CONFIG_COMPLETE_FILE = '/etc/platform/.initial_config_complete'
CONFIG_FAIL_FILE = '/var/run/.config_fail'
COMMON_CERT_FILE = "/etc/ssl/private/server-cert.pem"
FIREWALL_RULES_FILE = '/etc/platform/iptables.rules'
OPENSTACK_PASSWORD_RULES_FILE = '/etc/keystone/password-rules.conf'
INSTALLATION_FAILED_FILE = '/etc/platform/installation_failed'

BACKUPS_PATH = '/opt/backups'

INTERFACES_LOG_FILE = "/tmp/configure_interfaces.log"
TC_SETUP_SCRIPT = '/usr/local/bin/cgcs_tc_setup.sh'

LINK_MTU_DEFAULT = "1500"

CINDER_LVM_THIN = "thin"
CINDER_LVM_THICK = "thick"

DEFAULT_IMAGE_STOR_SIZE = \
    sysinv_constants.DEFAULT_IMAGE_STOR_SIZE
DEFAULT_DATABASE_STOR_SIZE = \
    sysinv_constants.DEFAULT_DATABASE_STOR_SIZE
DEFAULT_IMG_CONVERSION_STOR_SIZE = \
    sysinv_constants.DEFAULT_IMG_CONVERSION_STOR_SIZE
DEFAULT_SMALL_IMAGE_STOR_SIZE = \
    sysinv_constants.DEFAULT_SMALL_IMAGE_STOR_SIZE
DEFAULT_SMALL_DATABASE_STOR_SIZE = \
    sysinv_constants.DEFAULT_SMALL_DATABASE_STOR_SIZE
DEFAULT_SMALL_IMG_CONVERSION_STOR_SIZE = \
    sysinv_constants.DEFAULT_SMALL_IMG_CONVERSION_STOR_SIZE
DEFAULT_SMALL_BACKUP_STOR_SIZE = \
    sysinv_constants.DEFAULT_SMALL_BACKUP_STOR_SIZE
DEFAULT_VIRTUAL_IMAGE_STOR_SIZE = \
    sysinv_constants.DEFAULT_VIRTUAL_IMAGE_STOR_SIZE
DEFAULT_VIRTUAL_DATABASE_STOR_SIZE = \
    sysinv_constants.DEFAULT_VIRTUAL_DATABASE_STOR_SIZE
DEFAULT_VIRTUAL_IMG_CONVERSION_STOR_SIZE = \
    sysinv_constants.DEFAULT_VIRTUAL_IMG_CONVERSION_STOR_SIZE
DEFAULT_VIRTUAL_BACKUP_STOR_SIZE = \
    sysinv_constants.DEFAULT_VIRTUAL_BACKUP_STOR_SIZE
DEFAULT_EXTENSION_STOR_SIZE = \
    sysinv_constants.DEFAULT_EXTENSION_STOR_SIZE

SYSTEM_CONFIG_TIMEOUT = 300
SERVICE_ENABLE_TIMEOUT = 180
MINIMUM_ROOT_DISK_SIZE = 500
MAXIMUM_CGCS_LV_SIZE = 500
LDAP_CONTROLLER_CONFIGURE_TIMEOUT = 30
WRSROOT_MAX_PASSWORD_AGE = 45  # 45 days

LAG_MODE_ACTIVE_BACKUP = "active-backup"
LAG_MODE_BALANCE_XOR = "balance-xor"
LAG_MODE_8023AD = "802.3ad"

LAG_TXHASH_LAYER2 = "layer2"

LAG_MIIMON_FREQUENCY = 100

LOOPBACK_IFNAME = 'lo'

DEFAULT_MULTICAST_SUBNET_IPV4 = '239.1.1.0/28'
DEFAULT_MULTICAST_SUBNET_IPV6 = 'ff08::1:1:0/124'

DEFAULT_MGMT_ON_LOOPBACK_SUBNET_IPV4 = '192.168.204.0/28'

DEFAULT_REGION_NAME = "RegionOne"
DEFAULT_SERVICE_PROJECT_NAME = "services"

SSH_WARNING_MESSAGE = "WARNING: Command should only be run from the " \
                      "console. Continuing with this terminal may cause " \
                      "loss of connectivity and configuration failure."
SSH_ERROR_MESSAGE = "ERROR: Command should only be run from the console."
