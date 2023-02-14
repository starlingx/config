#
# Copyright (c) 2013-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

import os
import tsconfig.tsconfig as tsc

SYSINV_RUNNING_IN_LAB = '/etc/sysinv/.running_in_lab'
SYSINV_CONFIG_PATH = os.path.join(tsc.PLATFORM_PATH, "sysinv", tsc.SW_VERSION)
SYSINV_CONFIG_FILE_LOCAL = '/etc/sysinv/sysinv.conf'
SYSINV_CONF_DEFAULT_FILE = 'sysinv.conf.default'
SYSINV_CONF_DEFAULT_PATH = os.path.join(SYSINV_CONFIG_PATH,
                                        SYSINV_CONF_DEFAULT_FILE)

SYSINV_CONDUCTOR_ACTIVE_PATH = os.path.join(SYSINV_CONFIG_PATH,
                                            '.sysinv_conductor_active')

HTTPS_CONFIG_REQUIRED = os.path.join(tsc.CONFIG_PATH, '.https_config_required')
ADMIN_ENDPOINT_CONFIG_REQUIRED = os.path.join(tsc.CONFIG_PATH, '.admin_endpoint_config_required')

# Minimum password length
MINIMUM_PASSWORD_LENGTH = 8

# IP families
IPV4_FAMILY = 4
IPV6_FAMILY = 6
IP_FAMILIES = {IPV4_FAMILY: "IPv4",
               IPV6_FAMILY: "IPv6"}

# Default DAD state for each IP family
IP_DAD_STATES = {IPV4_FAMILY: False,
                 IPV6_FAMILY: True}

# IPv4 address mode definitions
IPV4_DISABLED = "disabled"
IPV4_STATIC = "static"
IPV4_DHCP = "dhcp"
IPV4_DHCP_ADDR_ONLY = "dhcp-addr-only"
IPV4_LINK_LOCAL = "link-local"
IPV4_POOL = "pool"

IPV4_ADDRESS_MODES = [IPV4_DISABLED,
                      IPV4_STATIC,
                      IPV4_DHCP,
                      IPV4_POOL]

# IPv6 address mode definitions
IPV6_DISABLED = "disabled"
IPV6_STATIC = "static"
IPV6_DHCP = "dhcp"
IPV6_DHCP_ADDR_ONLY = "dhcp-addr-only"
IPV6_AUTO = "auto"
IPV6_AUTO_ADDR_ONLY = "auto-addr-only"
IPV6_LINK_LOCAL = "link-local"
IPV6_POOL = "pool"

IPV6_ADDRESS_MODES = [IPV6_DISABLED,
                      IPV6_STATIC,
                      IPV6_AUTO,
                      IPV6_LINK_LOCAL,
                      IPV6_POOL]

# sysinv-vim-mtce definitions
# Host Actions:
UNLOCK_ACTION = 'unlock'
FORCE_UNLOCK_ACTION = 'force-unlock'
LOCK_ACTION = 'lock'
FORCE_LOCK_ACTION = 'force-lock'
REBOOT_ACTION = 'reboot'
RESET_ACTION = 'reset'
REINSTALL_ACTION = 'reinstall'
POWERON_ACTION = 'power-on'
POWEROFF_ACTION = 'power-off'
SWACT_ACTION = 'swact'
FORCE_SWACT_ACTION = 'force-swact'
SUBFUNCTION_CONFIG_ACTION = 'subfunction_config'
VIM_SERVICES_ENABLED = 'services-enabled'
VIM_SERVICES_DISABLED = 'services-disabled'
VIM_SERVICES_DISABLE_EXTEND = 'services-disable-extend'
VIM_SERVICES_DISABLE_FAILED = 'services-disable-failed'
VIM_SERVICES_DELETE_FAILED = 'services-delete-failed'
DELETE_ACTION = 'delete'
NONE_ACTION = 'none'
APPLY_ACTION = 'apply'
INSTALL_ACTION = 'install'
APPLY_CEPH_POOL_QUOTA_UPDATE = 'apply_storage_pool_quota'
ACTIVATE_OBJECT_STORAGE = 'activate_object_storage'
FORCE_ACTION = 'force_action'

MTCE_ACTIONS = [REBOOT_ACTION,
                REINSTALL_ACTION,
                RESET_ACTION,
                POWERON_ACTION,
                POWEROFF_ACTION,
                SWACT_ACTION,
                UNLOCK_ACTION,
                VIM_SERVICES_DISABLED,
                VIM_SERVICES_DISABLE_FAILED,
                FORCE_SWACT_ACTION]

# These go to VIM First
VIM_ACTIONS = [LOCK_ACTION,
               FORCE_LOCK_ACTION]

CONFIG_ACTIONS = [SUBFUNCTION_CONFIG_ACTION]

# Personalities
CONTROLLER = 'controller'
STORAGE = 'storage'
WORKER = 'worker'
EDGEWORKER = 'edgeworker'

PERSONALITIES = [CONTROLLER, STORAGE, WORKER, EDGEWORKER]

# Subfunction features
SUBFUNCTIONS = 'subfunctions'
LOWLATENCY = 'lowlatency'

# CPU functions
PLATFORM_FUNCTION = "Platform"
VSWITCH_FUNCTION = "Vswitch"
SHARED_FUNCTION = "Shared"
APPLICATION_FUNCTION = "Application"
ISOLATED_FUNCTION = "Application-isolated"
NO_FUNCTION = "None"

CPU_FUNCTIONS = [
    PLATFORM_FUNCTION,
    VSWITCH_FUNCTION,
    SHARED_FUNCTION,
    APPLICATION_FUNCTION,
    ISOLATED_FUNCTION,
    NO_FUNCTION
]

# Host Personality Sub-Types
HOST_ADD = 'host_add'  # for personality sub-type validation
HOST_DELETE = 'host_delete'  # for personality sub-type validation

# Availability
AVAILABILITY_AVAILABLE = 'available'
AVAILABILITY_INTEST = 'intest'
AVAILABILITY_OFFLINE = 'offline'
AVAILABILITY_ONLINE = 'online'
AVAILABILITY_DEGRADED = 'degraded'

DB_SUPPRESS_STATUS = 1
DB_MGMT_AFFECTING = 2
DB_DEGRADE_AFFECTING = 3

# States
ADMIN_UNLOCKED = 'unlocked'
ADMIN_LOCKED = 'locked'
LOCKING = 'Locking'
FORCE_LOCKING = "Force Locking"
OPERATIONAL_ENABLED = 'enabled'
OPERATIONAL_DISABLED = 'disabled'

UPGRADING = 'upgrading'
PROVISIONED = 'provisioned'
PROVISIONING = 'provisioning'
UNPROVISIONED = 'unprovisioned'

# Host names
LOCALHOST_HOSTNAME = 'localhost'

CONTROLLER_HOSTNAME = 'controller'
CONTROLLER_0_HOSTNAME = '%s-0' % CONTROLLER_HOSTNAME
CONTROLLER_1_HOSTNAME = '%s-1' % CONTROLLER_HOSTNAME
CONTROLLER_GATEWAY = '%s-gateway' % CONTROLLER_HOSTNAME
CONTROLLER_CINDER = '%s-cinder' % CONTROLLER_HOSTNAME
CONTROLLER_0_MGMT = '%s-mgmt' % CONTROLLER_0_HOSTNAME

PXECONTROLLER_HOSTNAME = 'pxecontroller'
OAMCONTROLLER_HOSTNAME = 'oamcontroller'

STORAGE_HOSTNAME = 'storage'
STORAGE_0_HOSTNAME = '%s-0' % STORAGE_HOSTNAME
STORAGE_1_HOSTNAME = '%s-1' % STORAGE_HOSTNAME
STORAGE_2_HOSTNAME = '%s-2' % STORAGE_HOSTNAME
# Other Storage Hostnames are built dynamically.

# Replication Peer groups
PEER_PREFIX = 'group-'

VIM_DEFAULT_TIMEOUT_IN_SECS = 5
VIM_DELETE_TIMEOUT_IN_SECS = 10
MTC_ADD_TIMEOUT_IN_SECS = 6
MTC_DELETE_TIMEOUT_IN_SECS = 10
MTC_DEFAULT_TIMEOUT_IN_SECS = 6
HWMON_DEFAULT_TIMEOUT_IN_SECS = 6
PATCH_DEFAULT_TIMEOUT_IN_SECS = 6

# ihost field attributes
IHOST_STOR_FUNCTION = 'stor_function'
IHOST_IS_MAX_CPU_MHZ_CONFIGURABLE = 'is_max_cpu_configurable'
IHOST_MAX_CPU_MHZ_ALLOWED = 'max_cpu_mhz_allowed'

# ihost config_status field values
CONFIG_STATUS_OUT_OF_DATE = "Config out-of-date"
CONFIG_STATUS_REINSTALL = "Reinstall required"

# when reinstall starts, mtc update the db with task = 'Reinstalling'
TASK_REINSTALLING = "Reinstalling"
TASK_BOOTING = "Booting"
TASK_UNLOCKING = "Unlocking"
TASK_TESTING = "Testing"

HOST_ACTION_STATE = "action_state"
HAS_REINSTALLING = "reinstalling"
HAS_REINSTALLED = "reinstalled"

INV_STATE_INITIAL_INVENTORIED = "inventoried"
INV_STATE_REINSTALLING = "reinstalling"

# Board Management Region Info
REGION_PRIMARY = "Internal"
REGION_SECONDARY = "External"

# Hugepage sizes in MiB
MIB_2M = 2
MIB_1G = 1024
Ki = 1024
NUM_4K_PER_MiB = 256

# Defines per-socket vswitch memory requirements (in MB)
VSWITCH_MEMORY_MB = 1024

# Dynamic IO Resident Set Size(RSS) in MiB per socket
DISK_IO_RESIDENT_SET_SIZE_MIB = 1000
DISK_IO_RESIDENT_SET_SIZE_MIB_VBOX = 500

# Memory reserved for platform core in MiB per host
PLATFORM_CORE_MEMORY_RESERVED_MIB = 2000
PLATFORM_CORE_MEMORY_RESERVED_MIB_VBOX = 1100
PLATFORM_CORE_MEMORY_RESERVED_MIB_VBOX_WORKER = 2000

# For AIO config, memory reserved for controller in MiB
COMBINED_NODE_CONTROLLER_MEMORY_RESERVED_MIB = 7000
COMBINED_NODE_CONTROLLER_MEMORY_RESERVED_MIB_VBOX = 3000
COMBINED_NODE_CONTROLLER_MEMORY_RESERVED_MIB_XEOND = 3000

# For standard/distributed cloud config, memory reserved for controller in MiB
STANDARD_CONTROLLER_MEMORY_RESERVED_MIB = 16500
DISTRIBUTED_CLOUD_CONTROLLER_MEMORY_RESERVED_MIB = \
    STANDARD_CONTROLLER_MEMORY_RESERVED_MIB + 8000

# Max number of physical cores in a xeon-d cpu
NUMBER_CORES_XEOND = 8

# Network overhead for DHCP or vrouter, assume 100 networks * 40 MB each
NETWORK_METADATA_OVERHEAD_MIB = 4000
NETWORK_METADATA_OVERHEAD_MIB_VBOX = 0

# Sensors
SENSOR_DATATYPE_VALID_LIST = ['discrete', 'analog']
MTCE_PORT = 2112
HWMON_PORT = 2212

# Neutron extension aliases
NEUTRON_HOST_ALIAS = "host"
NEUTRON_WRS_PROVIDER_ALIAS = "wrs-provider"

# Data Networks
DATANETWORK_TYPE_NONE = "none"
DATANETWORK_TYPE_FLAT = "flat"
DATANETWORK_TYPE_VLAN = "vlan"
DATANETWORK_TYPE_VXLAN = "vxlan"

DATANETWORK_MODE_DYNAMIC = "dynamic"
DATANETWORK_MODE_STATIC = "static"

DATANETWORK_VXLAN_MODES = [
    DATANETWORK_MODE_DYNAMIC,
    DATANETWORK_MODE_STATIC
]

# Represents the number of bytes added to a tenant packet when it is carried
# by a VXLAN based provider network.  We start by assuming a tenant network
# with an MTU of 1500 bytes.  This means that at the host vswitch the
# ethernet frame will be 1514 bytes (+4 if VLAN tagged) not including the FCS
# trailer.   To get this packet on to the provider network it must be
# encapsulated as-is with a {IPv4|IPv6}+UDP+VXLAN headers.  The ETH+VLAN
# headers are not included because they themselves are not included in the
# provider network MTU (i.e., the VXLAN packet must fit within the ethernet
# payload of the provider interface).
# Therefore the maximum overhead, assuming a VLAN tagged provider network, is:
#
#  IPv4 = 20 + 8 + 8 = 36
#  IPv6 = 40 + 8 + 8 = 56
#
# This brings the maximum tenant packet size to:
#  IPv4 = 36 + 1518 = 1554
#  IPv6 = 56 + 1518 = 1574
#
# Therefore to support an tenant MTU of 1500 the underlying physical
# interface must support an MTU of 1574 bytes.
#
VXLAN_MTU_OVERHEAD = 74

# Supported worker node vswitch types
VSWITCH_TYPE_OVS_DPDK = "ovs-dpdk"
VSWITCH_TYPE_NUAGE_VRS = "nuage_vrs"
VSWITCH_TYPE_NONE = "none"

# Partition default sizes
# These values must be aligned with the values used by
# the apply_bootstrap_manifest task during the bootstrap
DEFAULT_PLATFORM_STOR_SIZE = 10
DEFAULT_PLATFORM_SYSTEMCONTROLLER_STOR_SIZE = 20
DEFAULT_DOCKER_STOR_SIZE = 1
DEFAULT_DOCKER_DISTRIBUTION_STOR_SIZE = 1
DEFAULT_DATABASE_STOR_SIZE = 10
DEFAULT_SMALL_DATABASE_STOR_SIZE = 5
DEFAULT_SMALL_BACKUP_STOR_SIZE = 20
DEFAULT_TINY_DATABASE_STOR_SIZE = 1
DEFAULT_TINY_BACKUP_STOR_SIZE = 1
DEFAULT_TINY_PLATFORM_STOR_SIZE = 1
DEFAULT_EXTENSION_STOR_SIZE = 1
DEFAULT_DC_VAULT_STOR_SIZE = 15

BACKUP_OVERHEAD = 5
IMAGE_CONVERSION_SIZE = 1
KUBERNETES_DOCKER_STOR_SIZE = 30
DOCKER_DISTRIBUTION_STOR_SIZE = 16
ETCD_STOR_SIZE = 5
KUBELET_STOR_SIZE = 10
TINY_KUBERNETES_DOCKER_STOR_SIZE = 20
TINY_DOCKER_DISTRIBUTION_STOR_SIZE = 8
TINY_ETCD_STOR_SIZE = 1
TINY_KUBELET_STOR_SIZE = 2

# The threshold between small and large disks is 240GiB
DEFAULT_SMALL_DISK_SIZE = 240

# The minimum small disk size needed to create all partitions
# Value based on the following calculation:
# 2*DEFAULT_SMALL_DATABASE_STOR_SIZE                   10 (2*5)
# DEFAULT_SMALL_BACKUP_STOR_SIZE                       20
# LOG_VOL_SIZE (reserved in kickstarts)                 8
# SCRATCH_VOL_SIZE (reserved in kickstarts)            16
# DEFAULT_PLATFORM_STOR_SIZE                           10
# DEFAULT_EXTENSION_STOR_SIZE                           1
# DEFAULT_RABBIT_STOR_SIZE                              2
# KUBERNETES_DOCKER_STOR_SIZE                          30
# DOCKER_DISTRIBUTION_STOR_SIZE                        16
# ETCD_STOR_SIZE                                        5
# CEPH_MON_SIZE                                        20
# KUBELET_STOR_SIZE                                    10
# DC_VAULT_SIZE                                        15
# buffer inside VG for LV creation                      1
# platform backup partition (created in kickstarts)    10
# root partition (created in kickstarts)               20
# boot/EFI partition (created in kickstarts)            1
# buffer for partition creation                         1
# -------------------------------------------------------
#                                                     196
MINIMUM_SMALL_DISK_SIZE = 196

# The minimum tiny disk size needed to create all partitions
# Value based on the following calculation:
# 2*DEFAULT_TINY_DATABASE_STOR_SIZE                     2 (2*1)
# DEFAULT_TINY_BACKUP_STOR_SIZE                         1
# LOG_VOL_SIZE (reserved in kickstarts)                 3
# SCRATCH_VOL_SIZE (reserved in kickstarts)             2
# DEFAULT_TINY_PLATFORM_STOR_SIZE                       1
# DEFAULT_EXTENSION_STOR_SIZE                           1
# DEFAULT_RABBIT_STOR_SIZE                              2
# TINY_KUBERNETES_DOCKER_STOR_SIZE                     20
# TINY_DOCKER_DISTRIBUTION_STOR_SIZE                    8
# TINY_ETCD_STOR_SIZE                                   1
# TINY_KUBELET_STOR_SIZE                                2
# platform backup partition (created in kickstarts)     1
# root partition (created in kickstarts)               15
# boot/EFI partition (created in kickstarts)            1
# -------------------------------------------------------
#                                                      60
MINIMUM_TINY_DISK_SIZE = 60

# Openstack Interface names
OS_INTERFACE_PUBLIC = 'public'
OS_INTERFACE_INTERNAL = 'internal'
OS_INTERFACE_ADMIN = 'admin'

# Default region one name
REGION_ONE_NAME = 'RegionOne'
# DC Region Must match VIRTUAL_MASTER_CLOUD in dcorch
SYSTEM_CONTROLLER_REGION = 'SystemController'

# Valid major numbers for disks:
#     https://www.kernel.org/doc/Documentation/admin-guide/devices.txt
#
#   3 block First MFM, RLL and IDE hard disk/CD-ROM interface
#   8 block SCSI disk devices (0-15)
#  65 block SCSI disk devices (16-31)
#  66 block SCSI disk devices (32-47)
#  67 block SCSI disk devices (48-63)
#  68 block SCSI disk devices (64-79)
#  69 block SCSI disk devices (80-95)
#  70 block SCSI disk devices (96-111)
#  71 block SCSI disk devices (112-127)
# 128 block SCSI disk devices (128-143)
# 129 block SCSI disk devices (144-159)
# 130 block SCSI disk devices (160-175)
# 131 block SCSI disk devices (176-191)
# 132 block SCSI disk devices (192-207)
# 133 block SCSI disk devices (208-223)
# 134 block SCSI disk devices (224-239)
# 135 block SCSI disk devices (240-255)
# 240-254 block    LOCAL/EXPERIMENTAL USE (253 == /dev/vdX)
# 259 block    Block Extended Major (NVMe - /dev/nvmeXn1)
VALID_MAJOR_LIST = ['3', '8', '65', '66', '67', '68', '69', '70', '71',
                    '128', '129', '130', '131', '132', '133', '134',
                    '135', '253', '259']
VENDOR_ID_LIO = 'LIO-ORG'

# Storage backends supported
SB_TYPE_FILE = 'file'
SB_TYPE_LVM = 'lvm'
SB_TYPE_CEPH = 'ceph'
SB_TYPE_CEPH_EXTERNAL = 'ceph-external'
SB_TYPE_EXTERNAL = 'external'
SB_TYPE_CEPH_ROOK = 'ceph-rook'

SB_SUPPORTED = [SB_TYPE_FILE,
                SB_TYPE_LVM,
                SB_TYPE_CEPH,
                SB_TYPE_CEPH_EXTERNAL,
                SB_TYPE_EXTERNAL,
                SB_TYPE_CEPH_ROOK]

# Storage backend default names
SB_DEFAULT_NAME_SUFFIX = "-store"
SB_DEFAULT_NAMES = {
    SB_TYPE_FILE: SB_TYPE_FILE + SB_DEFAULT_NAME_SUFFIX,
    SB_TYPE_LVM: SB_TYPE_LVM + SB_DEFAULT_NAME_SUFFIX,
    SB_TYPE_CEPH: SB_TYPE_CEPH + SB_DEFAULT_NAME_SUFFIX,
    SB_TYPE_CEPH_EXTERNAL: SB_TYPE_CEPH_EXTERNAL + SB_DEFAULT_NAME_SUFFIX,
    SB_TYPE_CEPH_ROOK: SB_TYPE_CEPH_ROOK + SB_DEFAULT_NAME_SUFFIX,
    SB_TYPE_EXTERNAL: 'shared_services'
}

# Service names
SERVICE_NAME_NOVA = 'nova'
SERVICE_NAME_NEUTRON = 'neutron'

# Storage backends services
SB_SVC_CINDER = 'cinder'
SB_SVC_GLANCE = 'glance'
SB_SVC_NOVA = 'nova'
SB_SVC_SWIFT = 'swift'
SB_SVC_RBD_PROVISIONER = 'rbd-provisioner'

SB_FILE_SVCS_SUPPORTED = [SB_SVC_GLANCE]
SB_LVM_SVCS_SUPPORTED = [SB_SVC_CINDER]
# Primary tier supported services.
SB_CEPH_SVCS_SUPPORTED = [SB_SVC_GLANCE, SB_SVC_CINDER, SB_SVC_SWIFT,
                          SB_SVC_NOVA, SB_SVC_RBD_PROVISIONER]
SB_CEPH_EXTERNAL_SVCS_SUPPORTED = [SB_SVC_CINDER, SB_SVC_GLANCE, SB_SVC_NOVA]
SB_EXTERNAL_SVCS_SUPPORTED = [SB_SVC_CINDER, SB_SVC_GLANCE]
SB_CEPH_ROOK_SVCS_SUPPORTED = [SB_SVC_GLANCE, SB_SVC_CINDER, SB_SVC_NOVA]

# Storage backend: Service specific backend nomenclature
CINDER_BACKEND_CEPH = SB_TYPE_CEPH
CINDER_BACKEND_CEPH_EXTERNAL = SB_TYPE_CEPH_EXTERNAL
CINDER_BACKEND_LVM = SB_TYPE_LVM
GLANCE_BACKEND_FILE = SB_TYPE_FILE
GLANCE_BACKEND_RBD = 'rbd'
GLANCE_BACKEND_HTTP = 'http'
GLANCE_BACKEND_GLANCE = 'glance'

# Clusters
CLUSTER_TYPE_CEPH = "ceph"
CLUSTER_CEPH_DEFAULT_NAME = "ceph_cluster"

# Storage Tiers: types (aligns with polymorphic backends)
SB_TIER_TYPE_CEPH = SB_TYPE_CEPH
SB_TIER_SUPPORTED = [SB_TIER_TYPE_CEPH]
SB_TIER_DEFAULT_NAMES = {
    SB_TIER_TYPE_CEPH: 'storage'  # maps to crushmap 'storage-tier' root
}

# Supported secondary tier services.
SB_TIER_CEPH_SECONDARY_SVCS = [SB_SVC_CINDER, SB_SVC_RBD_PROVISIONER]

SB_TIER_STATUS_DEFINED = 'defined'
SB_TIER_STATUS_IN_USE = 'in-use'

# File name reserved for internal ceph cluster.
SB_TYPE_CEPH_CONF_FILENAME = "ceph.conf"

# Glance images path when it is file backended
GLANCE_IMAGE_PATH = tsc.PLATFORM_PATH + "/" + SB_SVC_GLANCE + "/images"

# Path for Ceph (internal and external) config files
CEPH_CONF_PATH = "/etc/ceph/"

# Requested storage backend API operations
SB_API_OP_CREATE = "create"
SB_API_OP_MODIFY = "modify"
SB_API_OP_DELETE = "delete"

# Storage backend state
SB_STATE_CONFIGURED = 'configured'
SB_STATE_CONFIGURING = 'configuring'
SB_STATE_CONFIG_ERR = 'configuration-failed'
SB_STATE_CONFIGURING_ON_UNLOCK = 'configuring-on-unlock'

# Storage backend tasks
SB_TASK_NONE = None
SB_TASK_APPLY_MANIFESTS = 'applying-manifests'
SB_TASK_APPLY_CONFIG_FILE = 'applying-config-file'
SB_TASK_PROVISION_STORAGE = 'provision-storage'
SB_TASK_PROVISION_SERVICES = 'provision-services'
SB_TASK_RECONFIG_WORKER = 'reconfig-worker'
SB_TASK_RESIZE_CEPH_MON_LV = 'resize-ceph-mon-lv'
SB_TASK_ADD_OBJECT_GATEWAY = 'add-object-gateway'
SB_TASK_RESTORE = 'restore'

# Storage backend ceph-mon-lv size
SB_CEPH_MON_GIB = 20
SB_CEPH_MON_GIB_MIN = 20
SB_CEPH_MON_GIB_MAX = 40

SB_CONFIGURATION_TIMEOUT = 1200
INIT_CEPH_INFO_INTERVAL_SECS = 30

# Ceph storage deployment model
# Controller model: OSDs are on controllers, no storage nodes can
# be defined.
# Storage model: OSDs are on dedicated storage nodes.
CEPH_STORAGE_MODEL = 'storage-nodes'
CEPH_CONTROLLER_MODEL = 'controller-nodes'
CEPH_AIO_SX_MODEL = 'aio-sx'
CEPH_UNDEFINED_MODEL = 'undefined'

# Storage: Minimum number of monitors
MIN_STOR_MONITORS_MULTINODE = 2
MIN_STOR_MONITORS_AIO = 1

# Suffix used in LVM volume name to indicate that the
# volume is actually a thin pool.  (And thin volumes will
# be created in the thin pool.)
LVM_POOL_SUFFIX = '-pool'

# Controller DRBD File System Resizing States
CONTROLLER_FS_RESIZING_IN_PROGRESS = 'drbd_fs_resizing_in_progress'
CONTROLLER_FS_AVAILABLE = 'available'

# DRBD File Systems
DRBD_PLATFORM = 'platform'
DRBD_PGSQL = 'pgsql'
DRBD_EXTENSION = 'extension'
DRBD_DC_VAULT = 'dc-vault'
DRBD_ETCD = 'etcd'
DRBD_DOCKER_DISTRIBUTION = 'docker-distribution'

# File system names
FILESYSTEM_NAME_BACKUP = 'backup'
FILESYSTEM_NAME_PLATFORM = 'platform'
FILESYSTEM_NAME_CINDER = 'cinder'
FILESYSTEM_NAME_DATABASE = 'database'
FILESYSTEM_NAME_SCRATCH = 'scratch'
FILESYSTEM_NAME_DOCKER = 'docker'
FILESYSTEM_NAME_DOCKER_DISTRIBUTION = 'docker-distribution'
FILESYSTEM_NAME_EXTENSION = 'extension'
FILESYSTEM_NAME_ETCD = 'etcd'
FILESYSTEM_NAME_DC_VAULT = 'dc-vault'
FILESYSTEM_NAME_KUBELET = 'kubelet'
FILESYSTEM_NAME_IMAGE_CONVERSION = 'image-conversion'
FILESYSTEM_NAME_INSTANCES = 'instances'
FILESYSTEM_NAME_LOG = 'log'
FILESYSTEM_NAME_VAR = 'var'
FILESYSTEM_NAME_ROOT = 'root'

FILESYSTEM_LV_DICT = {
    FILESYSTEM_NAME_PLATFORM: 'platform-lv',
    FILESYSTEM_NAME_BACKUP: 'backup-lv',
    FILESYSTEM_NAME_SCRATCH: 'scratch-lv',
    FILESYSTEM_NAME_IMAGE_CONVERSION: 'conversion-lv',
    FILESYSTEM_NAME_INSTANCES: 'instances-lv',
    FILESYSTEM_NAME_DOCKER: 'docker-lv',
    FILESYSTEM_NAME_DOCKER_DISTRIBUTION: 'dockerdistribution-lv',
    FILESYSTEM_NAME_DATABASE: 'pgsql-lv',
    FILESYSTEM_NAME_EXTENSION: 'extension-lv',
    FILESYSTEM_NAME_ETCD: 'etcd-lv',
    FILESYSTEM_NAME_DC_VAULT: 'dc-vault-lv',
    FILESYSTEM_NAME_KUBELET: 'kubelet-lv',
    FILESYSTEM_NAME_LOG: 'log-lv',
    FILESYSTEM_NAME_VAR: 'var-lv',
    FILESYSTEM_NAME_ROOT: 'root-lv',
}

# Supported DRDB file system resizes (via controllerfs-modify)
FILESYSTEM_DRBD_DICT = {
    FILESYSTEM_NAME_PLATFORM: DRBD_PLATFORM,
    FILESYSTEM_NAME_DATABASE: DRBD_PGSQL,
    FILESYSTEM_NAME_EXTENSION: DRBD_EXTENSION,
    FILESYSTEM_NAME_DC_VAULT: DRBD_DC_VAULT,
    FILESYSTEM_NAME_ETCD: DRBD_ETCD,
    FILESYSTEM_NAME_DOCKER_DISTRIBUTION: DRBD_DOCKER_DISTRIBUTION,
}

FS_CREATION_ALLOWED = [
    FILESYSTEM_NAME_IMAGE_CONVERSION,
    FILESYSTEM_NAME_INSTANCES,
]

FILESYSTEM_CONTROLLER_SUPPORTED_LIST = [
    FILESYSTEM_NAME_SCRATCH,
    FILESYSTEM_NAME_BACKUP,
    FILESYSTEM_NAME_DOCKER,
    FILESYSTEM_NAME_KUBELET,
    FILESYSTEM_NAME_IMAGE_CONVERSION,
    FILESYSTEM_NAME_INSTANCES,
    FILESYSTEM_NAME_LOG,
    FILESYSTEM_NAME_VAR,
    FILESYSTEM_NAME_ROOT,
]

FILESYSTEM_WORKER_SUPPORTED_LIST = [
    FILESYSTEM_NAME_DOCKER,
    FILESYSTEM_NAME_KUBELET,
    FILESYSTEM_NAME_SCRATCH,
    FILESYSTEM_NAME_INSTANCES,
    FILESYSTEM_NAME_LOG,
    FILESYSTEM_NAME_VAR,
    FILESYSTEM_NAME_ROOT,
]

FILESYSTEM_STORAGE_SUPPORTED_LIST = [
    FILESYSTEM_NAME_DOCKER,
    FILESYSTEM_NAME_KUBELET,
    FILESYSTEM_NAME_SCRATCH,
    FILESYSTEM_NAME_LOG,
    FILESYSTEM_NAME_VAR,
    FILESYSTEM_NAME_ROOT,
]

FILESYSTEM_HOSTS_SUPPORTED_LIST_DICT = {
    CONTROLLER: FILESYSTEM_CONTROLLER_SUPPORTED_LIST,
    WORKER: FILESYSTEM_WORKER_SUPPORTED_LIST,
    STORAGE: FILESYSTEM_STORAGE_SUPPORTED_LIST,
}

SUPPORTED_LOGICAL_VOLUME_LIST = list(FILESYSTEM_LV_DICT.values())

SUPPORTED_REPLICATED_FILEYSTEM_LIST = [
    FILESYSTEM_NAME_PLATFORM,
    FILESYSTEM_NAME_DATABASE,
    FILESYSTEM_NAME_EXTENSION,
    FILESYSTEM_NAME_DC_VAULT,
    FILESYSTEM_NAME_ETCD,
    FILESYSTEM_NAME_DOCKER_DISTRIBUTION,
]

# Storage: Volume Group Types
LVG_NOVA_LOCAL = 'nova-local'
LVG_CGTS_VG = 'cgts-vg'
LVG_CINDER_VOLUMES = 'cinder-volumes'
LVG_ALLOWED_VGS = [LVG_NOVA_LOCAL, LVG_CGTS_VG, LVG_CINDER_VOLUMES]

# Cinder LVM Parameters
CINDER_LVM_MINIMUM_DEVICE_SIZE_GIB = 5  # GiB
CINDER_LVM_DRBD_RESOURCE = 'drbd-cinder'
CINDER_LVM_DRBD_WAIT_PEER_RETRY = 5
CINDER_LVM_DRBD_WAIT_PEER_SLEEP = 2
CINDER_LVM_POOL_LV = LVG_CINDER_VOLUMES + LVM_POOL_SUFFIX
CINDER_LVM_POOL_META_LV = CINDER_LVM_POOL_LV + "_tmeta"
CINDER_RESIZE_FAILURE = "cinder-resize-failure"
CINDER_DRBD_DEVICE = '/dev/drbd4'

CINDER_LVM_TYPE_THIN = 'thin'
CINDER_LVM_TYPE_THICK = 'thick'

# Storage: Volume Group/Physical Volume States and timeouts
LVG_ADD = 'adding'
LVG_DEL = 'removing'

PV_ADD = 'adding'
PV_DEL = 'removing'
PV_ERR = 'failed'
PV_OPERATIONS = [PV_ADD, PV_DEL]  # We expect these to be transitory
PV_OP_TIMEOUT = 300  # Seconds to wait for an operation to complete
PV_TYPE_DISK = 'disk'
PV_TYPE_PARTITION = 'partition'
PV_NAME_UNKNOWN = 'unknown'

# Storage: Volume Group Parameter Types
LVG_CINDER_PARAM_LVM_TYPE = 'lvm_type'

# Storage: Volume Group Parameter: Cinder: LVM provisioing
LVG_CINDER_LVM_TYPE_THIN = 'thin'
LVG_CINDER_LVM_TYPE_THICK = 'thick'

# Controller audit requests (force updates from agents)
DISK_AUDIT_REQUEST = "audit_disk"
LVG_AUDIT_REQUEST = "audit_lvg"
PV_AUDIT_REQUEST = "audit_pv"
PARTITION_AUDIT_REQUEST = "audit_partition"
FILESYSTEM_AUDIT_REQUEST = "audit_fs"
CONTROLLER_AUDIT_REQUESTS = [DISK_AUDIT_REQUEST,
                             LVG_AUDIT_REQUEST,
                             PV_AUDIT_REQUEST,
                             PARTITION_AUDIT_REQUEST,
                             FILESYSTEM_AUDIT_REQUEST]

# Interface definitions
NETWORK_TYPE_NONE = 'none'
NETWORK_TYPE_MGMT = 'mgmt'
NETWORK_TYPE_ADMIN = 'admin'
NETWORK_TYPE_OAM = 'oam'
NETWORK_TYPE_BM = 'bm'
NETWORK_TYPE_MULTICAST = 'multicast'
NETWORK_TYPE_DATA = 'data'
NETWORK_TYPE_SYSTEM_CONTROLLER = 'system-controller'
NETWORK_TYPE_SYSTEM_CONTROLLER_OAM = 'system-controller-oam'
NETWORK_TYPE_CLUSTER_HOST = 'cluster-host'
NETWORK_TYPE_CLUSTER_POD = 'cluster-pod'
NETWORK_TYPE_CLUSTER_SERVICE = 'cluster-service'

NETWORK_TYPE_PCI_PASSTHROUGH = 'pci-passthrough'
NETWORK_TYPE_PCI_SRIOV = 'pci-sriov'
NETWORK_TYPE_PXEBOOT = 'pxeboot'
NETWORK_TYPE_IRONIC = 'ironic'
NETWORK_TYPE_STORAGE = 'storage'

PLATFORM_NETWORK_TYPES = [NETWORK_TYPE_PXEBOOT,
                          NETWORK_TYPE_MGMT,
                          NETWORK_TYPE_OAM,
                          NETWORK_TYPE_CLUSTER_HOST,
                          NETWORK_TYPE_IRONIC,
                          NETWORK_TYPE_STORAGE,
                          NETWORK_TYPE_ADMIN]

PCI_NETWORK_TYPES = [NETWORK_TYPE_PCI_PASSTHROUGH,
                     NETWORK_TYPE_PCI_SRIOV]

SRIOV_DRIVER_TYPE_VFIO = 'vfio'
SRIOV_DRIVER_TYPE_NETDEVICE = 'netdevice'
SRIOV_DRIVER_VFIO_PCI = 'vfio-pci'
SRIOV_DRIVER_TYPES = [SRIOV_DRIVER_TYPE_VFIO,
                      SRIOV_DRIVER_TYPE_NETDEVICE]

INTERFACE_TYPE_ETHERNET = 'ethernet'
INTERFACE_TYPE_VLAN = 'vlan'
INTERFACE_TYPE_AE = 'ae'
INTERFACE_TYPE_VIRTUAL = 'virtual'
INTERFACE_TYPE_VF = 'vf'

INTERFACE_CLASS_NONE = 'none'
INTERFACE_CLASS_PLATFORM = 'platform'
INTERFACE_CLASS_DATA = 'data'
INTERFACE_CLASS_PCI_PASSTHROUGH = 'pci-passthrough'
INTERFACE_CLASS_PCI_SRIOV = 'pci-sriov'

INTERFACE_PTP_ROLE_MASTER = 'master'
INTERFACE_PTP_ROLE_SLAVE = 'slave'
INTERFACE_PTP_ROLE_NONE = 'none'

AE_MODE_ACTIVE_STANDBY = 'active_standby'
AE_MODE_BALANCED = 'balanced'
AE_MODE_LACP = '802.3ad'
VALID_AEMODE_LIST = [AE_MODE_ACTIVE_STANDBY,
                     AE_MODE_BALANCED,
                     AE_MODE_LACP]

PRIMARY_RESELECT_ALWAYS = 'always'
PRIMARY_RESELECT_BETTER = 'better'
PRIMARY_RESELECT_FAILURE = 'failure'
VALID_PRIMARY_RESELECT_LIST = [PRIMARY_RESELECT_ALWAYS,
                               PRIMARY_RESELECT_BETTER,
                               PRIMARY_RESELECT_FAILURE]

SM_MULTICAST_MGMT_IP_NAME = "sm-mgmt-ip"
MTCE_MULTICAST_MGMT_IP_NAME = "mtce-mgmt-ip"
PATCH_CONTROLLER_MULTICAST_MGMT_IP_NAME = "patch-controller-mgmt-ip"
PATCH_AGENT_MULTICAST_MGMT_IP_NAME = "patch-agent-mgmt-ip"
SYSTEM_CONTROLLER_GATEWAY_IP_NAME = "system-controller-gateway-ip"

ADDRESS_FORMAT_ARGS = (CONTROLLER_HOSTNAME,
                       NETWORK_TYPE_MGMT)
MGMT_CINDER_IP_NAME = "%s-cinder-%s" % ADDRESS_FORMAT_ARGS

ETHERNET_NULL_MAC = '00:00:00:00:00:00'

DEFAULT_MTU = 1500

# Loopback management interface name for AIO simplex
LOOPBACK_IFNAME = 'lo'

# Link speed definitions
LINK_SPEED_1G = 1000
LINK_SPEED_10G = 10000
LINK_SPEED_25G = 25000

# VF rate limit
VF_TOTAL_RATE_RATIO = 0.9

# DRBD engineering limits.
# Link Util values are in Percentage.
DRBD_LINK_UTIL_MIN = 5
DRBD_LINK_UTIL_MAX = 80
DRBD_LINK_UTIL_DEFAULT = DRBD_LINK_UTIL_MAX // 2

DRBD_RTT_MS_MIN = 0.2
DRBD_RTT_MS_MAX = 20.0
DRBD_RTT_MS_DEFAULT = DRBD_RTT_MS_MIN

DRBD_NUM_PARALLEL_DEFAULT = 1

# Stor function types
STOR_FUNCTION_CINDER = 'cinder'
STOR_FUNCTION_OSD = 'osd'
STOR_FUNCTION_MONITOR = 'monitor'
STOR_FUNCTION_JOURNAL = 'journal'

# Disk types and names.
DEVICE_TYPE_HDD = 'HDD'
DEVICE_TYPE_SSD = 'SSD'
DEVICE_TYPE_NVME = 'NVME'
DEVICE_TYPE_UNDETERMINED = 'Undetermined'
DEVICE_TYPE_NA = 'N/A'
DEVICE_NAME_NVME = 'nvme'
DEVICE_NAME_DM = 'dm-'
DEVICE_NAME_MPATH = 'mpath'
DEVICE_FS_TYPE_MPATH = 'mpath_member'

# Disk model types.
DEVICE_MODEL_UNKNOWN = 'Unknown'

# Journal operations.
ACTION_CREATE_JOURNAL = "create"
ACTION_UPDATE_JOURNAL = "update"

# Load constants
MNT_DIR = '/tmp/mnt'

ACTIVE_LOAD_STATE = 'active'
IMPORTING_LOAD_STATE = 'importing'
IMPORTED_LOAD_STATE = 'imported'
IMPORTED_METADATA_LOAD_STATE = 'imported-metadata'
ERROR_LOAD_STATE = 'error'
DELETING_LOAD_STATE = 'deleting'
IMPORTED_LOAD_STATES = [
    IMPORTED_LOAD_STATE,
    IMPORTED_METADATA_LOAD_STATE
]

DELETE_LOAD_SCRIPT = '/etc/sysinv/upgrades/delete_load.sh'
IMPORTED_LOAD_MAX_COUNT = 1
LOAD_ISO = 'path_to_iso'
LOAD_SIGNATURE = 'path_to_sig'
IMPORT_LOAD_FILES = [LOAD_ISO, LOAD_SIGNATURE]
LOAD_FILES_STAGING_DIR = '/scratch/tmp_load'
STAGING_LOAD_FILES_REMOVAL_WAIT_TIME = 30

# Ceph
CEPH_HEALTH_OK = 'HEALTH_OK'
CEPH_HEALTH_BLOCK = 'HEALTH_BLOCK'

# Ceph backend pool parameters:
CEPH_POOL_RBD_NAME = 'rbd'
CEPH_POOL_RBD_PG_NUM = 64
CEPH_POOL_RBD_PGP_NUM = 64

CEPH_POOL_VOLUMES_NAME = 'cinder-volumes'
CEPH_POOL_VOLUMES_PG_NUM = 512
CEPH_POOL_VOLUMES_PGP_NUM = 512
CEPH_POOL_VOLUMES_QUOTA_GIB = 0
CEPH_POOL_VOLUMES_CHUNK_SIZE = 8
CEPH_POOL_VOLUMES_APP_NAME = 'cinder-volumes'

CEPH_POOL_IMAGES_NAME = 'images'
CEPH_POOL_IMAGES_PG_NUM = 256
CEPH_POOL_IMAGES_PGP_NUM = 256
CEPH_POOL_IMAGES_QUOTA_GIB = 20

CEPH_POOL_EPHEMERAL_NAME = 'ephemeral'
CEPH_POOL_EPHEMERAL_PG_NUM = 512
CEPH_POOL_EPHEMERAL_PGP_NUM = 512
CEPH_POOL_EPHEMERAL_QUOTA_GIB = 0

CEPH_POOL_KUBE_NAME = 'kube-rbd'
CEPH_POOL_KUBE_PG_NUM = 128
CEPH_POOL_KUBE_PGP_NUM = 128
CEPH_POOL_KUBE_QUOTA_GIB = 20

# Ceph RADOS Gateway default data pool
# Hammer version pool name will be kept if upgrade from R3 and
# Swift/Radosgw was configured/enabled in R3.
CEPH_POOL_OBJECT_GATEWAY_NAME_PART = 'rgw'
CEPH_POOL_OBJECT_GATEWAY_NAME_JEWEL = 'default.rgw.buckets.data'
CEPH_POOL_OBJECT_GATEWAY_NAME_HAMMER = '.rgw.buckets'
CEPH_POOL_OBJECT_GATEWAY_ROOT_NAME = '.rgw.root'
CEPH_POOL_OBJECT_GATEWAY_PG_NUM = 256
CEPH_POOL_OBJECT_GATEWAY_PGP_NUM = 256
CEPH_POOL_OBJECT_GATEWAY_QUOTA_GIB = 0

CEPH_POOL_OBJECT_GATEWAY_NAME = {
    CEPH_POOL_OBJECT_GATEWAY_NAME_JEWEL,
    CEPH_POOL_OBJECT_GATEWAY_NAME_HAMMER}

# Main pools for Ceph data backing
CEPH_POOLS = [{'pool_name': CEPH_POOL_VOLUMES_NAME,
               'pg_num': CEPH_POOL_VOLUMES_PG_NUM,
               'pgp_num': CEPH_POOL_VOLUMES_PGP_NUM,
               'quota_gib': None,
               'data_pt': 35},
              {'pool_name': CEPH_POOL_IMAGES_NAME,
               'pg_num': CEPH_POOL_IMAGES_PG_NUM,
               'pgp_num': CEPH_POOL_IMAGES_PGP_NUM,
               'quota_gib': None,
               'data_pt': 18},
              {'pool_name': CEPH_POOL_EPHEMERAL_NAME,
               'pg_num': CEPH_POOL_EPHEMERAL_PG_NUM,
               'pgp_num': CEPH_POOL_EPHEMERAL_PGP_NUM,
               'quota_gib': None,
               'data_pt': 27},
              {'pool_name': CEPH_POOL_OBJECT_GATEWAY_NAME_JEWEL,
               'pg_num': CEPH_POOL_OBJECT_GATEWAY_PG_NUM,
               'pgp_num': CEPH_POOL_OBJECT_GATEWAY_PGP_NUM,
               'quota_gib': None,
               'data_pt': 10},
              {'pool_name': CEPH_POOL_KUBE_NAME,
               'pg_num': CEPH_POOL_KUBE_PG_NUM,
               'pgp_num': CEPH_POOL_KUBE_PGP_NUM,
               'quota_gib': None,
               'data_pt': 10}]

ALL_CEPH_POOLS = [CEPH_POOL_RBD_NAME,
                  CEPH_POOL_VOLUMES_NAME,
                  CEPH_POOL_IMAGES_NAME,
                  CEPH_POOL_EPHEMERAL_NAME,
                  CEPH_POOL_OBJECT_GATEWAY_NAME_JEWEL,
                  CEPH_POOL_OBJECT_GATEWAY_NAME_HAMMER,
                  CEPH_POOL_KUBE_NAME]

# Supported pools for secondary ceph tiers
SB_TIER_CEPH_POOLS = [
    {'pool_name': CEPH_POOL_VOLUMES_NAME,
     'pg_num': CEPH_POOL_VOLUMES_PG_NUM,
     'pgp_num': CEPH_POOL_VOLUMES_PGP_NUM,
     'be_quota_attr': 'cinder_pool_gib',
     'quota_default': 0,
     'data_pt': 80},
    {'pool_name': CEPH_POOL_KUBE_NAME,
     'pg_num': CEPH_POOL_KUBE_PG_NUM,
     'pgp_num': CEPH_POOL_KUBE_PGP_NUM,
     'be_quota_attr': 'kube_pool_gib',
     'quota_default': 20,
     'data_pt': 20}]

# See http://ceph.com/pgcalc/. We set it to more than 100 because pool usage
# varies greatly in StarlingX and we want to avoid running too low on PGs
CEPH_TARGET_PGS_PER_OSD = 200

# Dual node and Storage
CEPH_REPLICATION_FACTOR_DEFAULT = 2
CEPH_REPLICATION_FACTOR_SUPPORTED = [2, 3]
CEPH_CONTROLLER_MODEL_REPLICATION_SUPPORTED = [2]

# Single node
AIO_SX_CEPH_REPLICATION_FACTOR_DEFAULT = 1
AIO_SX_CEPH_REPLICATION_FACTOR_SUPPORTED = [1, 2, 3]

CEPH_REPLICATION_MAP_SUPPORTED = {
    1: [1],
    2: [1],
    3: [1, 2]
}

CEPH_REPLICATION_MAP_DEFAULT = {
    # replication: min_replication
    1: 1,
    2: 1,
    3: 2
}

# ceph osd pool size
CEPH_BACKEND_REPLICATION_CAP = 'replication'
# ceph osd pool min size
CEPH_BACKEND_MIN_REPLICATION_CAP = 'min_replication'
CEPH_BACKEND_CAP_DEFAULT = {
    CEPH_BACKEND_REPLICATION_CAP:
        str(CEPH_REPLICATION_FACTOR_DEFAULT),
    CEPH_BACKEND_MIN_REPLICATION_CAP:
        str(CEPH_REPLICATION_MAP_DEFAULT[CEPH_REPLICATION_FACTOR_DEFAULT])
}
CEPH_REPLICATION_GROUP0_HOSTS = {
    2: [STORAGE_0_HOSTNAME, STORAGE_1_HOSTNAME],
    3: [STORAGE_0_HOSTNAME, STORAGE_1_HOSTNAME, STORAGE_2_HOSTNAME]
}

CEPH_CRUSH_MAP_BACKUP_DIR_FOR_AIO = '/etc/sysinv'
CEPH_CRUSH_MAP_BACKUP = 'crushmap.bin.backup'
CEPH_CRUSH_MAP_APPLIED = '.crushmap_applied'
CEPH_CRUSH_MAP_DEPTH = 3
CEPH_CRUSH_TIER_SUFFIX = "-tier"


# PCI Alias types and names
NOVA_PCI_ALIAS_GPU_NAME = "gpu"
NOVA_PCI_ALIAS_GPU_CLASS = "030000"
NOVA_PCI_ALIAS_GPU_PF_NAME = "gpu-pf"
NOVA_PCI_ALIAS_GPU_VF_NAME = "gpu-vf"
NOVA_PCI_ALIAS_QAT_CLASS = "0x0b4000"
NOVA_PCI_ALIAS_QAT_DH895XCC_PF_NAME = "qat-dh895xcc-pf"
NOVA_PCI_ALIAS_QAT_C62X_PF_NAME = "qat-c62x-pf"
NOVA_PCI_ALIAS_QAT_PF_VENDOR = "8086"
NOVA_PCI_ALIAS_QAT_DH895XCC_PF_DEVICE = "0435"
NOVA_PCI_ALIAS_QAT_C62X_PF_DEVICE = "37c8"
NOVA_PCI_ALIAS_QAT_DH895XCC_VF_NAME = "qat-dh895xcc-vf"
NOVA_PCI_ALIAS_QAT_C62X_VF_NAME = "qat-c62x-vf"
NOVA_PCI_ALIAS_QAT_VF_VENDOR = "8086"
NOVA_PCI_ALIAS_QAT_DH895XCC_VF_DEVICE = "0443"
NOVA_PCI_ALIAS_QAT_C62X_VF_DEVICE = "37c9"
NOVA_PCI_ALIAS_USER_NAME = "user"

# Service Parameter
SERVICE_TYPE_IDENTITY = 'identity'
SERVICE_TYPE_KEYSTONE = 'keystone'
SERVICE_TYPE_IMAGE = 'image'
SERVICE_TYPE_VOLUME = 'volume'
SERVICE_TYPE_HORIZON = "horizon"
SERVICE_TYPE_CINDER = 'cinder'
SERVICE_TYPE_PLATFORM = 'platform'
SERVICE_TYPE_RADOSGW = 'radosgw'
SERVICE_TYPE_GLANCE = 'glance'
SERVICE_TYPE_BARBICAN = 'barbican'
SERVICE_TYPE_DOCKER = 'docker'
SERVICE_TYPE_HTTP = 'http'
SERVICE_TYPE_OPENSTACK = 'openstack'
SERVICE_TYPE_KUBERNETES = 'kubernetes'
SERVICE_TYPE_PTP = 'ptp'
SERVICE_TYPE_CEPH = 'ceph'

# For service parameter sections that include a wildcard, any 'name' field will be
# allowed by the API. The wildcard card name will only be matched if no other matches
# are found first.
SERVICE_PARAM_NAME_WILDCARD = '*wildcard*'

SERVICE_PARAM_SECTION_IDENTITY_CONFIG = 'config'

SERVICE_PARAM_IDENTITY_CONFIG_TOKEN_EXPIRATION = 'token_expiration'
SERVICE_PARAM_IDENTITY_CONFIG_TOKEN_EXPIRATION_DEFAULT = 3600

SERVICE_PARAM_SECTION_IDENTITY_LDAP_DOMAIN1 = 'ldap-domain1'
SERVICE_PARAM_SECTION_IDENTITY_LDAP_DOMAIN2 = 'ldap-domain2'
SERVICE_PARAM_SECTION_IDENTITY_LDAP_DOMAIN3 = 'ldap-domain3'
SERVICE_PARAM_NAME_IDENTITY_LDAP_DOMAIN = 'domain_name'
SERVICE_PARAM_NAME_IDENTITY_LDAP_DOMAIN_DEFAULT = 'undef'
SERVICE_PARAM_NAME_IDENTITY_LDAP_URI = 'ldap_uri'
SERVICE_PARAM_NAME_IDENTITY_LDAP_ACCESS_FILTER = 'ldap_access_filter'
SERVICE_PARAM_NAME_IDENTITY_LDAP_SEARCH_BASE = 'ldap_search_base'
SERVICE_PARAM_NAME_IDENTITY_LDAP_USER_SEARCH_BASE = 'ldap_user_search_base'
SERVICE_PARAM_NAME_IDENTITY_LDAP_GROUP_SEARCH_BASE = 'ldap_group_search_base'
SERVICE_PARAM_NAME_IDENTITY_LDAP_DEFAULT_BIND_DN = 'ldap_default_bind_dn'
SERVICE_PARAM_NAME_IDENTITY_LDAP_DEFAULT_AUTH_TOK = 'ldap_default_authtok'

SERVICE_PARAM_PARAMETER_NAME_EXTERNAL_ADMINURL = 'external-admin-url'

# Platform Service Parameters
SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE = 'maintenance'
SERVICE_PARAM_SECTION_PLATFORM_SYSINV = 'sysinv'
SERVICE_PARAM_SECTION_PLATFORM_CONFIG = 'config'
SERVICE_PARAM_SECTION_PLATFORM_COREDUMP = 'coredump'
SERVICE_PARAM_SECTION_PLATFORM_POSTGRESQL = 'postgresql'

# Containerd runTimeClass CRI entries
SERVICE_PARAM_SECTION_PLATFORM_CRI_RUNTIME_CLASS = 'container_runtime'
SERVICE_PARAM_NAME_PLATFORM_CRI_RUNTIME_CLASS = 'custom_container_runtime'

SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT = 'worker_boot_timeout'
SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT = 'controller_boot_timeout'
SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD = 'heartbeat_period'
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION = 'heartbeat_failure_action'
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD = 'heartbeat_failure_threshold'
SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD = 'heartbeat_degrade_threshold'
SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD = 'mnfa_threshold'
SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT = 'mnfa_timeout'

SERVICE_PARAM_PLAT_MTCE_WORKER_BOOT_TIMEOUT_DEFAULT = 720
SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT_DEFAULT = 1200
SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD_DEFAULT = 100
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_ACTION_DEFAULT = 'fail'
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD_DEFAULT = 10
SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD_DEFAULT = 6
SERVICE_PARAM_PLAT_MTCE_MNFA_THRESHOLD_DEFAULT = 2
SERVICE_PARAM_PLAT_MTCE_MNFA_TIMEOUT_DEFAULT = 0

SERVICE_PARAM_NAME_PLAT_CONFIG_VIRTUAL = 'virtual_system'

SERVICE_PARAM_NAME_PLAT_CONFIG_INTEL_NIC_DRIVER_VERSION = 'intel_nic_driver_version'
SERVICE_PARAM_PLAT_CONFIG_INTEL_CVL_2_54 = 'cvl-2.54'
SERVICE_PARAM_PLAT_CONFIG_INTEL_CVL_4_0_1 = 'cvl-4.0.1'

# default time to live seconds
PM_TTL_DEFAULT = 86400

SERVICE_PARAM_SECTION_RADOSGW_CONFIG = 'config'
SERVICE_PARAM_NAME_RADOSGW_SERVICE_ENABLED = 'service_enabled'
SERVICE_PARAM_NAME_RADOSGW_FS_SIZE_MB = 'fs_size_mb'

# docker parameters
SERVICE_PARAM_SECTION_DOCKER_PROXY = 'proxy'
SERVICE_PARAM_NAME_DOCKER_HTTP_PROXY = 'http_proxy'
SERVICE_PARAM_NAME_DOCKER_HTTPS_PROXY = 'https_proxy'
SERVICE_PARAM_NAME_DOCKER_NO_PROXY = 'no_proxy'

SERVICE_PARAM_SECTION_DOCKER_REGISTRY = 'registry'

SERVICE_PARAM_SECTION_DOCKER_DOCKER_REGISTRY = 'docker-registry'
SERVICE_PARAM_SECTION_DOCKER_GCR_REGISTRY = 'gcr-registry'
SERVICE_PARAM_SECTION_DOCKER_K8S_REGISTRY = 'k8s-registry'
SERVICE_PARAM_SECTION_DOCKER_QUAY_REGISTRY = 'quay-registry'
SERVICE_PARAM_SECTION_DOCKER_ELASTIC_REGISTRY = 'elastic-registry'
SERVICE_PARAM_SECTION_DOCKER_GHCR_REGISTRY = 'ghcr-registry'
SERVICE_PARAM_SECTION_DOCKER_REGISTRYK8S_REGISTRY = 'registryk8s-registry'
SERVICE_PARAM_SECTION_DOCKER_ICR_REGISTRY = 'icr-registry'
SERVICE_PARAM_NAME_DOCKER_URL = 'url'
SERVICE_PARAM_NAME_DOCKER_AUTH_SECRET = 'auth-secret'
SERVICE_PARAM_NAME_DOCKER_TYPE = 'type'
SERVICE_PARAM_NAME_DOCKER_SECURE_REGISTRY = 'secure'
SERVICE_PARAM_NAME_DOCKER_ADDITIONAL_OVERRIDES = 'additional-overrides'

DOCKER_REGISTRY_TYPE_AWS_ECR = 'aws-ecr'
DOCKER_REGISTRY_TYPE_DOCKER = 'docker'

# default docker registries
DEFAULT_DOCKER_K8S_REGISTRY = 'k8s.gcr.io'
DEFAULT_DOCKER_GCR_REGISTRY = 'gcr.io'
DEFAULT_DOCKER_QUAY_REGISTRY = 'quay.io'
DEFAULT_DOCKER_DOCKER_REGISTRY = 'docker.io'
DEFAULT_DOCKER_ELASTIC_REGISTRY = 'docker.elastic.co'
DEFAULT_DOCKER_GHCR_REGISTRY = 'ghcr.io'
DEFAULT_DOCKER_REGISTRYK8S_REGISTRY = 'registry.k8s.io'
DEFAULT_DOCKER_ICR_REGISTRY = 'icr.io'

DEFAULT_REGISTRIES_INFO = {
    SERVICE_PARAM_SECTION_DOCKER_K8S_REGISTRY: {
        'registry_default': DEFAULT_DOCKER_K8S_REGISTRY,
        'registry_replaced': None,
        'registry_auth': None
    },
    SERVICE_PARAM_SECTION_DOCKER_GCR_REGISTRY: {
        'registry_default': DEFAULT_DOCKER_GCR_REGISTRY,
        'registry_replaced': None,
        'registry_auth': None
    },
    SERVICE_PARAM_SECTION_DOCKER_QUAY_REGISTRY: {
        'registry_default': DEFAULT_DOCKER_QUAY_REGISTRY,
        'registry_replaced': None,
        'registry_auth': None
    },
    SERVICE_PARAM_SECTION_DOCKER_DOCKER_REGISTRY: {
        'registry_default': DEFAULT_DOCKER_DOCKER_REGISTRY,
        'registry_replaced': None,
        'registry_auth': None
    },
    SERVICE_PARAM_SECTION_DOCKER_ELASTIC_REGISTRY: {
        'registry_default': DEFAULT_DOCKER_ELASTIC_REGISTRY,
        'registry_replaced': None,
        'registry_auth': None
    },
    SERVICE_PARAM_SECTION_DOCKER_GHCR_REGISTRY: {
        'registry_default': DEFAULT_DOCKER_GHCR_REGISTRY,
        'registry_replaced': None,
        'registry_auth': None
    },
    SERVICE_PARAM_SECTION_DOCKER_REGISTRYK8S_REGISTRY: {
        'registry_default': DEFAULT_DOCKER_REGISTRYK8S_REGISTRY,
        'registry_replaced': None,
        'registry_auth': None
    },
    SERVICE_PARAM_SECTION_DOCKER_ICR_REGISTRY: {
        'registry_default': DEFAULT_DOCKER_ICR_REGISTRY,
        'registry_replaced': None,
        'registry_auth': None
    }
}

# kubernetes parameters
SERVICE_PARAM_SECTION_KUBERNETES_CONFIG = 'config'
SERVICE_PARAM_NAME_KUBERNETES_POD_MAX_PIDS = 'pod_max_pids'
SERVICE_PARAM_NAME_KUBERNETES_AUTOMATIC_RECOVERY = 'automatic_recovery'
# Platform pods use under 20 in steady state, but allow extra room.
SERVICE_PARAM_KUBERNETES_POD_MAX_PIDS_MIN = 100
# Account for uncontrolled changes in applications (e.g. stx-openstack) by
# setting a very large number. Will document the recommended minimum value
# for supported applications.
SERVICE_PARAM_KUBERNETES_POD_MAX_PIDS_DEFAULT = 10000
SERVICE_PARAM_KUBERNETES_POD_MAX_PIDS_MAX = 65535

SERVICE_PARAM_SECTION_KUBERNETES_CERTIFICATES = 'certificates'
SERVICE_PARAM_NAME_KUBERNETES_API_SAN_LIST = 'apiserver_certsan'

SERVICE_PARAM_SECTION_KUBERNETES_APISERVER = 'kube_apiserver'
SERVICE_PARAM_SECTION_KUBERNETES_CONTROLLER_MANAGER = 'kube_controller_manager'
SERVICE_PARAM_SECTION_KUBERNETES_SCHEDULER = 'kube_scheduler'
SERVICE_PARAM_SECTION_KUBERNETES_KUBELET = 'kubelet'
SERVICE_PARAM_NAME_KUBERNETES_FEATURE_GATES = 'feature-gates'

SERVICE_PARAM_SECTION_KUBERNETES_APISERVER_VOLUMES = 'kube_apiserver_volumes'
SERVICE_PARAM_SECTION_KUBERNETES_CONTROLLER_MANAGER_VOLUMES = 'kube_controller_manager_volumes'
SERVICE_PARAM_SECTION_KUBERNETES_SCHEDULER_VOLUMES = 'kube_scheduler_volumes'

SERVICE_PARAM_NAME_OIDC_ISSUER_URL = 'oidc-issuer-url'
SERVICE_PARAM_NAME_OIDC_CLIENT_ID = 'oidc-client-id'
SERVICE_PARAM_NAME_OIDC_USERNAME_CLAIM = 'oidc-username-claim'
SERVICE_PARAM_NAME_OIDC_GROUPS_CLAIM = 'oidc-groups-claim'
SERVICE_PARAM_DEPRECATED_NAME_OIDC_ISSUER_URL = 'oidc_issuer_url'
SERVICE_PARAM_DEPRECATED_NAME_OIDC_CLIENT_ID = 'oidc_client_id'
SERVICE_PARAM_DEPRECATED_NAME_OIDC_USERNAME_CLAIM = 'oidc_username_claim'
SERVICE_PARAM_DEPRECATED_NAME_OIDC_GROUPS_CLAIM = 'oidc_groups_claim'

# ptp service parameters
SERVICE_PARAM_SECTION_PTP_GLOBAL = 'global'
SERVICE_PARAM_SECTION_PTP_PHC2SYS = 'phc2sys'
SERVICE_PARAM_NAME_PTP_UPDATE_RATE = 'update-rate'
SERVICE_PARAM_NAME_PTP_SUMMARY_UPDATES = 'summary-updates'

PTP_PHC2SYS_DEFAULTS = {
    SERVICE_PARAM_NAME_PTP_UPDATE_RATE: 10,
    SERVICE_PARAM_NAME_PTP_SUMMARY_UPDATES: 600
}

PTP_PHC2SYS_OPTIONS_MAP = {
    SERVICE_PARAM_NAME_PTP_UPDATE_RATE: 'R',
    SERVICE_PARAM_NAME_PTP_SUMMARY_UPDATES: 'u'
}

# default filesystem size to 25 MB
SERVICE_PARAM_RADOSGW_FS_SIZE_MB_DEFAULT = 25

# HTTP Service Parameters
SERVICE_PARAM_SECTION_HTTP_CONFIG = 'config'
SERVICE_PARAM_HTTP_PORT_HTTP = 'http_port'
SERVICE_PARAM_HTTP_PORT_HTTPS = 'https_port'
SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT = 8080
SERVICE_PARAM_HTTP_PORT_HTTPS_DEFAULT = 8443

# Openstack Service Parameters
SERVICE_PARAM_SECTION_OPENSTACK_HELM = 'helm'
SERVICE_PARAM_NAME_ENDPOINT_DOMAIN = "endpoint_domain"

# Collectd Service Parameters
SERVICE_PARAM_SECTION_COLLECTD = 'collectd'
SERVICE_PARAM_COLLECTD_NETWORK_SERVERS = 'network_servers'

# platform kernel parameter auditd
# enables and disables auditd
SERVICE_PARAM_SECTION_PLATFORM_KERNEL = 'kernel'
SERVICE_PARAM_NAME_PLATFORM_AUDITD = 'audit'
SERVICE_PARAM_PLATFORM_AUDITD_DISABLED = '0'
SERVICE_PARAM_PLATFORM_AUDITD_ENABLED = '1'

# platform keystone security compliance config
SERVICE_PARAM_SECTION_SECURITY_COMPLIANCE = 'security_compliance'
SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_UNIQUE_LAST_PASSWORD_COUNT = 'unique_last_password_count'
SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_PASSWORD_REGEX = 'password_regex'
SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_PASSWORD_REGEX_DESCRIPTION = 'password_regex_description'
SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_LOCKOUT_DURATION = \
    'lockout_seconds'
SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_LOCKOUT_FAILURE_ATTEMPTS = \
    'lockout_retries'
SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_LOCKOUT_DURATION_DEFAULT = 1800
SERVICE_PARAM_NAME_SECURITY_COMPLIANCE_LOCKOUT_FAILURE_ATTEMPTS_DEFAULT = 5

# Platform coredump parameter
SERVICE_PARAM_NAME_PLATFORM_PROCESS_SIZE_MAX = 'process_size_max'
SERVICE_PARAM_NAME_PLATFORM_EXTERNAL_SIZE_MAX = 'external_size_max'
SERVICE_PARAM_NAME_PLATFORM_MAX_USE = 'max_use'
SERVICE_PARAM_NAME_PLATFORM_KEEP_FREE = 'keep_free'

SERVICE_PARAM_PLAT_PROCESS_SIZE_MAX_MINSIZE = 0
SERVICE_PARAM_PLAT_EXTERNAL_SIZE_MAX_MINSIZE = 0
SERVICE_PARAM_PLAT_MAX_USE_MINSIZE = 0
SERVICE_PARAM_PLAT_KEEP_FREE_MINSIZE = '1G'

# Platform postgres parameters
SERVICE_PARAM_NAME_POSTGRESQL_AUTOVACUUM_WORKERS = 'autovacuum_max_workers'
SERVICE_PARAM_NAME_POSTGRESQL_MAX_WORKER_PROCESSES = 'max_worker_processes'
SERVICE_PARAM_NAME_POSTGRESQL_MAX_PARALLEL_WORKERS = 'max_parallel_workers'
SERVICE_PARAM_NAME_POSTGRESQL_MAX_PARALLEL_MAINTENANCE_WORKERS = 'max_parallel_maintenance_workers'
SERVICE_PARAM_NAME_POSTGRESQL_MAX_PARALLEL_WORKERS_PER_GATHER = 'max_parallel_workers_per_gather'

# Ceph Service Parameters
SERVICE_PARAM_SECTION_CEPH_MONITOR = 'monitor'
SERVICE_PARAM_NAME_CEPH_MONITOR_AUTH_ID_RECLAIM = 'auth_id_reclaim'

# Worker Host CPU parameters
SERVICE_PARAM_NAME_PLATFORM_MAX_CPU_PERCENTAGE = 'cpu_max_freq_min_percentage'
SERVICE_PARAM_PLATFORM_MAX_CPU_PERCENTAGE_DEFAULT = 80

# TIS part number, CPE = combined load, STD = standard load
TIS_STD_BUILD = 'Standard'
TIS_AIO_BUILD = 'All-in-one'

# Free space needed on CentOS for Debian upgrade
WORKER_UPGRADE_FREE_SPACE_NEEDED_IN_GIB = 23.5
# Total disk space needed on CentOS for Debian upgrade
STORAGE_UPGRADE_SPACE_NEEDED_IN_GIB = 118
CONTROLLER_UPGRADE_SPACE_NEEDED_IN_GIB = 220

# Platform Upgrade states
UPGRADE_STARTING = 'starting'
UPGRADE_STARTED = 'started'
UPGRADE_DATA_MIGRATION = 'data-migration'
UPGRADE_DATA_MIGRATION_COMPLETE = 'data-migration-complete'
UPGRADE_DATA_MIGRATION_FAILED = 'data-migration-failed'
UPGRADE_UPGRADING_CONTROLLERS = 'upgrading-controllers'
UPGRADE_UPGRADING_HOSTS = 'upgrading-hosts'
UPGRADE_ACTIVATION_REQUESTED = 'activation-requested'
UPGRADE_ACTIVATING = 'activating'
UPGRADE_ACTIVATING_HOSTS = 'activating-hosts'
UPGRADE_ACTIVATION_FAILED = 'activation-failed'
UPGRADE_ACTIVATION_COMPLETE = 'activation-complete'
UPGRADE_COMPLETING = 'completing'
UPGRADE_COMPLETED = 'completed'
UPGRADE_ABORTING = 'aborting'
UPGRADE_ABORT_COMPLETING = 'abort-completing'
UPGRADE_ABORTING_ROLLBACK = 'aborting-reinstall'

# Upgrade Manifests Timeout
UPGRADE_ACTIVATION_MANIFEST_TIMEOUT_IN_SECS = 600

# List of all Platform Upgrade States
PLATFORM_UPGRADE_STATES = [
    UPGRADE_STARTING,
    UPGRADE_STARTED,
    UPGRADE_DATA_MIGRATION,
    UPGRADE_DATA_MIGRATION_COMPLETE,
    UPGRADE_DATA_MIGRATION_FAILED,
    UPGRADE_UPGRADING_CONTROLLERS,
    UPGRADE_UPGRADING_HOSTS,
    UPGRADE_ACTIVATION_REQUESTED,
    UPGRADE_ACTIVATING,
    UPGRADE_ACTIVATING_HOSTS,
    UPGRADE_ACTIVATION_FAILED,
    UPGRADE_ACTIVATION_COMPLETE,
    UPGRADE_COMPLETING,
    UPGRADE_COMPLETED,
    UPGRADE_ABORTING,
    UPGRADE_ABORT_COMPLETING,
    UPGRADE_ABORTING_ROLLBACK
]

# Restore states
RESTORE_STATE_IN_PROGRESS = 'restore-in-progress'
RESTORE_STATE_COMPLETED = 'restore-completed'

# Restore progress constants
RESTORE_PROGRESS_ALREADY_COMPLETED = "Restore procedure already completed"
RESTORE_PROGRESS_STARTED = "Restore procedure started"
RESTORE_PROGRESS_ALREADY_IN_PROGRESS = "Restore procedure already in progress"
RESTORE_PROGRESS_NOT_IN_PROGRESS = "Restore procedure is not in progress"
RESTORE_PROGRESS_IN_PROGRESS = "Restore procedure is in progress"
RESTORE_PROGRESS_COMPLETED = "Restore procedure completed"

# LLDP
LLDP_OVS_PORT_PREFIX = 'lldp'
LLDP_OVS_PORT_NAME_LEN = 15
LLDP_MULTICAST_ADDRESS = '01:80:c2:00:00:0e'
LLDP_ETHER_TYPE = '0x88cc'
LLDP_TLV_TYPE_CHASSIS_ID = 'chassis_id'
LLDP_TLV_TYPE_PORT_ID = 'port_identifier'
LLDP_TLV_TYPE_TTL = 'ttl'
LLDP_TLV_TYPE_SYSTEM_NAME = 'system_name'
LLDP_TLV_TYPE_SYSTEM_DESC = 'system_description'
LLDP_TLV_TYPE_SYSTEM_CAP = 'system_capabilities'
LLDP_TLV_TYPE_MGMT_ADDR = 'management_address'
LLDP_TLV_TYPE_PORT_DESC = 'port_description'
LLDP_TLV_TYPE_DOT1_LAG = 'dot1_lag'
LLDP_TLV_TYPE_DOT1_PORT_VID = 'dot1_port_vid'
LLDP_TLV_TYPE_DOT1_MGMT_VID = 'dot1_management_vid'
LLDP_TLV_TYPE_DOT1_PROTO_VIDS = 'dot1_proto_vids'
LLDP_TLV_TYPE_DOT1_PROTO_IDS = 'dot1_proto_ids'
LLDP_TLV_TYPE_DOT1_VLAN_NAMES = 'dot1_vlan_names'
LLDP_TLV_TYPE_DOT1_VID_DIGEST = 'dot1_vid_digest'
LLDP_TLV_TYPE_DOT3_MAC_STATUS = 'dot3_mac_status'
LLDP_TLV_TYPE_DOT3_MAX_FRAME = 'dot3_max_frame'
LLDP_TLV_TYPE_DOT3_POWER_MDI = 'dot3_power_mdi'
LLDP_TLV_VALID_LIST = [LLDP_TLV_TYPE_CHASSIS_ID, LLDP_TLV_TYPE_PORT_ID,
                       LLDP_TLV_TYPE_TTL, LLDP_TLV_TYPE_SYSTEM_NAME,
                       LLDP_TLV_TYPE_SYSTEM_DESC, LLDP_TLV_TYPE_SYSTEM_CAP,
                       LLDP_TLV_TYPE_MGMT_ADDR, LLDP_TLV_TYPE_PORT_DESC,
                       LLDP_TLV_TYPE_DOT1_LAG, LLDP_TLV_TYPE_DOT1_PORT_VID,
                       LLDP_TLV_TYPE_DOT1_VID_DIGEST,
                       LLDP_TLV_TYPE_DOT1_MGMT_VID,
                       LLDP_TLV_TYPE_DOT1_PROTO_VIDS,
                       LLDP_TLV_TYPE_DOT1_PROTO_IDS,
                       LLDP_TLV_TYPE_DOT1_VLAN_NAMES,
                       LLDP_TLV_TYPE_DOT1_VID_DIGEST,
                       LLDP_TLV_TYPE_DOT3_MAC_STATUS,
                       LLDP_TLV_TYPE_DOT3_MAX_FRAME,
                       LLDP_TLV_TYPE_DOT3_POWER_MDI]

LLDP_AGENT_STATE_REMOVED = 'removed'
LLDP_NEIGHBOUR_STATE_REMOVED = LLDP_AGENT_STATE_REMOVED
# LLDP_FULL_AUDIT_COUNT based on frequency of host_lldp_get_and_report()
LLDP_FULL_AUDIT_COUNT = 6

# Fault Management
FM_SUPPRESSED = 'suppressed'
FM_UNSUPPRESSED = 'unsuppressed'

# sysadmin password aging.
# Setting aging to max defined value qualifies
# as "never" on certain Linux distros including WRL
SYSADMIN_PASSWORD_NO_AGING = 99999

# SDN Controller
SDN_CONTROLLER_STATE_ENABLED = 'enabled'
SDN_CONTROLLER_STATE_DISABLED = 'disabled'

# Partition table size in bytes.
PARTITION_TABLE_SIZE = 2097152

# States that describe the states of a partition.

# Partition is ready for being used.
PARTITION_READY_STATUS = 0
# Partition is used by a PV.
PARTITION_IN_USE_STATUS = 1
# An in-service request to create the partition has been sent.
PARTITION_CREATE_IN_SVC_STATUS = 2
# An unlock request to create the partition has been sent.
PARTITION_CREATE_ON_UNLOCK_STATUS = 3
# A request to delete the partition has been sent.
PARTITION_DELETING_STATUS = 4
# A request to modify the partition has been sent.
PARTITION_MODIFYING_STATUS = 5
# The partition has been deleted.
PARTITION_DELETED_STATUS = 6
# The creation of the partition has encountered a known error.
PARTITION_ERROR_STATUS = 10
# Partition creation failed due to an internal error, check packstack logs.
PARTITION_ERROR_STATUS_INTERNAL = 11
# Partition was not created because disk does not have a GPT.
PARTITION_ERROR_STATUS_GPT = 12

PARTITION_STATUS_MSG = {
    PARTITION_IN_USE_STATUS: "In-Use",
    PARTITION_CREATE_IN_SVC_STATUS: "Creating",
    PARTITION_CREATE_ON_UNLOCK_STATUS: "Creating (on unlock)",
    PARTITION_DELETING_STATUS: "Deleting",
    PARTITION_MODIFYING_STATUS: "Modifying",
    PARTITION_READY_STATUS: "Ready",
    PARTITION_DELETED_STATUS: "Deleted",
    PARTITION_ERROR_STATUS: "Error",
    PARTITION_ERROR_STATUS_INTERNAL: "Error: Internal script error.",
    PARTITION_ERROR_STATUS_GPT: "Error:Missing GPT Table."}

PARTITION_STATUS_OK_TO_DELETE = [
    PARTITION_READY_STATUS,
    PARTITION_CREATE_ON_UNLOCK_STATUS,
    PARTITION_ERROR_STATUS,
    PARTITION_ERROR_STATUS_INTERNAL,
    PARTITION_ERROR_STATUS_GPT]

PARTITION_STATUS_SEND_DELETE_RPC = [
    PARTITION_READY_STATUS,
    PARTITION_ERROR_STATUS,
    PARTITION_ERROR_STATUS_INTERNAL]

PARTITION_CMD_CREATE = "create"
PARTITION_CMD_DELETE = "delete"
PARTITION_CMD_MODIFY = "modify"

# User creatable, system managed,  GUID partitions types.
PARTITION_USER_MANAGED_GUID_PREFIX = "ba5eba11-0000-1111-2222-"
USER_PARTITION_PHYSICAL_VOLUME = PARTITION_USER_MANAGED_GUID_PREFIX + "000000000001"
# Note that 000000000002 is used for the persistent backup partition
LINUX_LVM_PARTITION = "e6d6d379-f507-44c2-a23c-238f2a3df928"
CEPH_REGULAR_OSD_GUID = "4FBD7E29-9D25-41B8-AFD0-062C0CEFF05D"
CEPH_REGULAR_JOURNAL_GUID = "45B0969E-9B03-4F30-B4C6-B4B80CEFF106"
CEPH_MPATH_OSD_GUID = "4FBD7E29-8AE0-4982-BF9D-5A8D867AF560"
CEPH_MPATH_JOURNAL_GUID = "45B0969E-8AE0-4982-BF9D-5A8D867AF560"

CEPH_PARTITIONS = [CEPH_REGULAR_OSD_GUID,
                   CEPH_MPATH_OSD_GUID,
                   CEPH_REGULAR_JOURNAL_GUID,
                   CEPH_MPATH_JOURNAL_GUID]

# Partition name for those partitions designated for PV use.
PARTITION_NAME_PV = "LVM Physical Volume"

# Partition table types.
PARTITION_TABLE_GPT = "gpt"
PARTITION_TABLE_MSDOS = "msdos"

PARTITION_MANAGE_LOCK = "partition-manage"

# Optional services
ALL_OPTIONAL_SERVICES = [SERVICE_TYPE_CINDER,
                         SERVICE_TYPE_RADOSGW]

# System mode
SYSTEM_MODE_DUPLEX = "duplex"
SYSTEM_MODE_SIMPLEX = "simplex"
SYSTEM_MODE_DUPLEX_DIRECT = "duplex-direct"

# System Security Profiles
SYSTEM_SECURITY_PROFILE_STANDARD = "standard"
SYSTEM_SECURITY_PROFILE_EXTENDED = "extended"

# Install states
INSTALL_STATE_PRE_INSTALL = "preinstall"
INSTALL_STATE_INSTALLING = "installing"
INSTALL_STATE_POST_INSTALL = "postinstall"
INSTALL_STATE_FAILED = "failed"
INSTALL_STATE_INSTALLED = "installed"
INSTALL_STATE_BOOTING = "booting"
INSTALL_STATE_COMPLETED = "completed"

tox_work_dir = os.environ.get("TOX_WORK_DIR")
if tox_work_dir:
    SYSINV_VOLATILE_PATH = tox_work_dir
else:
    SYSINV_VOLATILE_PATH = os.path.join(tsc.VOLATILE_PATH, "sysinv")

SYSINV_FIRST_REPORT_FLAG = os.path.join(SYSINV_VOLATILE_PATH,
                                        ".sysinv_agent_first_report_sent")
SYSINV_REPORTED = os.path.join(SYSINV_VOLATILE_PATH,
                               ".sysinv_reported")

NETWORK_CONFIG_LOCK_FILE = os.path.join(
    tsc.VOLATILE_PATH, "apply_network_config.lock")

SYSINV_USERNAME = "sysinv"
SYSINV_GRPNAME = "sysinv"
SYSINV_SYSADMIN_GRPNAME = "sys_protected"

# This is the first report sysinv is sending to conductor since boot
SYSINV_AGENT_FIRST_REPORT = 'first_report'

# SSL configuration
CERT_TYPE_SSL = 'ssl'
SSL_CERT_DIR = "/etc/ssl/private/"
SSL_CERT_FILE = "server-cert.pem"  # pem with PK and cert
# self signed pem to get started
SSL_CERT_SS_FILE = "self-signed-server-cert.pem"
CERT_FILE = "cert.pem"
CERT_KEY_FILE = "key.pem"
CERT_CA_FILE = "ca-cert.pem"
SSL_PEM_FILE = os.path.join(SSL_CERT_DIR, SSL_CERT_FILE)
SSL_PEM_SS_FILE = os.path.join(SSL_CERT_DIR, SSL_CERT_SS_FILE)
SSL_PEM_FILE_SHARED = os.path.join(tsc.CONFIG_PATH, SSL_CERT_FILE)

DOCKER_REGISTRY_USER = 'sysinv'
DOCKER_REGISTRY_HOST = 'registry.local'
DOCKER_REGISTRY_PORT = '9001'
DOCKER_REGISTRY_SERVER = '%s:%s' % (DOCKER_REGISTRY_HOST, DOCKER_REGISTRY_PORT)
DOCKER_REGISTRY_CERT_FILE = os.path.join(SSL_CERT_DIR, "registry-cert.crt")
DOCKER_REGISTRY_KEY_FILE = os.path.join(SSL_CERT_DIR, "registry-cert.key")
DOCKER_REGISTRY_PKCS1_KEY_FILE = os.path.join(SSL_CERT_DIR,
                                              "registry-cert-pkcs1.key")
DOCKER_REGISTRY_CERT_FILE_SHARED = os.path.join(tsc.CONFIG_PATH,
                                                "registry-cert.crt")
DOCKER_REGISTRY_KEY_FILE_SHARED = os.path.join(tsc.CONFIG_PATH,
                                               "registry-cert.key")
DOCKER_REGISTRY_PKCS1_KEY_FILE_SHARED = os.path.join(tsc.CONFIG_PATH,
                                              "registry-cert-pkcs1.key")

SSL_CERT_CA_DIR = "/etc/pki/ca-trust/source/anchors/"
SSL_CERT_CA_FILE = os.path.join(SSL_CERT_CA_DIR, CERT_CA_FILE)
SSL_CERT_CA_FILE_SHARED = os.path.join(tsc.CONFIG_PATH, CERT_CA_FILE)
SSL_CERT_CA_LIST_SHARED_DIR = os.path.join(tsc.CONFIG_PATH, "ssl_ca")

KUBERNETES_PKI_SHARED_DIR = os.path.join(tsc.CONFIG_PATH, "kubernetes/pki")

CERT_OPENSTACK_DIR = "/etc/ssl/private/openstack"
CERT_OPENSTACK_SHARED_DIR = os.path.join(tsc.CONFIG_PATH, 'openstack')
OPENSTACK_CERT_FILE = os.path.join(CERT_OPENSTACK_DIR, CERT_FILE)
OPENSTACK_CERT_KEY_FILE = os.path.join(CERT_OPENSTACK_DIR, CERT_KEY_FILE)
OPENSTACK_CERT_CA_FILE = os.path.join(CERT_OPENSTACK_DIR, CERT_CA_FILE)
OPENSTACK_CERT_FILE_SHARED = os.path.join(CERT_OPENSTACK_SHARED_DIR,
                                          CERT_FILE)
OPENSTACK_CERT_KEY_FILE_SHARED = os.path.join(CERT_OPENSTACK_SHARED_DIR,
                                              CERT_KEY_FILE)
OPENSTACK_CERT_CA_FILE_SHARED = os.path.join(CERT_OPENSTACK_SHARED_DIR,
                                             CERT_CA_FILE)

CERT_MODE_KUBERNETES_ROOT_CA = 'kubernetes-root-ca'
CERT_MODE_ETCD = 'etcd'
CERT_MODE_SSL = 'ssl'
CERT_MODE_SSL_CA = 'ssl_ca'
CERT_MODE_DOCKER_REGISTRY = 'docker_registry'
CERT_MODE_OPENSTACK = 'openstack'
CERT_MODE_OPENSTACK_CA = 'openstack_ca'
CERT_MODE_OPENLDAP = 'openldap'
CERT_MODE_OPENLDAP_CA = 'openldap_ca'
CERT_MODES_SUPPORTED = [CERT_MODE_SSL,
                        CERT_MODE_SSL_CA,
                        CERT_MODE_DOCKER_REGISTRY,
                        CERT_MODE_OPENSTACK,
                        CERT_MODE_OPENSTACK_CA,
                        CERT_MODE_OPENLDAP,
                        CERT_MODE_OPENLDAP_CA,
                        ]
CERT_MODES_SUPPORTED_CERT_MANAGER = [CERT_MODE_SSL,
                                     CERT_MODE_DOCKER_REGISTRY,
                                     CERT_MODE_OPENLDAP]

KUBERNETES_ROOTCA_FILE = '/etc/kubernetes/pki/ca.crt'
ETCD_ROOTCA_FILE = '/etc/etcd/ca.crt'

# CONFIG file permissions
CONFIG_FILE_PERMISSION_ROOT_READ_ONLY = 0o400
CONFIG_FILE_PERMISSION_DEFAULT = 0o644

# TPM configuration states
TPMCONFIG_APPLYING = "tpm-config-applying"
TPMCONFIG_PARTIALLY_APPLIED = "tpm-config-partially-applied"
TPMCONFIG_APPLIED = "tpm-config-applied"
TPMCONFIG_FAILED = "tpm-config-failed"

# timezone
TIME_ZONE_UTC = "UTC"

# Semantic check messages
WARNING_MESSAGE_INDEX = 'warning_message_index'
WARN_CINDER_ON_ROOT_WITH_LVM = 1
WARN_CINDER_ON_ROOT_WITH_CEPH = 2
WARNING_ROOT_PV_CINDER_LVM_MSG = (
    "Warning: All deployed VMs must be booted from Cinder volumes and "
    "not use ephemeral or swap disks. See StarlingX System Engineering "
    "Guidelines for more details on supported worker configurations.")
WARNING_ROOT_PV_CINDER_CEPH_MSG = (
    "Warning: This worker must use a secondary disk for local storage. "
    "See StarlingX System Engineering Guidelines for more details on "
    "supported worker configurations.")
PV_WARNINGS = {WARN_CINDER_ON_ROOT_WITH_LVM: WARNING_ROOT_PV_CINDER_LVM_MSG,
               WARN_CINDER_ON_ROOT_WITH_CEPH: WARNING_ROOT_PV_CINDER_CEPH_MSG}

# License file
LICENSE_FILE = ".license"

# Cinder lvm config complete file.
NODE_CINDER_LVM_CONFIG_COMPLETE_FILE = \
    os.path.join(tsc.PLATFORM_CONF_PATH, '.node_cinder_lvm_config_complete')
INITIAL_CINDER_LVM_CONFIG_COMPLETE_FILE = \
    os.path.join(tsc.CONFIG_PATH, '.initial_cinder_lvm_config_complete')

DISK_WIPE_IN_PROGRESS_FLAG = \
    os.path.join(tsc.PLATFORM_CONF_PATH, '.disk_wipe_in_progress')
DISK_WIPE_COMPLETE_TIMEOUT = 5  # wait for a disk to finish wiping.

# Clone label set in DB
CLONE_ISO_MAC = 'CLONEISOMAC_'
CLONE_ISO_DISK_SID = 'CLONEISODISKSID_'

DISTRIBUTED_CLOUD_ROLE_SUBCLOUD = 'subcloud'

DISTRIBUTED_CLOUD_ROLE_SYSTEMCONTROLLER = 'systemcontroller'

GLANCE_DEFAULT_PIPELINE = 'keystone'
GLANCE_CACHE_PIPELINE = 'keystone+cachemanagement'
GLANCE_LOCAL_REGISTRY = '0.0.0.0'
GLANCE_SQLALCHEMY_DATA_API = 'glance.db.sqlalchemy.api'
GLANCE_REGISTRY_DATA_API = 'glance.db.registry.api'

# kernel options for various security feature selections
SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_V1 = 'spectre_meltdown_v1'
SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_V1_OPTS = 'nopti nospectre_v2 nospectre_v1'
SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_ALL = 'spectre_meltdown_all'
SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_ALL_OPTS = ''
SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_OPTS = {
    SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_V1: SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_V1_OPTS,
    SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_ALL: SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_ALL_OPTS
}


SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_DEFAULT_OPTS = SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_V1_OPTS

# Helm: Supported application (aka chart bundles)
HELM_APP_OPENSTACK = 'openstack'
HELM_APP_PLATFORM = 'platform-integ-apps'
HELM_APP_OIDC_AUTH = 'oidc-auth-apps'
HELM_APP_CERT_MANAGER = 'cert-manager'
HELM_APP_NGINX_IC = 'nginx-ingress-controller'
HELM_APP_VAULT = 'vault'
HELM_APP_ROOK_CEPH = 'rook-ceph-apps'
HELM_APP_SNMP = 'snmp'
HELM_APP_PTP_NOTIFICATION = 'ptp-notification'
HELM_APP_PORTIERIS = 'portieris'

# Apply mode for openstack app
OPENSTACK_RESTORE_DB = 'restore_db'
OPENSTACK_RESTORE_STORAGE = 'restore_storage'
OPENSTACK_NORMAL = 'normal'

OPENSTACK_APP_APPLY_MODES = [
    OPENSTACK_RESTORE_DB,
    OPENSTACK_RESTORE_STORAGE,
    OPENSTACK_NORMAL
]

# Application Apply Modes
HELM_APP_APPLY_MODES = {
    HELM_APP_OPENSTACK: OPENSTACK_APP_APPLY_MODES
}

HELM_APP_ISO_INSTALL_PATH = '/usr/local/share/applications/helm'

# RBD Provisioner Ceph backend capabilities fields
K8S_RBD_PROV_STORAGECLASS_NAME = 'rbd_storageclass_name'             # Customer
K8S_RBD_PROV_NAMESPACES = 'rbd_provisioner_namespaces'               # Customer
K8S_RBD_PROV_NAMESPACES_READY = '.rbd_provisioner_namespaces_ready'  # Hidden

# RBD Provisioner defaults and constants
K8S_RBD_PROV_NAMESPACE_DEFAULT = "kube-system"
K8S_RBD_PROV_USER_NAME = 'admin'
K8S_RBD_PROV_ADMIN_SECRET_NAME = 'ceph-admin'
K8S_RBD_PROV_STOR_CLASS_NAME = 'general'

##################################
# Kubernetes application section #
##################################
# Working paths
APP_INSTALL_ROOT_PATH = '/scratch'
APP_INSTALL_PATH = APP_INSTALL_ROOT_PATH + '/apps'
APP_METADATA_FILE = 'metadata.yaml'
APP_PENDING_REAPPLY_FLAG = os.path.join(
    tsc.HELM_OVERRIDES_PATH, ".app_reapply")

# Armada
APP_SYNCED_ARMADA_DATA_PATH = os.path.join(tsc.PLATFORM_PATH, 'armada', tsc.SW_VERSION)

# FluxCD
APP_FLUXCD_MANIFEST_DIR = 'fluxcd-manifests'
APP_FLUXCD_DATA_PATH = os.path.join(tsc.PLATFORM_PATH, 'fluxcd', tsc.SW_VERSION)
APP_ROOT_KUSTOMIZE_FILE = 'kustomization.yaml'
APP_HELMREPOSITORY_FILE = "helmrepository.yaml"
APP_BASE_HELMREPOSITORY_FILE = os.path.join("base", APP_HELMREPOSITORY_FILE)
APP_RELEASE_CLEANUP_FILE = 'helmrelease_cleanup.yaml'
FLUXCD_CRD_HELM_REL_GROUP = 'helm.toolkit.fluxcd.io'
FLUXCD_CRD_HELM_REL_VERSION = 'v2beta1'
FLUXCD_CRD_HELM_REL_PLURAL = 'helmreleases'
FLUXCD_CRD_HELM_REPO_GROUP = 'source.toolkit.fluxcd.io'
FLUXCD_CRD_HELM_REPO_VERSION = 'v1beta1'
FLUXCD_CRD_HELM_REPO_PLURAL = 'helmrepositories'
FLUXCD_CRD_HELM_CHART_GROUP = 'source.toolkit.fluxcd.io'
FLUXCD_CRD_HELM_CHART_VERSION = 'v1beta1'
FLUXCD_CRD_HELM_CHART_PLURAL = 'helmcharts'
# Actually beginning of errors, should be used with
# string.startswith(FLUXCD_RECOVERY_HELM_RELEASE_STATUS_ERRORS[number])
# We want to recover from these errors
FLUXCD_RECOVERY_HELM_RELEASE_STATUS_ERRORS = [
    'Helm upgrade failed: another operation (install/upgrade/rollback) is in progress'
]
FLUXCD_RECOVERABLE_HELM_RELEASE_STATUS = [
    'pending-install',
    'pending-upgrade',
    'pending-rollback'
]
FLUXCD_NAMESPACE = "flux-helm"
FLUXCD_HELM_CONTROLLER_LABEL = "helm-controller"
FLUXCD_SOURCE_CONTROLLER_LABEL = "source-controller"

# State constants
APP_NOT_PRESENT = 'missing'
APP_UPLOAD_IN_PROGRESS = 'uploading'
APP_UPLOAD_SUCCESS = 'uploaded'
APP_UPLOAD_FAILURE = 'upload-failed'
APP_APPLY_IN_PROGRESS = 'applying'
APP_APPLY_SUCCESS = 'applied'
APP_APPLY_FAILURE = 'apply-failed'
APP_REMOVE_IN_PROGRESS = 'removing'
APP_REMOVE_FAILURE = 'remove-failed'
APP_INACTIVE_STATE = 'inactive'
APP_UPDATE_IN_PROGRESS = 'updating'
APP_RECOVER_IN_PROGRESS = 'recovering'
APP_RESTORE_REQUESTED = 'restore-requested'

# Operation constants
APP_VALIDATE_OP = 'validate'
APP_UPLOAD_OP = 'upload'
APP_APPLY_OP = 'apply'
APP_REMOVE_OP = 'remove'
APP_DELETE_OP = 'delete'
APP_UPDATE_OP = 'update'
APP_ROLLBACK_OP = 'rollback'
APP_ABORT_OP = 'abort'
APP_EVALUATE_REAPPLY_OP = 'evaluate-reapply'
# Backup/Restore lifecycle actions:
APP_BACKUP = 'backup'
APP_ETCD_BACKUP = 'etcd-backup'
APP_RESTORE = 'restore'

# Lifecycle constants
APP_LIFECYCLE_TIMING_PRE = 'pre'
APP_LIFECYCLE_TIMING_POST = 'post'

APP_LIFECYCLE_TYPE_SEMANTIC_CHECK = 'check'
APP_LIFECYCLE_TYPE_OPERATION = 'operation'
APP_LIFECYCLE_TYPE_RBD = 'rbd'
APP_LIFECYCLE_TYPE_RESOURCE = 'resource'
# armada manifest
# outside the function that has the retry decorator
APP_LIFECYCLE_TYPE_MANIFEST = 'manifest'
# inside the function that has a retry decorator
APP_LIFECYCLE_TYPE_ARMADA_REQUEST = 'armada-request'
# same as armada
APP_LIFECYCLE_TYPE_FLUXCD_REQUEST = 'fluxcd-request'

APP_LIFECYCLE_MODE_MANUAL = 'manual'
APP_LIFECYCLE_MODE_AUTO = 'auto'
APP_LIFECYCLE_FORCE_OPERATION = 'force'
APP_LIFECYCLE_OPERATION_MTC_ACTION = 'mtc-action'

BACKUP_ACTION_NOTIFY_SUCCESS = 'success'
BACKUP_ACTION_NOTIFY_FAILURE = 'failure'

BACKUP_ACTION_SEMANTIC_CHECK = 'backup-semantic-check'
BACKUP_ACTION_PRE_BACKUP = 'pre-backup-action'
BACKUP_ACTION_PRE_ETCD_BACKUP = 'pre-etcd-backup-action'
BACKUP_ACTION_POST_ETCD_BACKUP = 'post-etcd-backup-action'
BACKUP_ACTION_POST_BACKUP = 'post-backup-action'
BACKUP_ACTION_PRE_RESTORE = 'pre-restore-action'
BACKUP_ACTION_POST_RESTORE = 'post-restore-action'

# backup/restore parameters from the command line utility:
HOOK_PARAMETERS_MAP = {
    BACKUP_ACTION_SEMANTIC_CHECK: [APP_LIFECYCLE_MODE_AUTO,
                                   APP_LIFECYCLE_TYPE_SEMANTIC_CHECK,
                                   APP_LIFECYCLE_TIMING_PRE,
                                   APP_BACKUP],
    BACKUP_ACTION_PRE_BACKUP: [APP_LIFECYCLE_MODE_AUTO,
                               APP_LIFECYCLE_TYPE_OPERATION,
                               APP_LIFECYCLE_TIMING_PRE,
                               APP_BACKUP],
    BACKUP_ACTION_POST_BACKUP: [APP_LIFECYCLE_MODE_AUTO,
                                APP_LIFECYCLE_TYPE_OPERATION,
                                APP_LIFECYCLE_TIMING_POST,
                                APP_BACKUP],
    BACKUP_ACTION_PRE_ETCD_BACKUP: [APP_LIFECYCLE_MODE_AUTO,
                                    APP_LIFECYCLE_TYPE_OPERATION,
                                    APP_LIFECYCLE_TIMING_PRE,
                                    APP_ETCD_BACKUP],
    BACKUP_ACTION_POST_ETCD_BACKUP: [APP_LIFECYCLE_MODE_AUTO,
                                     APP_LIFECYCLE_TYPE_OPERATION,
                                     APP_LIFECYCLE_TIMING_POST,
                                     APP_ETCD_BACKUP],
    BACKUP_ACTION_PRE_RESTORE: [APP_LIFECYCLE_MODE_AUTO,
                                APP_LIFECYCLE_TYPE_OPERATION,
                                APP_LIFECYCLE_TIMING_PRE,
                                APP_RESTORE],
    BACKUP_ACTION_POST_RESTORE: [APP_LIFECYCLE_MODE_AUTO,
                                 APP_LIFECYCLE_TYPE_OPERATION,
                                 APP_LIFECYCLE_TIMING_POST,
                                 APP_RESTORE],
}

# Application metadata constants
APP_METADATA_MAINTAIN_ATTRIBUTES = 'maintain_attributes'
APP_METADATA_MAINTAIN_USER_OVERRIDES = 'maintain_user_overrides'
APP_METADATA_APPLY_PROGRESS_ADJUST = 'apply_progress_adjust'
APP_METADATA_APPLY_PROGRESS_ADJUST_DEFAULT_VALUE = 0
APP_METADATA_APPS = 'apps'
APP_METADATA_BEHAVIOR = 'behavior'
APP_METADATA_EVALUATE_REAPPLY = 'evaluate_reapply'
APP_METADATA_AFTER = 'after'
APP_METADATA_TRIGGERS = 'triggers'
APP_METADATA_TYPE = 'type'
APP_METADATA_FILTERS = 'filters'
APP_METADATA_FILTER_FIELD = 'filter_field'
APP_METADATA_PLATFORM_MANAGED_APP = 'platform_managed_app'
APP_METADATA_PLATFORM_MANAGED_APPS = 'platform_managed_apps_list'
APP_METADATA_DESIRED_STATE = 'desired_state'
APP_METADATA_DESIRED_STATES = 'desired_states'
APP_METADATA_FORBIDDEN_MANUAL_OPERATIONS = 'forbidden_manual_operations'
APP_METADATA_ORDERED_APPS = 'ordered_apps'
APP_METADATA_UPGRADES = 'upgrades'
APP_METADATA_UPDATE_FAILURE_SKIP_RECOVERY = 'update_failure_no_rollback'
APP_METADATA_AUTO_UPDATE = 'auto_update'
APP_METADATA_FAILED_VERSIONS = 'failed_versions'
APP_METADATA_FROM_VERSIONS = 'from_versions'
APP_METADATA_SUPPORTED_K8S_VERSION = 'supported_k8s_version'
APP_METADATA_SUPPORTED_RELEASES = 'supported_releases'
APP_METADATA_MINIMUM = 'minimum'
APP_METADATA_MAXIMUM = 'maximum'

APP_EVALUATE_REAPPLY_TYPE_HOST_ADD = 'host-add'
APP_EVALUATE_REAPPLY_TYPE_HOST_DELETE = 'host-delete'
APP_EVALUATE_REAPPLY_TYPE_HOST_REINSTALL = REINSTALL_ACTION
APP_EVALUATE_REAPPLY_TYPE_HOST_LOCK = LOCK_ACTION
APP_EVALUATE_REAPPLY_TYPE_HOST_FORCE_LOCK = FORCE_LOCK_ACTION
APP_EVALUATE_REAPPLY_TYPE_HOST_UNLOCK = UNLOCK_ACTION
APP_EVALUATE_REAPPLY_TYPE_HOST_FORCE_UNLOCK = FORCE_UNLOCK_ACTION
APP_EVALUATE_REAPPLY_TYPE_HOST_SWACT = SWACT_ACTION
APP_EVALUATE_REAPPLY_TYPE_HOST_FORCE_SWACT = FORCE_SWACT_ACTION
APP_EVALUATE_REAPPLY_TYPE_RUNTIME_APPLY_PUPPET = 'runtime-apply-puppet'
APP_EVALUATE_REAPPLY_HOST_AVAILABILITY = 'host-availability-updated'
APP_EVALUATE_REAPPLY_TYPE_SYSTEM_MODIFY = 'system-modify'
APP_EVALUATE_REAPPLY_TYPE_DETECTED_SWACT = 'detected-swact'
APP_EVALUATE_REAPPLY_TYPE_KUBE_UPGRADE_COMPLETE = 'kube-upgrade-complete'

APP_EVALUATE_REAPPLY_TRIGGER_TO_METADATA_MAP = {
    UNLOCK_ACTION:
        APP_EVALUATE_REAPPLY_TYPE_HOST_UNLOCK,
    FORCE_UNLOCK_ACTION:
        APP_EVALUATE_REAPPLY_TYPE_HOST_FORCE_UNLOCK,
    LOCK_ACTION:
        APP_EVALUATE_REAPPLY_TYPE_HOST_LOCK,
    FORCE_LOCK_ACTION:
        APP_EVALUATE_REAPPLY_TYPE_HOST_FORCE_LOCK,
    SWACT_ACTION:
        APP_EVALUATE_REAPPLY_TYPE_HOST_SWACT,
    FORCE_SWACT_ACTION:
        APP_EVALUATE_REAPPLY_TYPE_HOST_FORCE_SWACT,
    APP_EVALUATE_REAPPLY_TYPE_DETECTED_SWACT:
        APP_EVALUATE_REAPPLY_TYPE_DETECTED_SWACT,
    APP_EVALUATE_REAPPLY_TYPE_RUNTIME_APPLY_PUPPET:
        APP_EVALUATE_REAPPLY_TYPE_RUNTIME_APPLY_PUPPET,
    APP_EVALUATE_REAPPLY_HOST_AVAILABILITY:
        APP_EVALUATE_REAPPLY_HOST_AVAILABILITY,
    APP_EVALUATE_REAPPLY_TYPE_HOST_ADD:
        APP_EVALUATE_REAPPLY_TYPE_HOST_ADD,
    APP_EVALUATE_REAPPLY_TYPE_HOST_REINSTALL:
        APP_EVALUATE_REAPPLY_TYPE_HOST_REINSTALL,
    APP_EVALUATE_REAPPLY_TYPE_HOST_DELETE:
        APP_EVALUATE_REAPPLY_TYPE_HOST_DELETE,
    APP_EVALUATE_REAPPLY_TYPE_SYSTEM_MODIFY:
        APP_EVALUATE_REAPPLY_TYPE_SYSTEM_MODIFY
}

# Progress constants
APP_PROGRESS_ABORTED = 'operation aborted, check system inventory logs for details'
APP_PROGRESS_ABORTED_BY_USER = 'operation aborted by user'
APP_PROGRESS_APPLY_MANIFEST = 'applying application manifest'
APP_PROGRESS_COMPLETED = 'completed'
APP_PROGRESS_DELETE_MANIFEST = 'deleting application manifest'
APP_PROGRESS_DOWNLOAD_IMAGES = 'retrieving docker images'
APP_PROGRESS_IMAGES_DOWNLOAD_FAILED = 'failed to download one or more image(s).'
APP_PROGRESS_EXTRACT_TARFILE = 'extracting application tar file'
APP_PROGRESS_GENERATE_OVERRIDES = 'generating application overrides'
APP_PROGRESS_TARFILE_DOWNLOAD = 'downloading tarfile'
APP_PROGRESS_VALIDATE_UPLOAD_CHARTS = 'validating and uploading charts'
APP_PROGRESS_DEPS_PLATFORM_APP = "%s is required and is not applied" % HELM_APP_PLATFORM
APP_PROGRESS_ROLLBACK_RELEASES = 'rolling back application releases'
APP_PROGRESS_UPDATE_ABORTED = 'Application update from version {} to version {} aborted. '
APP_PROGRESS_UPDATE_COMPLETED = 'Application update from version {} to version {} completed.'
APP_PROGRESS_RECOVER_ABORTED = 'Application recover to version {} aborted. '
APP_PROGRESS_RECOVER_COMPLETED = 'Application recover to version {} completed. '
APP_PROGRESS_CLEANUP_FAILED = 'Application files/helm release cleanup for version {} failed.'
APP_PROGRESS_RECOVER_IN_PROGRESS = 'recovering version {} '
APP_PROGRESS_RECOVER_CHARTS = 'recovering helm charts'
APP_PROGRESS_UPDATE_FAILED_SKIP_RECOVERY = "Application {} update from " \
    "version {} to version {} failed and recovery skipped " \
    "because skip_recovery was requested."
APP_PROGRESS_UPDATE_FAILED_ARMADA_TO_FLUXCD = "Application {} update from " \
    "version {} to version {} failed and recovery skipped " \
    "because recovering between Armada and FluxCD is not allowed"
APP_PROGRESS_REMOVE_FAILED_WARNING = "Application remove failed. Status forced to '{}'. " \
    "Use native helm commands to clean up application helm releases."

# Auto-recovery limits
APP_AUTO_RECOVERY_MAX_COUNT = 5

# Node label operation constants
LABEL_ASSIGN_OP = 'assign'
LABEL_REMOVE_OP = 'remove'

# Placeholder constants
APP_NAME_PLACEHOLDER = 'app-name-placeholder'
APP_VERSION_PLACEHOLDER = 'app-version-placeholder'
APP_MANIFEST_NAME_PLACEHOLDER = 'manifest-placeholder'
APP_TARFILE_NAME_PLACEHOLDER = 'tarfile-placeholder'

# Default node labels
CONTROL_PLANE_LABEL = 'openstack-control-plane=enabled'
COMPUTE_NODE_LABEL = 'openstack-compute-node=enabled'
OPENVSWITCH_LABEL = 'openvswitch=enabled'
SRIOV_LABEL = 'sriov=enabled'
SRIOVDP_LABEL = 'sriovdp=enabled'
KUBE_TOPOLOGY_MANAGER_LABEL = 'kube-topology-mgr-policy'
KUBE_CPU_MANAGER_LABEL = 'kube-cpu-mgr-policy'
KUBE_IGNORE_ISOL_CPU_LABEL = 'kube-ignore-isol-cpus=enabled'

# Accepted label values
KUBE_TOPOLOGY_MANAGER_VALUES = [
    'none',
    'best-effort',
    'restricted',
    'single-numa-node'
]
KUBE_CPU_MANAGER_VALUES = [
    'none',
    'static'
]
# Default DNS service domain
DEFAULT_DNS_SERVICE_DOMAIN = 'cluster.local'

# Ansible bootstrap
ANSIBLE_BOOTSTRAP_FLAG = os.path.join(tsc.VOLATILE_PATH, ".ansible_bootstrap")
ANSIBLE_BOOTSTRAP_COMPLETED_FLAG = os.path.join(tsc.CONFIG_PATH,
                                                ".bootstrap_completed")
UNLOCK_READY_FLAG = os.path.join(tsc.PLATFORM_CONF_PATH, ".unlock_ready")
INVENTORY_WAIT_TIMEOUT_IN_SECS = 120
DEFAULT_RPCAPI_TIMEOUT_IN_SECS = 60

ANSIBLE_RESTORE_ROOK_FLAG = os.path.join(tsc.VOLATILE_PATH, ".ansible_restore_rook")

# Ansible playbooks
ANSIBLE_KUBE_NETWORKING_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/upgrade-k8s-networking.yml'
ANSIBLE_KUBE_PUSH_IMAGES_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/push_k8s_images.yml'
ANSIBLE_PLATFORM_BACKUP_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/backup.yml'
ANSIBLE_KUBE_STATIC_IMAGES_PLAYBOOK = \
    '/usr/share/ansible/stx-ansible/playbooks/upgrade-static-images.yml'

# Clock synchronization types
NTP = 'ntp'
PTP = 'ptp'

CLOCK_SYNCHRONIZATION = [
    NTP,
    PTP
]

# PTP transport modes
PTP_TRANSPORT_UDP = 'udp'
PTP_TRANSPORT_L2 = 'l2'
PTP_NETWORK_TRANSPORT_IEEE_802_3 = 'L2'

# PTP instance default parameters
PTP_TX_TIMESTAMP_TIMEOUT = '20'
PTP_SUMMARY_INTERVAL = '6'
PTP_CLOCK_SERVO_LINREG = 'linreg'
PTP_TIME_STAMPING_HARDWARE = 'hardware'
PTP_DELAY_MECHANISM_E2E = 'E2E'
PTP_BOUNDARY_CLOCK_JBOD_1 = '1'
PTP_SLAVEONLY_0 = '0'
PTP_SLAVEONLY_1 = '1'
PTP_TS2PHC_PULSEWIDTH_100000000 = '100000000'
PTP_LEAPFILE_PATH = '/usr/share/zoneinfo/leap-seconds.list'

# PTP pmc values
PTP_PMC_CLOCK_CLASS = '248'
PTP_PMC_CLOCK_ACCURACY = '0xfe'
PTP_PMC_OFFSET_SCALED_LOG_VARIANCE = '0xffff'
PTP_PMC_CURRENT_UTC_OFFSET = '37'
PTP_PMC_LEAP61 = '0'
PTP_PMC_LEAP59 = '0'
PTP_PMC_CURRENT_UTC_OFFSET_VALID = '1'
PTP_PMC_PTP_TIMESCALE = '1'
PTP_PMC_TIME_TRACEABLE = '0'
PTP_PMC_FREQUENCY_TRACEABLE = '0'
PTP_PMC_TIME_SOURCE = '0xa0'

# PTP instance types
PTP_INSTANCE_TYPE_PTP4L = 'ptp4l'
PTP_INSTANCE_TYPE_PHC2SYS = 'phc2sys'
PTP_INSTANCE_TYPE_TS2PHC = 'ts2phc'
PTP_INSTANCE_TYPE_CLOCK = 'clock'

# PTP instances created during migration
PTP_INSTANCE_LEGACY_PTP4L = 'ptp4l-legacy'
PTP_INSTANCE_LEGACY_PHC2SYS = 'phc2sys-legacy'

# PTP interfaces created during migration
PTP_INTERFACE_LEGACY_PTP4L = 'ptp4lif-legacy'
PTP_INTERFACE_LEGACY_PHC2SYS = 'phc2sysif-legacy'

# PTP parameter: owner types
PTP_PARAMETER_OWNER_INSTANCE = 'ptp-instance'
PTP_PARAMETER_OWNER_INTERFACE = 'ptp-interface'

# Global PTP configuration migrated to legacy instance
PTP_PARAMETER_DELAY_MECHANISM = 'delay_mechanism'
PTP_PARAMETER_TIME_STAMPING = 'time_stamping'
PTP_PARAMETER_NETWORK_TRANSPORT = 'network_transport'

# Special PTP service parameters migrated from legacy configuration
PTP_PARAMETER_UDS_ADDRESS = 'uds_address'
PTP_PARAMETER_DOMAIN_NUMBER = 'domainNumber'
PTP_PARAMETER_DEFAULT_DOMAIN = '0'
PTP_PARAMETER_BC_JBOD = 'boundary_clock_jbod'

# PTP service parameters NOT migrated from legacy configuration
PTP_PARAMETER_UPDATE_RATE = 'update-rate'
PTP_PARAMETER_SUMMARY_UPDATES = 'summary-updates'

# Patching PTP entities
PTP_INSTANCE_ARRAY_PATH = '/ptp_instances/-'
PTP_INTERFACE_ARRAY_PATH = '/ptp_interfaces/-'
PTP_PARAMETER_ARRAY_PATH = '/ptp_parameters/-'
PTP_PATCH_OPERATION_ADD = 'add'
PTP_PATCH_OPERATION_DELETE = 'remove'

# Patching host entities
MGMT_MAC_PATH = '/mgmt_mac'

# Backup & Restore
FIX_INSTALL_UUID_INTERVAL_SECS = 30

# ceph-mon IP placeholders (keys)
CEPH_MON_0 = 'ceph-mon-0-ip'
CEPH_MON_1 = 'ceph-mon-1-ip'
CEPH_MON_2 = 'ceph-mon-2-ip'
CEPH_FLOATING_MON = 'ceph-floating-mon-ip'

# Broadcom interface definitions
DRIVER_BNXT_EN = 'bnxt_en'

# Mellanox interface definitions
DRIVER_MLX_CX4 = 'mlx5_core'

MELLANOX_DRIVERS = [DRIVER_MLX_CX4]

# Drivers that require devices to be up before setting
# up SR-IOV.
DRIVERS_UP_BEFORE_SRIOV = [DRIVER_BNXT_EN]

# Drivers that require additional time before they
# become operational
DRIVERS_NOT_IMMEDIATELY_OPERATIONAL = [DRIVER_BNXT_EN]

# Traffic control
TRAFFIC_CONTROL_SCRIPT = '/usr/local/bin/tc_setup.sh'

# Host Board Management Constants
HOST_BM_TYPE_DEPROVISIONED = "none"
HOST_BM_TYPE_IPMI = "ipmi"
HOST_BM_TYPE_REDFISH = "redfish"
HOST_BM_TYPE_DYNAMIC = "dynamic"
HOST_BM_TYPE_DEFAULT = HOST_BM_TYPE_DYNAMIC

HOST_BM_VALID_TYPE_LIST = [HOST_BM_TYPE_DEPROVISIONED,
                           HOST_BM_TYPE_DYNAMIC,
                           HOST_BM_TYPE_IPMI,
                           HOST_BM_TYPE_REDFISH]
HOST_BM_VALID_PROVISIONED_TYPE_LIST = [HOST_BM_TYPE_DYNAMIC,
                                       HOST_BM_TYPE_IPMI,
                                       HOST_BM_TYPE_REDFISH]
# K8s device plugins
DEVICE_PLUGINS_FILE = "enabled_kube_plugins"
ENABLED_KUBE_PLUGINS = os.path.join(tsc.CONFIG_PATH, DEVICE_PLUGINS_FILE)
KUBE_INTEL_GPU_DEVICE_PLUGIN_LABEL = "intelgpu=enabled"

# Port on which ceph manager and ceph-mgr listens
CEPH_MGR_PORT = 7999

# Tempdir for temporary storage of large post data
SYSINV_TMPDIR = '/scratch/sysinv-tmpdir'

# Unique name of certificate
CERTIFICATE_TYPE_ADMIN_ENDPOINT = 'admin-endpoint-cert'
CERTIFICATE_TYPE_ADMIN_ENDPOINT_INTERMEDIATE_CA = 'intermediate-ca-cert'

DC_ADMIN_ENDPOINT_SECRET_NAME = 'dc-adminep-certificate'
SC_ADMIN_ENDPOINT_SECRET_NAME = 'sc-adminep-certificate'
SC_INTERMEDIATE_CA_SECRET_NAME = 'sc-adminep-ca-certificate'

DC_ADMIN_ROOT_CA_SECRET_NAME = 'dc-adminep-root-ca-certificate'

DC_ADMIN_ENDPOINT_NAMESPACE = 'dc-cert'
SC_ADMIN_ENDPOINT_NAMESPACE = 'sc-cert'

ADMIN_EP_CERT_FILENAME = os.path.join(SSL_CERT_DIR, 'admin-ep-cert.pem')

DC_ROOT_CA_CERT_FILE = 'dc-adminep-root-ca.crt'
DC_ROOT_CA_CERT_PATH = \
    os.path.join(SSL_CERT_CA_DIR, DC_ROOT_CA_CERT_FILE)

DC_ROOT_CA_CONFIG_PATH = \
    os.path.join(tsc.CONFIG_PATH, DC_ROOT_CA_CERT_FILE)
ADMIN_EP_CERT_FORMAT = '{tls_key}'

# Platform certificates
RESTAPI_CERT_SECRET_NAME = "system-restapi-gui-certificate"
REGISTRY_CERT_SECRET_NAME = "system-registry-local-certificate"
OPENLDAP_CERT_SECRET_NAME = "system-openldap-local-certificate"

# The k8s secret that holds openldap CA certificate
OPENLDAP_CA_CERT_SECRET_NAME = "system-local-ca"

CERT_NAMESPACE_PLATFORM_CERTS = 'deployment'
CERT_NAMESPACE_PLATFORM_CA_CERTS = 'cert-manager'

CERT_MODE_TO_SECRET_NAME = {
    CERT_MODE_SSL: RESTAPI_CERT_SECRET_NAME,
    CERT_MODE_DOCKER_REGISTRY: REGISTRY_CERT_SECRET_NAME,
    CERT_MODE_OPENLDAP: OPENLDAP_CERT_SECRET_NAME
}

# Storage associated networks
SB_SUPPORTED_NETWORKS = {
    SB_TYPE_CEPH: [NETWORK_TYPE_MGMT, NETWORK_TYPE_CLUSTER_HOST]
}

BEGIN_CERTIFICATE_MARKER = b"-----BEGIN CERTIFICATE-----\n"
END_CERTIFICATE_MARKER = b"\n-----END CERTIFICATE-----\n"
BEGIN_PRIVATE_KEY_MARKER = b"-----BEGIN PRIVATE KEY-----\n"
END_PRIVATE_KEY_MARKER = b"\n-----END PRIVATE KEY-----\n"
BEGIN_RSA_PRIVATE_KEY_MARKER = b"-----BEGIN RSA PRIVATE KEY-----\n"
END_RSA_PRIVATE_KEY_MARKER = b"\n-----END RSA PRIVATE KEY-----\n"

# Kubernetes root CA certficate update phases
KUBE_CERT_UPDATE_TRUSTBOTHCAS = "trust-both-cas"
KUBE_CERT_UPDATE_UPDATECERTS = "update-certs"
KUBE_CERT_UPDATE_TRUSTNEWCA = "trust-new-ca"

# kubernetes components secrets on rootCA update procedure
KUBE_ROOTCA_SECRET = 'system-kube-rootca-certificate'
KUBE_ROOTCA_ISSUER = 'system-kube-rootca-issuer'
KUBE_SELFSIGNED_ISSUER = 'system-kube-selfsigned-issuer'

# kubernetes components secrets on rootCA update procedure
KUBE_ADMIN_CERT = 'system-kube-admin-client-certificate'
KUBE_APISERVER_CERT = 'system-kube-apiserver-{}-server-certificate'
KUBE_APISERVER_KUBELET_CERT = 'system-kube-apiserver-{}-kubelet-client-certificate'
KUBE_SCHEDULER_CERT = 'system-kube-scheduler-{}-client-certificate'
KUBE_CONTROLLER_MANAGER_CERT = 'system-kube-controller-manager-{}-client-certificate'
KUBE_KUBELET_CERT = 'system-kube-kubelet-{}-client-certificate'

# minimum k8s certificate duration
K8S_CERTIFICATE_MINIMAL_DURATION = '24h'

# configuration UUID reboot required flag (bit)
CONFIG_REBOOT_REQUIRED = (1 << 127)

# Cert-Alarm related
CERT_LOCATION_MAP = {
    CERT_MODE_KUBERNETES_ROOT_CA: KUBERNETES_ROOTCA_FILE,
    CERT_MODE_ETCD: ETCD_ROOTCA_FILE,
    CERT_MODE_SSL: SSL_PEM_FILE,
    CERT_MODE_DOCKER_REGISTRY: DOCKER_REGISTRY_CERT_FILE,
    CERT_MODE_OPENSTACK: OPENSTACK_CERT_FILE,
    CERT_MODE_OPENSTACK_CA: OPENSTACK_CERT_CA_FILE
    # TODO(): TPM
}

CERT_ALARM_ANNOTATION_ALARM = 'starlingx.io/alarm'
CERT_ALARM_ANNOTATION_ALARM_BEFORE = 'starlingx.io/alarm-before'
CERT_ALARM_ANNOTATION_ALARM_SEVERITY = 'starlingx.io/alarm-severity'
CERT_ALARM_ANNOTATION_ALARM_TEXT = 'starlingx.io/alarm-text'

CERT_ALARM_DEFAULT_ANNOTATION_ALARM = 'enabled'
CERT_ALARM_DEFAULT_ANNOTATION_ALARM_BEFORE = '30d'
CERT_ALARM_DEFAULT_ANNOTATION_ALARM_BEFORE_CA = '180d'
CERT_ALARM_DEFAULT_ANNOTATION_ALARM_SEVERITY = 'unknown'
CERT_ALARM_DEFAULT_ANNOTATION_ALARM_TEXT = ''

# OS type
OS_RELEASE_FILE = '/etc/os-release'
OS_CENTOS = 'centos'
OS_DEBIAN = 'debian'
SUPPORTED_OS_TYPES = [OS_CENTOS, OS_DEBIAN]
OS_UPGRADE_FEED_FOLDER = '/var/www/pages/feed/'

# Configuration support placeholders
CONFIGURABLE = 'configurable'
NOT_CONFIGURABLE = 'not-configurable'

# apparmor states
APPARMOR_STATE_ENABLED = 'enabled'
APPARMOR_STATE_DISABLED = 'disabled'
