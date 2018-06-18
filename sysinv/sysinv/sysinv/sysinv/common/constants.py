#
# Copyright (c) 2013-2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

import copy
import os
import tsconfig.tsconfig as tsc

SYSINV_RUNNING_IN_LAB = '/etc/sysinv/.running_in_lab'
SYSINV_CONFIG_PATH = os.path.join(tsc.PLATFORM_PATH, "sysinv", tsc.SW_VERSION)

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
APPLY_PROFILE_ACTION = 'apply-profile'
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

CONFIG_ACTIONS = [SUBFUNCTION_CONFIG_ACTION,
                  APPLY_PROFILE_ACTION]

# Personalities
CONTROLLER = 'controller'
STORAGE = 'storage'
COMPUTE = 'compute'

PERSONALITIES = [CONTROLLER, STORAGE, COMPUTE]

# SUBFUNCTION FEATURES
SUBFUNCTIONS = 'subfunctions'
LOWLATENCY = 'lowlatency'

# CPU functions
PLATFORM_FUNCTION = "Platform"
VSWITCH_FUNCTION = "Vswitch"
SHARED_FUNCTION = "Shared"
VM_FUNCTION = "VMs"
NO_FUNCTION = "None"

# Host Personality Sub-Types
PERSONALITY_SUBTYPE_CEPH_BACKING = 'ceph-backing'
PERSONALITY_SUBTYPE_CEPH_CACHING = 'ceph-caching'
HOST_ADD = 'host_add'  # for personality sub-type validation
HOST_DELETE = 'host_delete'  # for personality sub-type validation

# Availability
AVAILABILITY_AVAILABLE = 'available'
AVAILABILITY_OFFLINE = 'offline'
AVAILABILITY_ONLINE = 'online'
AVAILABILITY_DEGRADED = 'degraded'

# States
ADMIN_UNLOCKED = 'unlocked'
ADMIN_LOCKED = 'locked'
LOCKING = 'Locking'
FORCE_LOCKING = "Force Locking"
OPERATIONAL_ENABLED = 'enabled'
OPERATIONAL_DISABLED = 'disabled'

BM_TYPE_GENERIC = 'bmc'
BM_TYPE_NONE = 'none'
PROVISIONED = 'provisioned'
PROVISIONING = 'provisioning'
UNPROVISIONED = 'unprovisioned'

# Host names
LOCALHOST_HOSTNAME = 'localhost'

CONTROLLER_HOSTNAME = 'controller'
CONTROLLER_0_HOSTNAME = '%s-0' % CONTROLLER_HOSTNAME
CONTROLLER_1_HOSTNAME = '%s-1' % CONTROLLER_HOSTNAME
CONTROLLER_GATEWAY = '%s-gateway' % CONTROLLER_HOSTNAME
CONTROLLER_PLATFORM_NFS = '%s-platform-nfs' % CONTROLLER_HOSTNAME
CONTROLLER_CGCS_NFS = '%s-nfs' % CONTROLLER_HOSTNAME
CONTROLLER_CINDER = '%s-cinder' % CONTROLLER_HOSTNAME

PXECONTROLLER_HOSTNAME = 'pxecontroller'
OAMCONTROLLER_HOSTNAME = 'oamcontroller'

STORAGE_HOSTNAME = 'storage'
STORAGE_0_HOSTNAME = '%s-0' % STORAGE_HOSTNAME
STORAGE_1_HOSTNAME = '%s-1' % STORAGE_HOSTNAME
STORAGE_2_HOSTNAME = '%s-2' % STORAGE_HOSTNAME
# Other Storage Hostnames are built dynamically.

# Replication Peer groups
PEER_PREFIX_BACKING = 'group-'
PEER_PREFIX_CACHING = 'group-cache-'
PEER_BACKING_RSVD_GROUP = '%s0' % PEER_PREFIX_BACKING

VIM_DEFAULT_TIMEOUT_IN_SECS = 5
VIM_DELETE_TIMEOUT_IN_SECS = 10
MTC_ADD_TIMEOUT_IN_SECS = 6
MTC_DELETE_TIMEOUT_IN_SECS = 10
MTC_DEFAULT_TIMEOUT_IN_SECS = 6
HWMON_DEFAULT_TIMEOUT_IN_SECS = 6
PATCH_DEFAULT_TIMEOUT_IN_SECS = 6

# ihost field attributes
IHOST_STOR_FUNCTION = 'stor_function'

# idisk stor function
IDISK_STOR_FUNCTION = 'stor_function'
IDISK_STOR_FUNC_ROOT = 'rootfs'
# idisk device functions
IDISK_DEV_FUNCTION = 'device_function'
IDISK_DEV_FUNC_CINDER = 'cinder_device'

# ihost config_status field values
CONFIG_STATUS_OUT_OF_DATE = "Config out-of-date"
CONFIG_STATUS_REINSTALL = "Reinstall required"

# when reinstall starts, mtc update the db with task = 'Reinstalling'
TASK_REINSTALLING = "Reinstalling"

HOST_ACTION_STATE = "action_state"
HAS_REINSTALLING = "reinstalling"
HAS_REINSTALLED = "reinstalled"

# Board Management Region Info
REGION_PRIMARY = "Internal"
REGION_SECONDARY = "External"

# Hugepage sizes in MiB
MIB_2M = 2
MIB_1G = 1024
Ki = 1024
NUM_4K_PER_MiB = 256

# Dynamic IO Resident Set Size(RSS) in MiB per socket
DISK_IO_RESIDENT_SET_SIZE_MIB = 2000
DISK_IO_RESIDENT_SET_SIZE_MIB_VBOX = 500

# Memory reserved for platform core in MiB per host
PLATFORM_CORE_MEMORY_RESERVED_MIB = 2000
PLATFORM_CORE_MEMORY_RESERVED_MIB_VBOX = 1100

# For combined node, memory reserved for controller in MiB
COMBINED_NODE_CONTROLLER_MEMORY_RESERVED_MIB = 10500
COMBINED_NODE_CONTROLLER_MEMORY_RESERVED_MIB_VBOX = 6000
COMBINED_NODE_CONTROLLER_MEMORY_RESERVED_MIB_XEOND = 7000

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

# Neutron provider networks
NEUTRON_PROVIDERNET_FLAT = "flat"
NEUTRON_PROVIDERNET_VXLAN = "vxlan"
NEUTRON_PROVIDERNET_VLAN = "vlan"

# Supported compute node vswitch types
VSWITCH_TYPE_OVS_DPDK = "ovs-dpdk"
VSWITCH_TYPE_NUAGE_VRS = "nuage_vrs"

# Partition default sizes
DEFAULT_IMAGE_STOR_SIZE = 10
DEFAULT_DATABASE_STOR_SIZE = 20
DEFAULT_IMG_CONVERSION_STOR_SIZE = 20
DEFAULT_SMALL_IMAGE_STOR_SIZE = 10
DEFAULT_SMALL_DATABASE_STOR_SIZE = 10
DEFAULT_SMALL_IMG_CONVERSION_STOR_SIZE = 10
DEFAULT_SMALL_BACKUP_STOR_SIZE = 30
DEFAULT_VIRTUAL_IMAGE_STOR_SIZE = 8
DEFAULT_VIRTUAL_DATABASE_STOR_SIZE = 5
DEFAULT_VIRTUAL_IMG_CONVERSION_STOR_SIZE = 8
DEFAULT_VIRTUAL_BACKUP_STOR_SIZE = 5
DEFAULT_EXTENSION_STOR_SIZE = 1
DEFAULT_PATCH_VAULT_STOR_SIZE = 8

# Openstack Interface names
OS_INTERFACE_PUBLIC = 'public'
OS_INTERFACE_INTERNAL = 'internal'
OS_INTERFACE_ADMIN = 'admin'

# Default region one name
REGION_ONE_NAME = 'RegionOne'
# DC Region Must match VIRTUAL_MASTER_CLOUD in dcorch
SYSTEM_CONTROLLER_REGION = 'SystemController'

# Storage backends supported
SB_TYPE_FILE = 'file'
SB_TYPE_LVM = 'lvm'
SB_TYPE_CEPH = 'ceph'
SB_TYPE_EXTERNAL = 'external'

SB_SUPPORTED = [SB_TYPE_FILE, SB_TYPE_LVM, SB_TYPE_CEPH, SB_TYPE_EXTERNAL]

# Storage backend default names
SB_DEFAULT_NAME_SUFFIX = "-store"
SB_DEFAULT_NAMES = {
    SB_TYPE_FILE:SB_TYPE_FILE + SB_DEFAULT_NAME_SUFFIX,
    SB_TYPE_LVM: SB_TYPE_LVM + SB_DEFAULT_NAME_SUFFIX,
    SB_TYPE_CEPH: SB_TYPE_CEPH + SB_DEFAULT_NAME_SUFFIX,
    SB_TYPE_EXTERNAL:'shared_services'
}

# Storage backends services
SB_SVC_CINDER = 'cinder'
SB_SVC_GLANCE = 'glance'
SB_SVC_NOVA = 'nova'  # usage reporting only
SB_SVC_SWIFT = 'swift'

SB_FILE_SVCS_SUPPORTED = [SB_SVC_GLANCE]
SB_LVM_SVCS_SUPPORTED = [SB_SVC_CINDER]
SB_CEPH_SVCS_SUPPORTED = [SB_SVC_GLANCE, SB_SVC_CINDER, SB_SVC_SWIFT]  # supported primary tier svcs
SB_EXTERNAL_SVCS_SUPPORTED = [SB_SVC_CINDER, SB_SVC_GLANCE]

# Storage backend: Service specific backend nomenclature
CINDER_BACKEND_CEPH = SB_TYPE_CEPH
CINDER_BACKEND_LVM = SB_TYPE_LVM
GLANCE_BACKEND_FILE = SB_TYPE_FILE
GLANCE_BACKEND_RBD = 'rbd'
GLANCE_BACKEND_HTTP = 'http'
GLANCE_BACKEND_GLANCE = 'glance'

# Storage Tiers: types (aligns with polymorphic backends)
SB_TIER_TYPE_CEPH = SB_TYPE_CEPH
SB_TIER_SUPPORTED = [SB_TIER_TYPE_CEPH]
SB_TIER_DEFAULT_NAMES = {
    SB_TIER_TYPE_CEPH: 'storage'  # maps to crushmap 'storage-tier' root
}
SB_TIER_CEPH_SECONDARY_SVCS = [SB_SVC_CINDER]  # supported secondary tier svcs

SB_TIER_STATUS_DEFINED = 'defined'
SB_TIER_STATUS_IN_USE = 'in-use'

# Glance images path when it is file backended
GLANCE_IMAGE_PATH = tsc.CGCS_PATH + "/" + SB_SVC_GLANCE + "/images"

# Requested storage backend API operations
SB_API_OP_CREATE = "create"
SB_API_OP_MODIFY = "modify"
SB_API_OP_DELETE = "delete"

# Storage backend state
SB_STATE_CONFIGURED = 'configured'
SB_STATE_CONFIGURING = 'configuring'
SB_STATE_CONFIG_ERR = 'configuration-failed'

# Storage backend tasks
SB_TASK_NONE = None
SB_TASK_APPLY_MANIFESTS = 'applying-manifests'
SB_TASK_RECONFIG_CONTROLLER = 'reconfig-controller'
SB_TASK_PROVISION_STORAGE = 'provision-storage'
SB_TASK_RECONFIG_COMPUTE = 'reconfig-compute'
SB_TASK_RESIZE_CEPH_MON_LV = 'resize-ceph-mon-lv'
SB_TASK_ADD_OBJECT_GATEWAY = 'add-object-gateway'
SB_TASK_RESTORE = 'restore'

# Storage backend ceph-mon-lv size
SB_CEPH_MON_GIB = 20
SB_CEPH_MON_GIB_MIN = 20
SB_CEPH_MON_GIB_MAX = 40

SB_CONFIGURATION_TIMEOUT = 1200

# Storage: Minimum number of monitors
MIN_STOR_MONITORS = 2

# Storage: reserved space for calculating controller rootfs limit
CONTROLLER_ROOTFS_RESERVED = 38

BACKUP_OVERHEAD = 20

# Suffix used in LVM volume name to indicate that the
# volume is actually a thin pool.  (And thin volumes will
# be created in the thin pool.)
LVM_POOL_SUFFIX = '-pool'

# Controller DRBD File System Resizing States
CONTROLLER_FS_RESIZING_IN_PROGRESS = 'drbd_fs_resizing_in_progress'
CONTROLLER_FS_AVAILABLE = 'available'

# DRBD File Systems
DRBD_PGSQL = 'pgsql'
DRBD_CGCS = 'cgcs'
DRBD_EXTENSION = 'extension'
DRBD_PATCH_VAULT = 'patch-vault'

# File system names
FILESYSTEM_NAME_BACKUP = 'backup'
FILESYSTEM_NAME_CGCS = 'cgcs'
FILESYSTEM_NAME_CINDER = 'cinder'
FILESYSTEM_NAME_DATABASE = 'database'
FILESYSTEM_NAME_IMG_CONVERSIONS = 'img-conversions'
FILESYSTEM_NAME_SCRATCH = 'scratch'
FILESYSTEM_NAME_EXTENSION = 'extension'
FILESYSTEM_NAME_PATCH_VAULT = 'patch-vault'

FILESYSTEM_LV_DICT = {
    FILESYSTEM_NAME_CGCS: 'cgcs-lv',
    FILESYSTEM_NAME_BACKUP: 'backup-lv',
    FILESYSTEM_NAME_SCRATCH: 'scratch-lv',
    FILESYSTEM_NAME_IMG_CONVERSIONS: 'img-conversions-lv',
    FILESYSTEM_NAME_DATABASE: 'pgsql-lv',
    FILESYSTEM_NAME_EXTENSION: 'extension-lv',
    FILESYSTEM_NAME_PATCH_VAULT: 'patch-vault-lv'
}

SUPPORTED_LOGICAL_VOLUME_LIST = FILESYSTEM_LV_DICT.values()

SUPPORTED_FILEYSTEM_LIST = [
    FILESYSTEM_NAME_BACKUP,
    FILESYSTEM_NAME_CGCS,
    FILESYSTEM_NAME_CINDER,
    FILESYSTEM_NAME_DATABASE,
    FILESYSTEM_NAME_EXTENSION,
    FILESYSTEM_NAME_IMG_CONVERSIONS,
    FILESYSTEM_NAME_SCRATCH,
    FILESYSTEM_NAME_PATCH_VAULT,
]

SUPPORTED_REPLICATED_FILEYSTEM_LIST = [
    FILESYSTEM_NAME_CGCS,
    FILESYSTEM_NAME_DATABASE,
    FILESYSTEM_NAME_EXTENSION,
    FILESYSTEM_NAME_PATCH_VAULT,
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
LVG_NOVA_PARAM_BACKING = 'instance_backing'
LVG_NOVA_PARAM_INST_LV_SZ = 'instances_lv_size_mib'
LVG_NOVA_PARAM_DISK_OPS = 'concurrent_disk_operations'
LVG_CINDER_PARAM_LVM_TYPE = 'lvm_type'

# Storage: Volume Group Parameter: Nova: Backing types
LVG_NOVA_BACKING_LVM = 'lvm'
LVG_NOVA_BACKING_IMAGE = 'image'
LVG_NOVA_BACKING_REMOTE = 'remote'

# Storage: Volume Group Parameter: Cinder: LVM provisioing
LVG_CINDER_LVM_TYPE_THIN = 'thin'
LVG_CINDER_LVM_TYPE_THICK = 'thick'

# Storage: Volume Group Parameter: Nova: Instances LV
LVG_NOVA_PARAM_INST_LV_SZ_DEFAULT = 0

# Storage: Volume Group Parameter: Nova: Concurrent Disk Ops
LVG_NOVA_PARAM_DISK_OPS_DEFAULT = 2

# Controller audit requests (force updates from agents)
DISK_AUDIT_REQUEST = "audit_disk"
LVG_AUDIT_REQUEST = "audit_lvg"
PV_AUDIT_REQUEST = "audit_pv"
PARTITION_AUDIT_REQUEST = "audit_partition"
CONTROLLER_AUDIT_REQUESTS = [DISK_AUDIT_REQUEST,
                             LVG_AUDIT_REQUEST,
                             PV_AUDIT_REQUEST,
                             PARTITION_AUDIT_REQUEST]

# Storage: Host Aggregates Groups
HOST_AGG_NAME_REMOTE = 'remote_storage_hosts'
HOST_AGG_META_REMOTE = 'remote'
HOST_AGG_NAME_LOCAL_LVM = 'local_storage_lvm_hosts'
HOST_AGG_META_LOCAL_LVM = 'local_lvm'
HOST_AGG_NAME_LOCAL_IMAGE = 'local_storage_image_hosts'
HOST_AGG_META_LOCAL_IMAGE = 'local_image'

# Interface definitions
NETWORK_TYPE_NONE = 'none'
NETWORK_TYPE_INFRA = 'infra'
NETWORK_TYPE_MGMT = 'mgmt'
NETWORK_TYPE_OAM = 'oam'
NETWORK_TYPE_BM = 'bm'
NETWORK_TYPE_MULTICAST = 'multicast'
NETWORK_TYPE_DATA = 'data'
NETWORK_TYPE_DATA_VRS = 'data-vrs'
NETWORK_TYPE_CONTROL = 'control'
NETWORK_TYPE_SYSTEM_CONTROLLER = 'system-controller'

NETWORK_TYPE_PCI_PASSTHROUGH = 'pci-passthrough'
NETWORK_TYPE_PCI_SRIOV = 'pci-sriov'
NETWORK_TYPE_PXEBOOT = 'pxeboot'

INTERFACE_TYPE_ETHERNET = 'ethernet'
INTERFACE_TYPE_VLAN = 'vlan'
INTERFACE_TYPE_AE = 'ae'
INTERFACE_TYPE_VIRTUAL = 'virtual'

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

# DRBD engineering limits.
# Link Util values are in Percentage.
DRBD_LINK_UTIL_MIN = 5
DRBD_LINK_UTIL_MAX = 80
DRBD_LINK_UTIL_DEFAULT = DRBD_LINK_UTIL_MAX / 2

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
ERROR_LOAD_STATE = 'error'
DELETING_LOAD_STATE = 'deleting'

DELETE_LOAD_SCRIPT = '/etc/sysinv/upgrades/delete_load.sh'

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

CEPH_POOL_IMAGES_NAME = 'images'
CEPH_POOL_IMAGES_PG_NUM = 256
CEPH_POOL_IMAGES_PGP_NUM = 256
CEPH_POOL_IMAGES_QUOTA_GIB = 20

CEPH_POOL_EPHEMERAL_NAME = 'ephemeral'
CEPH_POOL_EPHEMERAL_PG_NUM = 512
CEPH_POOL_EPHEMERAL_PGP_NUM = 512
CEPH_POOL_EPHEMERAL_QUOTA_GIB = 0

# Ceph RADOS Gateway default data pool
# Hammer version pool name will be kept if upgrade from R3 and
# Swift/Radosgw was configured/enabled in R3.
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
BACKING_POOLS = [{'pool_name': CEPH_POOL_VOLUMES_NAME,
                  'pg_num': CEPH_POOL_VOLUMES_PG_NUM,
                  'pgp_num': CEPH_POOL_VOLUMES_PGP_NUM,
                  'quota_gib': None,
                  'data_pt': 40},
                 {'pool_name': CEPH_POOL_IMAGES_NAME,
                  'pg_num': CEPH_POOL_IMAGES_PG_NUM,
                  'pgp_num': CEPH_POOL_IMAGES_PGP_NUM,
                  'quota_gib': None,
                  'data_pt': 20},
                 {'pool_name': CEPH_POOL_EPHEMERAL_NAME,
                  'pg_num': CEPH_POOL_EPHEMERAL_PG_NUM,
                  'pgp_num': CEPH_POOL_EPHEMERAL_PGP_NUM,
                  'quota_gib': None,
                  'data_pt': 30},
                 {'pool_name': CEPH_POOL_OBJECT_GATEWAY_NAME_JEWEL,
                  'pg_num': CEPH_POOL_OBJECT_GATEWAY_PG_NUM,
                  'pgp_num': CEPH_POOL_OBJECT_GATEWAY_PGP_NUM,
                  'quota_gib': None,
                  'data_pt': 10}]

ALL_BACKING_POOLS = [CEPH_POOL_RBD_NAME,
                     CEPH_POOL_VOLUMES_NAME,
                     CEPH_POOL_IMAGES_NAME,
                     CEPH_POOL_EPHEMERAL_NAME,
                     CEPH_POOL_OBJECT_GATEWAY_NAME_JEWEL,
                     CEPH_POOL_OBJECT_GATEWAY_NAME_HAMMER]

# Supported pools for secondary ceph tiers
SB_TIER_CEPH_POOLS = [
    {'pool_name': CEPH_POOL_VOLUMES_NAME,
     'pg_num': CEPH_POOL_VOLUMES_PG_NUM,
     'pgp_num': CEPH_POOL_VOLUMES_PGP_NUM,
     'be_quota_attr': 'cinder_pool_gib',
     'quota_default': 0,
     'data_pt': 100}]

# Pools for Ceph cache tiering
CACHE_POOLS = copy.deepcopy(BACKING_POOLS)
for p in CACHE_POOLS:
    # currently all BACKING_POOLS are cached, but this may change in the future
    p['pool_name'] = p['pool_name'] + "-cache"

# See http://ceph.com/pgcalc/. We set it to more than 100 because pool usage
# varies greatly in Titanium Cloud and we want to avoid running too low on PGs
CEPH_TARGET_PGS_PER_OSD = 200
CEPH_REPLICATION_FACTOR_DEFAULT = 2
CEPH_REPLICATION_FACTOR_SUPPORTED = [2,3]
CEPH_MIN_REPLICATION_FACTOR_SUPPORTED = [1,2]
CEPH_REPLICATION_MAP_DEFAULT = {
    # replication: min_replication
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

CEPH_MANAGER_RPC_TOPIC = "sysinv.ceph_manager"
CEPH_MANAGER_RPC_VERSION = "1.0"

CEPH_CRUSH_MAP_BACKUP = 'crushmap.bin.backup'
CEPH_CRUSH_MAP_APPLIED = '.crushmap_applied'
CEPH_CRUSH_MAP_DEPTH = 3
CEPH_CRUSH_TIER_SUFFIX = "-tier"

# Profiles
PROFILE_TYPE_CPU = 'cpu'
PROFILE_TYPE_INTERFACE = 'if'
PROFILE_TYPE_STORAGE = 'stor'
PROFILE_TYPE_MEMORY = 'memory'
PROFILE_TYPE_LOCAL_STORAGE = 'localstg'

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
SERVICE_TYPE_NETWORK = 'network'
SERVICE_TYPE_HORIZON = "horizon"
SERVICE_TYPE_CEPH = 'ceph'
SERVICE_TYPE_CINDER = 'cinder'
SERVICE_TYPE_MURANO = 'murano'
SERVICE_TYPE_MAGNUM = 'magnum'
SERVICE_TYPE_PLATFORM = 'platform'
SERVICE_TYPE_NOVA = 'nova'
SERVICE_TYPE_SWIFT = 'swift'
SERVICE_TYPE_IRONIC = 'ironic'
SERVICE_TYPE_CEILOMETER = 'ceilometer'
SERVICE_TYPE_PANKO = 'panko'
SERVICE_TYPE_AODH = 'aodh'
SERVICE_TYPE_GLANCE = 'glance'

SERVICE_PARAM_SECTION_MURANO_RABBITMQ = 'rabbitmq'
SERVICE_PARAM_SECTION_MURANO_ENGINE = 'engine'

SERVICE_PARAM_SECTION_IRONIC_NEUTRON = 'neutron'
SERVICE_PARAM_SECTION_IRONIC_PXE = 'pxe'

SERVICE_PARAM_SECTION_IDENTITY_ASSIGNMENT = 'assignment'
SERVICE_PARAM_SECTION_IDENTITY_IDENTITY = 'identity'
SERVICE_PARAM_SECTION_IDENTITY_LDAP = 'ldap'
SERVICE_PARAM_SECTION_IDENTITY_CONFIG = 'config'

SERVICE_PARAM_SECTION_CINDER_EMC_VNX = 'emc_vnx'
SERVICE_PARAM_CINDER_EMC_VNX_ENABLED = 'enabled'
SERVICE_PARAM_SECTION_CINDER_EMC_VNX_STATE = 'emc_vnx.state'

SERVICE_PARAM_SECTION_CINDER_HPE3PAR = 'hpe3par'
SERVICE_PARAM_CINDER_HPE3PAR_ENABLED = 'enabled'
SERVICE_PARAM_SECTION_CINDER_HPE3PAR_STATE = 'hpe3par.state'

SERVICE_PARAM_SECTION_CINDER_HPELEFTHAND = 'hpelefthand'
SERVICE_PARAM_CINDER_HPELEFTHAND_ENABLED = 'enabled'
SERVICE_PARAM_SECTION_CINDER_HPELEFTHAND_STATE = 'hpelefthand.state'

SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS = 'status'
SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_DISABLING = 'disabling'
SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_DISABLED = 'disabled'
SERVICE_PARAM_CINDER_SAN_CHANGE_STATUS_ENABLED = 'enabled'

SERVICE_PARAM_IDENTITY_CONFIG_TOKEN_EXPIRATION = 'token_expiration'
SERVICE_PARAM_IDENTITY_CONFIG_TOKEN_EXPIRATION_DEFAULT = 3600

SERVICE_PARAM_SECTION_NETWORK_DEFAULT = 'default'
SERVICE_PARAM_SECTION_NETWORK_ML2 = 'ml2'
SERVICE_PARAM_SECTION_NETWORK_ML2_ODL = 'ml2_odl'
SERVICE_PARAM_SECTION_NETWORK_BGP = 'bgp'
SERVICE_PARAM_SECTION_NETWORK_SFC = 'sfc'
SERVICE_PARAM_SECTION_NETWORK_DHCP = 'dhcp'

SERVICE_PARAM_PARAMETER_NAME_EXTERNAL_ADMINURL = 'external-admin-url'
SERVICE_PARAM_NAME_MURANO_DISABLE_AGENT = 'disable_murano_agent'
SERVICE_PARAM_NAME_MURANO_SSL = 'ssl'
SERVICE_PARAM_NAME_IRONIC_TFTP_SERVER = 'tftp_server'
SERVICE_PARAM_NAME_IRONIC_CONTROLLER_0_NIC = 'controller_0_if'
SERVICE_PARAM_NAME_IRONIC_CONTROLLER_1_NIC = 'controller_1_if'
SERVICE_PARAM_NAME_IRONIC_NETMASK = 'netmask'
SERVICE_PARAM_NAME_IRONIC_PROVISIONING_NETWORK = 'provisioning_network'
SERVICE_PARAM_SECTION_HORIZON_AUTH = 'auth'

SERVICE_PARAM_SECTION_CEPH_CACHE_TIER = 'cache_tiering'
SERVICE_PARAM_SECTION_CEPH_CACHE_TIER_DESIRED = 'cache_tiering.desired'
SERVICE_PARAM_SECTION_CEPH_CACHE_TIER_APPLIED = 'cache_tiering.applied'
SERVICE_PARAM_CEPH_CACHE_TIER_FEATURE_ENABLED = 'feature_enabled'
SERVICE_PARAM_CEPH_CACHE_TIER_CACHE_ENABLED = 'cache_enabled'
SERVICE_PARAM_CEPH_CACHE_TIER_TARGET_MAX_BYTES = 'target_max_bytes'

SERVICE_PARAM_CEPH_CACHE_HIT_SET_TYPE_BLOOM = 'bloom'
CACHE_TIERING_DEFAULTS = {
    'cache_min_evict_age': 0,
    'cache_min_flush_age': 0,
    # cache_target_dirty_high_ratio - not implemented
    'cache_target_dirty_ratio': 0.4,
    'cache_target_full_ratio': 0.95,
    'hit_set_count': 0,
    'hit_set_period': 0,
    'hit_set_type': SERVICE_PARAM_CEPH_CACHE_HIT_SET_TYPE_BLOOM,
    'min_read_recency_for_promote': 0,
    # min_write_recency_for_promote - not implemented
}

SERVICE_PARAM_ASSIGNMENT_DRIVER = 'driver'
SERVICE_PARAM_IDENTITY_DRIVER = 'driver'

SERVICE_PARAM_IDENTITY_SERVICE_BACKEND_SQL = 'sql'
SERVICE_PARAM_IDENTITY_SERVICE_BACKEND_LDAP = 'ldap'

SERVICE_PARAM_IDENTITY_ASSIGNMENT_DRIVER_SQL = 'sql'
SERVICE_PARAM_IDENTITY_ASSIGNMENT_DRIVER_LDAP = 'ldap'

SERVICE_PARAM_IDENTITY_IDENTITY_DRIVER_SQL = 'sql'
SERVICE_PARAM_IDENTITY_IDENTITY_DRIVER_LDAP = 'ldap'

SERVICE_PARAM_HORIZON_AUTH_LOCKOUT_PERIOD_SEC = \
    'lockout_seconds'
SERVICE_PARAM_HORIZON_AUTH_LOCKOUT_RETRIES = \
    'lockout_retries'
SERVICE_PARAM_HORIZON_AUTH_LOCKOUT_PERIOD_SEC_DEFAULT = 300
SERVICE_PARAM_HORIZON_AUTH_LOCKOUT_RETRIES_DEFAULT = 3

#### NEUTRON Service Parameters ####

SERVICE_PARAM_NAME_ML2_EXTENSION_DRIVERS = 'extension_drivers'
SERVICE_PARAM_NAME_ML2_MECHANISM_DRIVERS = 'mechanism_drivers'
SERVICE_PARAM_NAME_ML2_TENANT_NETWORK_TYPES = 'tenant_network_types'
SERVICE_PARAM_NAME_ML2_ODL_URL = 'url'
SERVICE_PARAM_NAME_ML2_ODL_USERNAME = 'username'
SERVICE_PARAM_NAME_ML2_ODL_PASSWORD = 'password'
SERVICE_PARAM_NAME_ML2_PORT_BINDING_CONTROLLER = 'port_binding_controller'
SERVICE_PARAM_NAME_DEFAULT_SERVICE_PLUGINS = 'service_plugins'
SERVICE_PARAM_NAME_BASE_MAC = 'base_mac'
SERVICE_PARAM_NAME_DVR_BASE_MAC = 'dvr_base_mac'
SERVICE_PARAM_NAME_DHCP_FORCE_METADATA = 'force_metadata'

# the compulsory set of service parameters when SDN is
# configured (required for semantic check on Compute unlock)
SERVICE_PARAM_NETWORK_ML2_COMPULSORY = \
    [SERVICE_PARAM_NAME_ML2_MECHANISM_DRIVERS,
     SERVICE_PARAM_NAME_ML2_ODL_URL,
     SERVICE_PARAM_NAME_ML2_ODL_USERNAME,
     SERVICE_PARAM_NAME_ML2_ODL_PASSWORD]

# a subset of the Neutron mechanism driver endpoints that we support
SERVICE_PARAM_NETWORK_ML2_MECH_DRIVERS = \
    ['openvswitch', 'vswitch', 'sriovnicswitch', 'opendaylight',
     'l2population', 'opendaylight_v2']

# a subset of the Neutron extensions that we support
SERVICE_PARAM_NETWORK_ML2_EXT_DRIVERS_PORT_SECURITY = 'port_security'
SERVICE_PARAM_NETWORK_ML2_EXT_DRIVERS = \
    ['dns', 'port_security']

# a subset of Neutron's tenant network types that we support
SERVICE_PARAM_NETWORK_ML2_TENANT_TYPES = \
    ['vlan', 'vxlan']

# a subset of Neutron service plugins that are supported
SERVICE_PARAM_NETWORK_DEFAULT_SERVICE_PLUGINS = \
    ['odl-router',
     'networking_odl.l3.l3_odl.OpenDaylightL3RouterPlugin',
     'odl-router_v2',
     'networking_odl.l3.l3_odl_v2:OpenDaylightL3RouterPlugin',
     'neutron_dynamic_routing.services.bgp.bgp_plugin.BgpPlugin',
     'networking_bgpvpn.neutron.services.plugin.BGPVPNPlugin',
     'router']

# Neutron service plugins for SDN
SERVICE_PLUGINS_SDN = \
    ['odl-router',
     'networking_odl.l3.l3_odl.OpenDaylightL3RouterPlugin',
     'odl-router_v2',
     'networking_odl.l3.l3_odl_v2:OpenDaylightL3RouterPlugin']

# sfc parameters
SERVICE_PARAM_NAME_SFC_QUOTA_FLOW_CLASSIFIER = 'sfc_quota_flow_classifier'
SERVICE_PARAM_NAME_SFC_QUOTA_PORT_CHAIN = 'sfc_quota_port_chain'
SERVICE_PARAM_NAME_SFC_QUOTA_PORT_PAIR_GROUP = 'sfc_quota_port_pair_group'
SERVICE_PARAM_NAME_SFC_QUOTA_PORT_PAIR = 'sfc_quota_port_pair'
SERVICE_PARAM_NAME_SFC_SFC_DRIVERS = 'sfc_drivers'
SERVICE_PARAM_NAME_SFC_FLOW_CLASSIFIER_DRIVERS = "flowclassifier_drivers"

# bgp parameters
SERVICE_PARAM_NAME_BGP_ROUTER_ID_C0 = 'bgp_router_id_c0'
SERVICE_PARAM_NAME_BGP_ROUTER_ID_C1 = 'bgp_router_id_c1'

# Set dns_domain for internal_dns
SERVICE_PARAM_NAME_DEFAULT_DNS_DOMAIN = 'dns_domain'

# Platform Service Parameters
SERVICE_PARAM_SECTION_PLATFORM_MAINTENANCE = 'maintenance'
SERVICE_PARAM_SECTION_PLATFORM_SYSINV = 'sysinv'
SERVICE_PARAM_NAME_SYSINV_FIREWALL_RULES_ID = 'firewall_rules_id'

SERVICE_PARAM_PLAT_MTCE_COMPUTE_BOOT_TIMEOUT = 'compute_boot_timeout'
SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT = 'controller_boot_timeout'
SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD = 'heartbeat_period'
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD = 'heartbeat_failure_threshold'
SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD = 'heartbeat_degrade_threshold'

SERVICE_PARAM_PLAT_MTCE_COMPUTE_BOOT_TIMEOUT_DEFAULT = 720
SERVICE_PARAM_PLAT_MTCE_CONTROLLER_BOOT_TIMEOUT_DEFAULT = 1200
SERVICE_PARAM_PLAT_MTCE_HBS_PERIOD_DEFAULT = 100
SERVICE_PARAM_PLAT_MTCE_HBS_FAILURE_THRESHOLD_DEFAULT = 10
SERVICE_PARAM_PLAT_MTCE_HBS_DEGRADE_THRESHOLD_DEFAULT = 6

# Nova Service Parameters
SERVICE_PARAM_SECTION_NOVA_PCI_ALIAS = 'pci_alias'
SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU = NOVA_PCI_ALIAS_GPU_NAME
SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU_PF = NOVA_PCI_ALIAS_GPU_PF_NAME
SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_GPU_VF = NOVA_PCI_ALIAS_GPU_VF_NAME
SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_DH895XCC_PF = NOVA_PCI_ALIAS_QAT_DH895XCC_PF_NAME
SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_DH895XCC_VF = NOVA_PCI_ALIAS_QAT_DH895XCC_VF_NAME
SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_C62X_PF = NOVA_PCI_ALIAS_QAT_C62X_PF_NAME
SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_QAT_C62X_VF = NOVA_PCI_ALIAS_QAT_C62X_VF_NAME
SERVICE_PARAM_NAME_NOVA_PCI_ALIAS_USER = NOVA_PCI_ALIAS_USER_NAME

# default time to live seconds
PM_TTL_DEFAULT = 86400

# Ceilometer Service Parameters
SERVICE_PARAM_SECTION_CEILOMETER_DATABASE = "database"
SERVICE_PARAM_NAME_CEILOMETER_DATABASE_METERING_TIME_TO_LIVE = "metering_time_to_live"
SERVICE_PARAM_CEILOMETER_DATABASE_METERING_TIME_TO_LIVE_DEFAULT = PM_TTL_DEFAULT

SERVICE_PARAM_SECTION_PANKO_DATABASE = "database"
SERVICE_PARAM_NAME_PANKO_DATABASE_EVENT_TIME_TO_LIVE = "event_time_to_live"
SERVICE_PARAM_PANKO_DATABASE_EVENT_TIME_TO_LIVE_DEFAULT = PM_TTL_DEFAULT

SERVICE_PARAM_SECTION_AODH_DATABASE = "database"
SERVICE_PARAM_NAME_AODH_DATABASE_ALARM_HISTORY_TIME_TO_LIVE = "alarm_history_time_to_live"
SERVICE_PARAM_AODH_DATABASE_ALARM_HISTORY_TIME_TO_LIVE_DEFAULT = PM_TTL_DEFAULT


# TIS part number, CPE = combined load, STD = standard load
TIS_STD_BUILD = 'Standard'
TIS_AIO_BUILD = 'All-in-one'

# Upgrade states
UPGRADE_STARTING = 'starting'
UPGRADE_STARTED = 'started'
UPGRADE_DATA_MIGRATION = 'data-migration'
UPGRADE_DATA_MIGRATION_COMPLETE = 'data-migration-complete'
UPGRADE_DATA_MIGRATION_FAILED = 'data-migration-failed'
UPGRADE_UPGRADING_CONTROLLERS = 'upgrading-controllers'
UPGRADE_UPGRADING_HOSTS = 'upgrading-hosts'
UPGRADE_ACTIVATION_REQUESTED = 'activation-requested'
UPGRADE_ACTIVATING = 'activating'
UPGRADE_ACTIVATION_FAILED = 'activation-failed'
UPGRADE_ACTIVATION_COMPLETE = 'activation-complete'
UPGRADE_COMPLETING = 'completing'
UPGRADE_COMPLETED = 'completed'
UPGRADE_ABORTING = 'aborting'
UPGRADE_ABORT_COMPLETING = 'abort-completing'
UPGRADE_ABORTING_ROLLBACK = 'aborting-reinstall'

# LLDP
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

# wrsroot password aging.
# Setting aging to max defined value qualifies
# as "never" on certain Linux distros including WRL
WRSROOT_PASSWORD_NO_AGING = 99999

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
LINUX_LVM_PARTITION = "e6d6d379-f507-44c2-a23c-238f2a3df928"

# Partition name for those partitions deignated for PV use.
PARTITION_NAME_PV = "LVM Physical Volume"

# Partition table types.
PARTITION_TABLE_GPT = "gpt"
PARTITION_TABLE_MSDOS = "msdos"

# Optional services
ALL_OPTIONAL_SERVICES = [SERVICE_TYPE_CINDER, SERVICE_TYPE_MURANO,
                         SERVICE_TYPE_MAGNUM, SERVICE_TYPE_SWIFT,
                         SERVICE_TYPE_IRONIC]

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
    SYSINV_LOCK_PATH = tox_work_dir
else:
    SYSINV_LOCK_PATH = os.path.join(tsc.VOLATILE_PATH, "sysinv")

NETWORK_CONFIG_LOCK_FILE = os.path.join(
    tsc.VOLATILE_PATH, "apply_network_config.lock")

SYSINV_USERNAME = "sysinv"
SYSINV_GRPNAME = "sysinv"

# SSL configuration
CERT_TYPE_SSL = 'ssl'
SSL_CERT_DIR = "/etc/ssl/private/"
SSL_CERT_FILE = "server-cert.pem"  # pem with PK and cert
CERT_MURANO_DIR = "/etc/ssl/private/murano-rabbit"
CERT_FILE = "cert.pem"
CERT_KEY_FILE = "key.pem"
CERT_CA_FILE = "ca-cert.pem"
SSL_PEM_FILE = os.path.join(SSL_CERT_DIR, SSL_CERT_FILE)
SSL_PEM_FILE_SHARED = os.path.join(tsc.CONFIG_PATH, SSL_CERT_FILE)

MURANO_CERT_KEY_FILE = os.path.join(CERT_MURANO_DIR, CERT_KEY_FILE)
MURANO_CERT_FILE = os.path.join(CERT_MURANO_DIR, CERT_FILE)
MURANO_CERT_CA_FILE = os.path.join(CERT_MURANO_DIR, CERT_CA_FILE)

SSL_CERT_CA_DIR = "/etc/ssl/certs/"
SSL_CERT_CA_FILE = os.path.join(SSL_CERT_CA_DIR, CERT_CA_FILE)
SSL_CERT_CA_FILE_SHARED = os.path.join(tsc.CONFIG_PATH, CERT_CA_FILE)

CERT_MODE_SSL = 'ssl'
CERT_MODE_SSL_CA = 'ssl_ca'
CERT_MODE_TPM = 'tpm_mode'
CERT_MODE_MURANO = 'murano'
CERT_MODE_MURANO_CA = 'murano_ca'
CERT_MODES_SUPPORTED = [CERT_MODE_SSL,
                        CERT_MODE_SSL_CA,
                        CERT_MODE_TPM,
                        CERT_MODE_MURANO,
                        CERT_MODE_MURANO_CA]

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
    "not use ephemeral or swap disks. See Titanium Cloud System Engineering "
    "Guidelines for more details on supported compute configurations.")
WARNING_ROOT_PV_CINDER_CEPH_MSG = (
    "Warning: This compute must have instance_backing set to 'remote' "
    "or use a secondary disk for local storage. See Titanium Cloud System "
    "Engineering Guidelines for more details on supported compute configurations.")
PV_WARNINGS = {WARN_CINDER_ON_ROOT_WITH_LVM: WARNING_ROOT_PV_CINDER_LVM_MSG,
               WARN_CINDER_ON_ROOT_WITH_CEPH: WARNING_ROOT_PV_CINDER_CEPH_MSG}

# Custom firewall rule file
FIREWALL_RULES_FILE = 'iptables.rules'
FIREWALL_RULES_MAX_FILE_SIZE = 102400

# License file
LICENSE_FILE = ".license"

# Cinder lvm config complete file.
NODE_CINDER_LVM_CONFIG_COMPLETE_FILE = \
    os.path.join(tsc.PLATFORM_CONF_PATH, '.node_cinder_lvm_config_complete')
INITIAL_CINDER_LVM_CONFIG_COMPLETE_FILE = \
    os.path.join(tsc.CONFIG_PATH, '.initial_cinder_lvm_config_complete')

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
