#
# Copyright (c) 2013-2019 Wind River Systems, Inc.
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
WORKER = 'worker'

PERSONALITIES = [CONTROLLER, STORAGE, WORKER]

# SUBFUNCTION FEATURES
SUBFUNCTIONS = 'subfunctions'
LOWLATENCY = 'lowlatency'

# CPU functions
PLATFORM_FUNCTION = "Platform"
VSWITCH_FUNCTION = "Vswitch"
SHARED_FUNCTION = "Shared"
APPLICATION_FUNCTION = "Applications"
NO_FUNCTION = "None"

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

# Defines per-socket vswitch memory requirements (in MB)
VSWITCH_MEMORY_MB = 1024

# Dynamic IO Resident Set Size(RSS) in MiB per socket
DISK_IO_RESIDENT_SET_SIZE_MIB = 2000
DISK_IO_RESIDENT_SET_SIZE_MIB_VBOX = 500

# Memory reserved for platform core in MiB per host
PLATFORM_CORE_MEMORY_RESERVED_MIB = 2000
PLATFORM_CORE_MEMORY_RESERVED_MIB_VBOX = 1100
PLATFORM_CORE_MEMORY_RESERVED_MIB_VBOX_WORKER = 2000

# For combined node, memory reserved for controller in MiB
COMBINED_NODE_CONTROLLER_MEMORY_RESERVED_MIB = 10500
COMBINED_NODE_CONTROLLER_MEMORY_RESERVED_MIB_VBOX = 6000
COMBINED_NODE_CONTROLLER_MEMORY_RESERVED_MIB_XEOND = 7000

# Max number of physical cores in a xeon-d cpu
NUMBER_CORES_XEOND = 8

# Max number of workers that can be added to an AIO duplex system
AIO_DUPLEX_MAX_WORKERS = 4

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
DEFAULT_CGCS_STOR_SIZE = 20
DEFAULT_DOCKER_STOR_SIZE = 1
DEFAULT_DOCKER_DISTRIBUTION_STOR_SIZE = 1
DEFAULT_DATABASE_STOR_SIZE = 20
DEFAULT_SMALL_CGCS_STOR_SIZE = 10
DEFAULT_SMALL_DATABASE_STOR_SIZE = 10
DEFAULT_SMALL_BACKUP_STOR_SIZE = 40
DEFAULT_VIRTUAL_DATABASE_STOR_SIZE = 5
DEFAULT_VIRTUAL_BACKUP_STOR_SIZE = 5
DEFAULT_EXTENSION_STOR_SIZE = 1
DEFAULT_PATCH_VAULT_STOR_SIZE = 8
DEFAULT_ETCD_STORE_SIZE = 1

# The threshold between small and large disks is 240GiB
DEFAULT_SMALL_DISK_SIZE = 240
# The minimum disk size needed to create all partitions
# Value based on the following calculation:
# DEFAULT_SMALL_CGCS_STOR_SIZE                         10
# 2*DEFAULT_SMALL_DATABASE_STOR_SIZE                   20 (2*10)
# DEFAULT_SMALL_BACKUP_STOR_SIZE                       40
# LOG_VOL_SIZE (reserved in kickstarts)                 8
# SCRATCH_VOL_SIZE (reserved in kickstarts)             8
# RABBIT_LV                                             2
# PLATFORM_LV                                           2
# ANCHOR_LV                                             1
# DEFAULT_EXTENSION_STOR_SIZE                           1
# KUBERNETES_DOCKER_STOR_SIZE (--kubernetes)           30
# DOCKER_DISTRIBUTION_STOR_SIZE (--kubernetes)         16
# ETCD_STOR_SIZE (--kubernetes)                         5
# CEPH_MON_SIZE (--kubernetes)                         20
# buffer inside VG for LV creation                      1
# root partition (created in kickstarts)               20
# boot partition (created in kickstarts)                1
# buffer for partition creation                         1
# -------------------------------------------------------
#                                                     186
MINIMUM_DISK_SIZE = 186

# Docker lv size when Kubernetes is configured
KUBERNETES_DOCKER_STOR_SIZE = 30
DOCKER_DISTRIBUTION_STOR_SIZE = 16
ETCD_STOR_SIZE = 5

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

SB_SUPPORTED = [SB_TYPE_FILE,
                SB_TYPE_LVM,
                SB_TYPE_CEPH,
                SB_TYPE_CEPH_EXTERNAL,
                SB_TYPE_EXTERNAL]

# Storage backend default names
SB_DEFAULT_NAME_SUFFIX = "-store"
SB_DEFAULT_NAMES = {
    SB_TYPE_FILE: SB_TYPE_FILE + SB_DEFAULT_NAME_SUFFIX,
    SB_TYPE_LVM: SB_TYPE_LVM + SB_DEFAULT_NAME_SUFFIX,
    SB_TYPE_CEPH: SB_TYPE_CEPH + SB_DEFAULT_NAME_SUFFIX,
    SB_TYPE_CEPH_EXTERNAL: SB_TYPE_CEPH_EXTERNAL + SB_DEFAULT_NAME_SUFFIX,
    SB_TYPE_EXTERNAL: 'shared_services'
}

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
GLANCE_IMAGE_PATH = tsc.CGCS_PATH + "/" + SB_SVC_GLANCE + "/images"

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
SB_TASK_RECONFIG_CONTROLLER = 'reconfig-controller'
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

# Ceph storage deployment model
# Controller model: OSDs are on controllers, no storage nodes can
# be defined.
# Storage model: OSDs are on dedicated storage nodes.
CEPH_STORAGE_MODEL = 'storage-nodes'
CEPH_CONTROLLER_MODEL = 'controller-nodes'
CEPH_AIO_SX_MODEL = 'aio-sx'
CEPH_UNDEFINED_MODEL = 'undefined'

# Storage: Minimum number of monitors
MIN_STOR_MONITORS = 2

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
DRBD_ETCD = 'etcd'
DRBD_DOCKER_DISTRIBUTION = 'docker-distribution'

# File system names
FILESYSTEM_NAME_BACKUP = 'backup'
FILESYSTEM_NAME_CGCS = 'cgcs'
FILESYSTEM_DISPLAY_NAME_CGCS = 'glance'
FILESYSTEM_NAME_CINDER = 'cinder'
FILESYSTEM_NAME_DATABASE = 'database'
FILESYSTEM_NAME_SCRATCH = 'scratch'
FILESYSTEM_NAME_DOCKER = 'docker'
FILESYSTEM_NAME_DOCKER_DISTRIBUTION = 'docker-distribution'
FILESYSTEM_NAME_EXTENSION = 'extension'
FILESYSTEM_NAME_ETCD = 'etcd'
FILESYSTEM_NAME_PATCH_VAULT = 'patch-vault'

FILESYSTEM_LV_DICT = {
    FILESYSTEM_NAME_CGCS: 'cgcs-lv',
    FILESYSTEM_NAME_BACKUP: 'backup-lv',
    FILESYSTEM_NAME_SCRATCH: 'scratch-lv',
    FILESYSTEM_NAME_DOCKER: 'docker-lv',
    FILESYSTEM_NAME_DOCKER_DISTRIBUTION: 'dockerdistribution-lv',
    FILESYSTEM_NAME_DATABASE: 'pgsql-lv',
    FILESYSTEM_NAME_EXTENSION: 'extension-lv',
    FILESYSTEM_NAME_ETCD: 'etcd-lv',
    FILESYSTEM_NAME_PATCH_VAULT: 'patch-vault-lv',
}

SUPPORTED_LOGICAL_VOLUME_LIST = FILESYSTEM_LV_DICT.values()

SUPPORTED_FILEYSTEM_LIST = [
    FILESYSTEM_NAME_BACKUP,
    FILESYSTEM_NAME_CGCS,
    FILESYSTEM_NAME_CINDER,
    FILESYSTEM_NAME_DATABASE,
    FILESYSTEM_NAME_EXTENSION,
    FILESYSTEM_NAME_SCRATCH,
    FILESYSTEM_NAME_DOCKER,
    FILESYSTEM_NAME_DOCKER_DISTRIBUTION,
    FILESYSTEM_NAME_PATCH_VAULT,
    FILESYSTEM_NAME_ETCD,
]

SUPPORTED_REPLICATED_FILEYSTEM_LIST = [
    FILESYSTEM_NAME_CGCS,
    FILESYSTEM_NAME_DATABASE,
    FILESYSTEM_NAME_EXTENSION,
    FILESYSTEM_NAME_PATCH_VAULT,
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
LVG_NOVA_PARAM_BACKING = 'instance_backing'
LVG_NOVA_PARAM_DISK_OPS = 'concurrent_disk_operations'
LVG_CINDER_PARAM_LVM_TYPE = 'lvm_type'

# Storage: Volume Group Parameter: Nova: Backing types
LVG_NOVA_BACKING_IMAGE = 'image'
LVG_NOVA_BACKING_REMOTE = 'remote'

# Storage: Volume Group Parameter: Cinder: LVM provisioing
LVG_CINDER_LVM_TYPE_THIN = 'thin'
LVG_CINDER_LVM_TYPE_THICK = 'thick'

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

# Interface definitions
NETWORK_TYPE_NONE = 'none'
NETWORK_TYPE_INFRA = 'infra'
NETWORK_TYPE_MGMT = 'mgmt'
NETWORK_TYPE_OAM = 'oam'
NETWORK_TYPE_BM = 'bm'
NETWORK_TYPE_MULTICAST = 'multicast'
NETWORK_TYPE_DATA = 'data'
NETWORK_TYPE_SYSTEM_CONTROLLER = 'system-controller'
NETWORK_TYPE_CLUSTER_HOST = 'cluster-host'
NETWORK_TYPE_CLUSTER_POD = 'cluster-pod'
NETWORK_TYPE_CLUSTER_SERVICE = 'cluster-service'

NETWORK_TYPE_PCI_PASSTHROUGH = 'pci-passthrough'
NETWORK_TYPE_PCI_SRIOV = 'pci-sriov'
NETWORK_TYPE_PXEBOOT = 'pxeboot'

PLATFORM_NETWORK_TYPES = [NETWORK_TYPE_PXEBOOT,
                          NETWORK_TYPE_MGMT,
                          NETWORK_TYPE_INFRA,
                          NETWORK_TYPE_OAM,
                          NETWORK_TYPE_CLUSTER_HOST]

PCI_NETWORK_TYPES = [NETWORK_TYPE_PCI_PASSTHROUGH,
                     NETWORK_TYPE_PCI_SRIOV]

INTERFACE_TYPE_ETHERNET = 'ethernet'
INTERFACE_TYPE_VLAN = 'vlan'
INTERFACE_TYPE_AE = 'ae'
INTERFACE_TYPE_VIRTUAL = 'virtual'

INTERFACE_CLASS_NONE = 'none'
INTERFACE_CLASS_PLATFORM = 'platform'
INTERFACE_CLASS_DATA = 'data'
INTERFACE_CLASS_PCI_PASSTHROUGH = 'pci-passthrough'
INTERFACE_CLASS_PCI_SRIOV = 'pci-sriov'

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
# varies greatly in Titanium Cloud and we want to avoid running too low on PGs
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
SERVICE_TYPE_GLANCE = 'glance'
SERVICE_TYPE_BARBICAN = 'barbican'
SERVICE_TYPE_DOCKER = 'docker'
SERVICE_TYPE_HTTP = 'http'
SERVICE_TYPE_OPENSTACK = 'openstack'

SERVICE_PARAM_SECTION_MURANO_RABBITMQ = 'rabbitmq'
SERVICE_PARAM_SECTION_MURANO_ENGINE = 'engine'

SERVICE_PARAM_SECTION_IRONIC_NEUTRON = 'neutron'
SERVICE_PARAM_SECTION_IRONIC_PXE = 'pxe'

SERVICE_PARAM_SECTION_IDENTITY_ASSIGNMENT = 'assignment'
SERVICE_PARAM_SECTION_IDENTITY_IDENTITY = 'identity'
SERVICE_PARAM_SECTION_IDENTITY_LDAP = 'ldap'
SERVICE_PARAM_SECTION_IDENTITY_CONFIG = 'config'

SERVICE_PARAM_SECTION_CINDER_DEFAULT = 'DEFAULT'
SERVICE_PARAM_CINDER_DEFAULT_VOLUME_TYPE = 'default_volume_type'
SERVICE_PARAM_CINDER_DEFAULT_MULTIPATH = 'multipath'
SERVICE_PARAM_CINDER_DEFAULT_MULTIPATH_STATE = 'multipath.state'
SERVICE_PARAM_CINDER_DEFAULT_MULTIPATH_STATE_DISABLED = 'false'

SERVICE_PARAM_SECTION_CINDER_EMC_VNX = 'emc_vnx'
SERVICE_PARAM_CINDER_EMC_VNX_ENABLED = 'enabled'
SERVICE_PARAM_SECTION_CINDER_EMC_VNX_STATE = 'emc_vnx.state'

SERVICE_PARAM_MAX_HPE3PAR = 12
SERVICE_PARAM_SECTION_CINDER_HPE3PAR = 'hpe3par'
SERVICE_PARAM_SECTION_CINDER_HPE3PAR_STATE = 'hpe3par.state'

SERVICE_PARAM_SECTION_CINDER_HPELEFTHAND = 'hpelefthand'
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

# NEUTRON Service Parameters

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

# service plugin for neutron network segment range feature
NEUTRON_PLUGIN_NETWORK_SEGMENT_RANGE = 'network_segment_range'

# a subset of Neutron service plugins that are supported
SERVICE_PARAM_NETWORK_DEFAULT_SERVICE_PLUGINS = \
    ['odl-router',
     'networking_odl.l3.l3_odl.OpenDaylightL3RouterPlugin',
     'odl-router_v2',
     'networking_odl.l3.l3_odl_v2:OpenDaylightL3RouterPlugin',
     'neutron_dynamic_routing.services.bgp.bgp_plugin.BgpPlugin',
     'networking_bgpvpn.neutron.services.plugin.BGPVPNPlugin',
     'router',
     NEUTRON_PLUGIN_NETWORK_SEGMENT_RANGE]

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

SERVICE_PARAM_SECTION_SWIFT_CONFIG = 'config'
SERVICE_PARAM_NAME_SWIFT_SERVICE_ENABLED = 'service_enabled'
SERVICE_PARAM_NAME_SWIFT_FS_SIZE_MB = 'fs_size_mb'

# docker parameters
SERVICE_PARAM_SECTION_DOCKER_PROXY = 'proxy'
SERVICE_PARAM_NAME_DOCKER_HTTP_PROXY = 'http_proxy'
SERVICE_PARAM_NAME_DOCKER_HTTPS_PROXY = 'https_proxy'
SERVICE_PARAM_NAME_DOCKER_NO_PROXY = 'no_proxy'
SERVICE_PARAM_SECTION_DOCKER_REGISTRY = 'registry'
SERVICE_PARAM_NAME_DOCKER_K8S_REGISTRY = 'k8s'
SERVICE_PARAM_NAME_DOCKER_GCR_REGISTRY = 'gcr'
SERVICE_PARAM_NAME_DOCKER_QUAY_REGISTRY = 'quay'
SERVICE_PARAM_NAME_DOCKER_DOCKER_REGISTRY = 'docker'
SERVICE_PARAM_NAME_DOCKER_REGISTRIES = 'registries'
SERVICE_PARAM_NAME_DOCKER_INSECURE_REGISTRY = 'insecure_registry'

# default filesystem size to 25 MB
SERVICE_PARAM_SWIFT_FS_SIZE_MB_DEFAULT = 25

# HTTP Service Parameters
SERVICE_PARAM_SECTION_HTTP_CONFIG = 'config'
SERVICE_PARAM_HTTP_PORT_HTTP = 'http_port'
SERVICE_PARAM_HTTP_PORT_HTTPS = 'https_port'
SERVICE_PARAM_HTTP_PORT_HTTP_DEFAULT = 8080
SERVICE_PARAM_HTTP_PORT_HTTPS_DEFAULT = 8443

# Openstack Service Parameters
SERVICE_PARAM_SECTION_OPENSTACK_HELM = 'helm'
SERVICE_PARAM_NAME_ENDPOINT_DOMAIN = "endpoint_domain"

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
CEPH_DATA_PARTITION = "4fbd7e29-9d25-41b8-afd0-062c0ceff05d"
CEPH_JOURNAL_PARTITION = "45b0969e-9b03-4f30-b4c6-b4b80ceff106"

# Partition name for those partitions deignated for PV use.
PARTITION_NAME_PV = "LVM Physical Volume"

# Partition table types.
PARTITION_TABLE_GPT = "gpt"
PARTITION_TABLE_MSDOS = "msdos"

PARTITION_MANAGE_LOCK = "partition-manage"

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
SYSINV_WRS_GRPNAME = "wrs_protected"

# This is the first report sysinv is sending to conductor since boot
SYSINV_AGENT_FIRST_REPORT = 'first_report'

# SSL configuration
CERT_TYPE_SSL = 'ssl'
SSL_CERT_DIR = "/etc/ssl/private/"
SSL_CERT_FILE = "server-cert.pem"  # pem with PK and cert
# self signed pem to get started
SSL_CERT_SS_FILE = "self-signed-server-cert.pem"
CERT_MURANO_DIR = "/etc/ssl/private/murano-rabbit"
CERT_FILE = "cert.pem"
CERT_KEY_FILE = "key.pem"
CERT_CA_FILE = "ca-cert.pem"
SSL_PEM_FILE = os.path.join(SSL_CERT_DIR, SSL_CERT_FILE)
SSL_PEM_SS_FILE = os.path.join(SSL_CERT_DIR, SSL_CERT_SS_FILE)
SSL_PEM_FILE_SHARED = os.path.join(tsc.CONFIG_PATH, SSL_CERT_FILE)

MURANO_CERT_KEY_FILE = os.path.join(CERT_MURANO_DIR, CERT_KEY_FILE)
MURANO_CERT_FILE = os.path.join(CERT_MURANO_DIR, CERT_FILE)
MURANO_CERT_CA_FILE = os.path.join(CERT_MURANO_DIR, CERT_CA_FILE)

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

SSL_CERT_CA_DIR = "/etc/ssl/certs/"
SSL_CERT_CA_FILE = os.path.join(SSL_CERT_CA_DIR, CERT_CA_FILE)
SSL_CERT_CA_FILE_SHARED = os.path.join(tsc.CONFIG_PATH, CERT_CA_FILE)

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

CERT_MODE_SSL = 'ssl'
CERT_MODE_SSL_CA = 'ssl_ca'
CERT_MODE_TPM = 'tpm_mode'
CERT_MODE_MURANO = 'murano'
CERT_MODE_MURANO_CA = 'murano_ca'
CERT_MODE_DOCKER_REGISTRY = 'docker_registry'
CERT_MODE_OPENSTACK = 'openstack'
CERT_MODE_OPENSTACK_CA = 'openstack_ca'
CERT_MODES_SUPPORTED = [CERT_MODE_SSL,
                        CERT_MODE_SSL_CA,
                        CERT_MODE_TPM,
                        CERT_MODE_MURANO,
                        CERT_MODE_MURANO_CA,
                        CERT_MODE_DOCKER_REGISTRY,
                        CERT_MODE_OPENSTACK,
                        CERT_MODE_OPENSTACK_CA,
                        ]

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
    "Guidelines for more details on supported worker configurations.")
WARNING_ROOT_PV_CINDER_CEPH_MSG = (
    "Warning: This worker must have instance_backing set to 'remote' "
    "or use a secondary disk for local storage. See Titanium Cloud System "
    "Engineering Guidelines for more details on supported worker configurations.")
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
SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_V1_OPTS = 'nopti nospectre_v2'
SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_ALL = 'spectre_meltdown_all'
SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_ALL_OPTS = ''
SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_OPTS = {
    SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_V1: SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_V1_OPTS,
    SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_ALL: SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_ALL_OPTS
}


SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_DEFAULT_OPTS = SYSTEM_SECURITY_FEATURE_SPECTRE_MELTDOWN_V1_OPTS

# Helm: Supported charts:
# These values match the names in the chart package's Chart.yaml
HELM_CHART_AODH = 'aodh'
HELM_CHART_BARBICAN = 'barbican'
HELM_CHART_CEILOMETER = 'ceilometer'
HELM_CHART_CINDER = 'cinder'
HELM_CHART_GARBD = 'garbd'
HELM_CHART_GLANCE = 'glance'
HELM_CHART_GNOCCHI = 'gnocchi'
HELM_CHART_HEAT = 'heat'
HELM_CHART_HORIZON = 'horizon'
HELM_CHART_INGRESS = 'ingress'
HELM_CHART_IRONIC = 'ironic'
HELM_CHART_KEYSTONE = 'keystone'
HELM_CHART_LIBVIRT = 'libvirt'
HELM_CHART_MAGNUM = 'magnum'
HELM_CHART_MARIADB = 'mariadb'
HELM_CHART_MEMCACHED = 'memcached'
HELM_CHART_NEUTRON = 'neutron'
HELM_CHART_NOVA = 'nova'
HELM_CHART_NOVA_API_PROXY = 'nova-api-proxy'
HELM_CHART_OPENVSWITCH = 'openvswitch'
HELM_CHART_PANKO = 'panko'
HELM_CHART_RABBITMQ = 'rabbitmq'
HELM_CHART_RBD_PROVISIONER = 'rbd-provisioner'
HELM_CHART_CEPH_POOLS_AUDIT = 'ceph-pools-audit'
HELM_CHART_HELM_TOOLKIT = 'helm-toolkit'
HELM_CHART_KEYSTONE_API_PROXY = 'keystone-api-proxy'

# Helm: Supported application (aka chart bundles)
HELM_APP_OPENSTACK = 'stx-openstack'

SUPPORTED_HELM_APP_NAMES = [
    HELM_APP_OPENSTACK
]

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
APP_SYNCED_DATA_PATH = os.path.join(tsc.PLATFORM_PATH, 'armada', tsc.SW_VERSION)
APP_METADATA_FILE = 'metadata.yaml'

# State constants
APP_UPLOAD_IN_PROGRESS = 'uploading'
APP_UPLOAD_SUCCESS = 'uploaded'
APP_UPLOAD_FAILURE = 'upload-failed'
APP_APPLY_IN_PROGRESS = 'applying'
APP_APPLY_SUCCESS = 'applied'
APP_APPLY_FAILURE = 'apply-failed'
APP_REMOVE_IN_PROGRESS = 'removing'
APP_REMOVE_FAILURE = 'remove-failed'

# Operation constants
APP_UPLOAD_OP = 'upload'
APP_APPLY_OP = 'apply'
APP_REMOVE_OP = 'remove'
APP_DELETE_OP = 'delete'

# Progress constants
APP_PROGRESS_ABORTED = 'operation aborted, check logs for detail'
APP_PROGRESS_APPLY_MANIFEST = 'applying application manifest'
APP_PROGRESS_COMPLETED = 'completed'
APP_PROGRESS_DELETE_MANIFEST = 'deleting application manifest'
APP_PROGRESS_DOWNLOAD_IMAGES = 'retrieving docker images'
APP_PROGRESS_EXTRACT_TARFILE = 'extracting application tar file'
APP_PROGRESS_GENERATE_OVERRIDES = 'generating application overrides'
APP_PROGRESS_TARFILE_DOWNLOAD = 'downloading tarfile'
APP_PROGRESS_VALIDATE_UPLOAD_CHARTS = 'validating and uploading charts'

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

# Default DNS service domain
DEFAULT_DNS_SERVICE_DOMAIN = 'cluster.local'
DEFAULT_DNS_SERVICE_IP = '10.96.0.10'

# Ansible bootstrap
ANSIBLE_BOOTSTRAP_FLAG = os.path.join(tsc.VOLATILE_PATH, ".ansible_bootstrap")
