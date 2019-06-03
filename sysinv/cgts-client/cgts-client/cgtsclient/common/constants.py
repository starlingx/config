#
# Copyright (c) 2013-2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# vim: tabstop=4 shiftwidth=4 softtabstop=4
# coding=utf-8
#

# Upgrade states
UPGRADE_ACTIVATION_REQUESTED = 'activation-requested'
UPGRADE_ABORTING = 'aborting'

# system type
TS_STD = "Standard"
TS_AIO = "All-in-one"

# system mode
SYSTEM_MODE_DUPLEX = "duplex"
SYSTEM_MODE_DUPLEX_DIRECT = "duplex-direct"
SYSTEM_MODE_SIMPLEX = "simplex"

# controller names, copy from sysinv.constants,
# refer to sysinv.constants when possible currently
# there is no dependency between cgtsclient and sysinv
CONTROLLER_HOSTNAME = 'controller'
CONTROLLER_0_HOSTNAME = '%s-0' % CONTROLLER_HOSTNAME
CONTROLLER_1_HOSTNAME = '%s-1' % CONTROLLER_HOSTNAME

# Storage backends supported
SB_TYPE_FILE = 'file'
SB_TYPE_LVM = 'lvm'
SB_TYPE_CEPH = 'ceph'
SB_TYPE_CEPH_EXTERNAL = 'ceph-external'
SB_TYPE_EXTERNAL = 'external'

SB_SUPPORTED = [SB_TYPE_FILE, SB_TYPE_LVM, SB_TYPE_CEPH, SB_TYPE_CEPH_EXTERNAL,
                SB_TYPE_EXTERNAL]
# Storage backend state
SB_STATE_CONFIGURED = 'configured'
SB_STATE_CONFIGURING = 'configuring'

# Storage backend tasks
SB_TASK_NONE = None
SB_TASK_PROVISION_STORAGE = 'provision-storage'
SB_TASK_RECONFIG_WORKER = 'reconfig-worker'
SB_TASK_RESIZE_CEPH_MON_LV = 'resize-ceph-mon-lv'
SB_TASK_ADD_OBJECT_GATEWAY = 'add-object-gateway'

# Profiles
PROFILE_TYPE_CPU = 'cpu'
PROFILE_TYPE_INTERFACE = 'if'
PROFILE_TYPE_STORAGE = 'stor'
PROFILE_TYPE_MEMORY = 'memory'
PROFILE_TYPE_LOCAL_STORAGE = 'localstg'

# Board Management Region Info
REGION_PRIMARY = "Internal"
REGION_SECONDARY = "External"


# Disk Partitions: From sysinv constants
# User creatable disk partitions, system managed,  GUID partitions types
PARTITION_USER_MANAGED_GUID_PREFIX = "ba5eba11-0000-1111-2222-"
USER_PARTITION_PHYSICAL_VOLUME = (PARTITION_USER_MANAGED_GUID_PREFIX +
                                  "000000000001")

# Size conversion types
KiB = 1
MiB = 2
GiB = 3
TiB = 4
PiB = 5

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
# The creation of the partition has encounter a known error.
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

# Partition table types.
PARTITION_TABLE_GPT = "gpt"
PARTITION_TABLE_MSDOS = "msdos"
