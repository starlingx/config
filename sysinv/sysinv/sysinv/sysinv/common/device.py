#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# PCI Device Class ID in hexidecimal string
PCI_DEVICE_CLASS_FPGA = '120000'

# Device Image
DEVICE_IMAGE_TMP_PATH = '/tmp/device_images'
DEVICE_IMAGE_PATH = '/opt/platform/device_images'

BITSTREAM_TYPE_ROOT_KEY = 'root-key'
BITSTREAM_TYPE_FUNCTIONAL = 'functional'
BITSTREAM_TYPE_KEY_REVOCATION = 'key-revocation'

# Device Image Status
DEVICE_IMAGE_UPDATE_PENDING = 'pending'
DEVICE_IMAGE_UPDATE_IN_PROGRESS = 'in-progress'
DEVICE_IMAGE_UPDATE_IN_PROGRESS_ABORTED = 'in-progress-aborted'
DEVICE_IMAGE_UPDATE_COMPLETED = 'completed'
DEVICE_IMAGE_UPDATE_FAILED = 'failed'
DEVICE_IMAGE_UPDATE_NULL = ''

# Device Image Action
APPLY_ACTION = 'apply'
REMOVE_ACTION = 'remove'
