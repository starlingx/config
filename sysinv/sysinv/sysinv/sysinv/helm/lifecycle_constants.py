#
# Copyright (c) 2021,2024 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

class LifecycleConstants(object):
    """Class containing an constants.

    Use these as a common interface to pass information.
    Don't place them in the LifecycleHookInfo since that object is rpc transferred.
    """

    EXTRA = 'extra'
    MANIFEST_APPLIED = 'manifest_applied'
    APP_APPLIED = 'app_applied'
    APP_REMOVED = 'app_removed'
    RETURN_CODE = 'rc'
    EVALUATE_REAPPLY_TRIGGER = 'trigger'
    TRIGGER_CONFIGURE_REQUIRED = 'configure_required'
    TRIGGER_TYPE = 'type'
    TRIGGER_OPENSTACK_WORKER = 'openstack_worker'
    TRIGGER_DELTA_FIELDS = 'delta_fields'
    ACTION = 'action'
    APP_STATUS = 'app_status'
    FROM_APP = 'from_app'
    TO_APP = 'to_app'
    ABORTED_OP = 'aborted_op'
    FROM_APP_VERSION = 'from_app_version'
    TO_APP_VERSION = 'to_app_version'
    RELEASE = 'release'

    APP_LIFECYCLE_TIMING_PRE = 'pre'
    APP_LIFECYCLE_TIMING_STATUS = 'status'
    APP_LIFECYCLE_TIMING_POST = 'post'
    APP_LIFECYCLE_TYPE_SEMANTIC_CHECK = 'check'
    APP_LIFECYCLE_TYPE_OPERATION = 'operation'
    APP_LIFECYCLE_TYPE_RBD = 'rbd'
    APP_LIFECYCLE_TYPE_RESOURCE = 'resource'
    APP_LIFECYCLE_TYPE_MANIFEST = 'manifest'
    APP_LIFECYCLE_TYPE_FLUXCD_REQUEST = 'fluxcd-request'
    APP_LIFECYCLE_MODE_MANUAL = 'manual'
    APP_LIFECYCLE_MODE_AUTO = 'auto'
    APP_LIFECYCLE_FORCE_OPERATION = 'force'
    APP_LIFECYCLE_OPERATION_MTC_ACTION = 'mtc-action'
