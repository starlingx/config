#
# Copyright (c) 2021 Wind River Systems, Inc.
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
