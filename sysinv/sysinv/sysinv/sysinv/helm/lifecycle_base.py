#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" System inventory AppLifecycle operator."""

import abc

import six
from oslo_log import log as logging
from sysinv.common import constants
from sysinv.common import exception
from sysinv.helm import lifecycle_utils as lifecycle_utils
from sysinv.helm.lifecycle_constants import LifecycleConstants


LOG = logging.getLogger(__name__)


@six.add_metaclass(abc.ABCMeta)
class AppLifecycleOperator(object):
    def app_lifecycle_actions(self, context, conductor_obj, app_op, app, hook_info):
        """ Perform lifecycle actions for an operation

        :param context: request context
        :param conductor_obj: conductor object
        :param app_op: AppOperator object
        :param app: AppOperator.Application object
        :param hook_info: LifecycleHookInfo object

        """

        # Semantic checks
        if hook_info.lifecycle_type == LifecycleConstants.APP_LIFECYCLE_TYPE_SEMANTIC_CHECK:
            if hook_info.mode == LifecycleConstants.APP_LIFECYCLE_MODE_AUTO and \
                    hook_info.operation == constants.APP_APPLY_OP and \
                    hook_info.relative_timing == LifecycleConstants.APP_LIFECYCLE_TIMING_PRE:
                raise exception.LifecycleSemanticCheckException(
                    "Automatic apply is disabled for %s." % app.name)
            elif hook_info.mode == LifecycleConstants.APP_LIFECYCLE_MODE_AUTO and \
                    hook_info.operation == constants.APP_EVALUATE_REAPPLY_OP:
                # To reject the reapply evaluation an app can override this
                # hook and raise exception.LifecycleSemanticCheckException
                pass
            # Check if operation is a delete or remove operation
            elif (hook_info.operation in [constants.APP_DELETE_OP,
                    constants.APP_REMOVE_OP]) and \
                        not hook_info.extra['force']:
                try:
                    # Store the forbidden operations in a list
                    forbidden = conductor_obj.apps_metadata[
                        constants.APP_METADATA_APPS][app.name][
                        constants.APP_METADATA_BEHAVIOR][
                        constants.APP_METADATA_FORBIDDEN_MANUAL_OPERATIONS]
                except KeyError:
                    pass
                else:
                    # Check if it is a forbidden operation
                    if hook_info.operation in forbidden:
                        raise exception.LifecycleSemanticCheckOpererationBlocked(
                            op=hook_info.operation.capitalize(),
                            app=app.name)

        # TODO(dvoicule) remove once each app has its lifecycle operator and takes care of its rbd
        # this is here to keep the same functionality while decoupling
        # Rbd
        elif hook_info.lifecycle_type == LifecycleConstants.APP_LIFECYCLE_TYPE_RBD:
            if hook_info.operation == constants.APP_APPLY_OP and \
                    hook_info.relative_timing == LifecycleConstants.APP_LIFECYCLE_TIMING_PRE:
                lifecycle_utils.create_rbd_provisioner_secrets(app_op, app, hook_info)
            elif hook_info.operation == constants.APP_REMOVE_OP and \
                    hook_info.relative_timing == LifecycleConstants.APP_LIFECYCLE_TIMING_POST:
                lifecycle_utils.delete_rbd_provisioner_secrets(app_op, app, hook_info)

        # TODO(dvoicule) remove once each app has its lifecycle operator and takes care of its resources
        # this is here to keep the same functionality while decoupling
        # Resources
        elif hook_info.lifecycle_type == LifecycleConstants.APP_LIFECYCLE_TYPE_RESOURCE:
            if hook_info.operation == constants.APP_APPLY_OP and \
                    hook_info.relative_timing == LifecycleConstants.APP_LIFECYCLE_TIMING_PRE:
                lifecycle_utils.create_local_registry_secrets(app_op, app, hook_info)
                lifecycle_utils.add_pod_security_admission_controller_labels(app_op, app, hook_info)
            elif hook_info.operation == constants.APP_REMOVE_OP and \
                    hook_info.relative_timing == LifecycleConstants.APP_LIFECYCLE_TIMING_POST:
                lifecycle_utils.delete_local_registry_secrets(app_op, app, hook_info)
