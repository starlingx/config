#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# All Rights Reserved.
#

""" System inventory AppLifecycle operator."""

from oslo_log import log as logging
from sysinv.helm import lifecycle_base as base

LOG = logging.getLogger(__name__)


class GenericAppLifecycleOperator(base.AppLifecycleOperator):
    def app_lifecycle_actions(self, context, conductor_obj, app_op, app, hook_info):
        """ Perform lifecycle actions for an operation

        :param context: request context
        :param conductor_obj: conductor object
        :param app_op: AppOperator object
        :param app: AppOperator.Application object
        :param hook_info: LifecycleHookInfo object

        """
        # An implementing class MUST call the base function to inherit the default behaviour
        super(GenericAppLifecycleOperator, self).app_lifecycle_actions(context, conductor_obj, app_op, app, hook_info)
