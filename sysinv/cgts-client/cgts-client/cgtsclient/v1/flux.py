# -*- encoding: utf-8 -*-
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import base


class FluxManager(base.Manager):
    path = '/v1/'

    def upgrade_controllers(self):
        _, response = self.api.json_request('UPDATE', f"{self.path}flux/")
        return response
