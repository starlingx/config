# -*- encoding: utf-8 -*-
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import base


class KubeAppManager(base.Manager):
    path = '/v1/evaluate_apps_reapply/'

    def post_evaluate_apps_reapply(self, triggers):
        _, body = self.api.json_request('POST', self.path, body=triggers)
        return body
