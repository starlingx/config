# -*- encoding: utf-8 -*-
#
# Copyright (c) 2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import base


class KubeAppManager(base.Manager):
    path = '/v1/'

    def post_evaluate_apps_reapply(self, triggers):
        _, body = self.api.json_request('POST', f"{self.path}evaluate_apps_reapply/", body=triggers)
        return body

    def update_all(self):
        return self.api.json_request('POST', f"{self.path}apps/update_all/")

    def get_apps_update_status(self):
        _, response = self.api.json_request('GET', f"{self.path}apps/get_apps_update_status/")
        return response

    def rollback_all_apps(self):
        return self.api.json_request('POST', f"{self.path}apps/rollback_all_apps/")

    def get_all_apps_by_status(self, status):
        _, response = self.api.json_request(
            'GET', f'{self.path}apps/get_all_apps_by_status' + '?status=' + status)
        return response
