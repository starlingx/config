#
# Copyright (c) 2020 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base


class RestoreManager(base.Manager):
    path = '/v1/restore'

    def get(self):
        return self._json_get(self.path, {})

    def start(self):
        _, body = self.api.json_request('PATCH', self.path, body={'action': 'start'})
        return body

    def complete(self):
        _, body = self.api.json_request('PATCH', self.path, body={'action': 'complete'})
        return body
