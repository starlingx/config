# -*- encoding: utf-8 -*-
#
# Copyright (c) 2015-2016 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


from cgtsclient.common import base


class HealthManager(base.Manager):

    def get(self):
        path = '/v1/health/'
        resp, body = self.api.json_request('GET', path)
        return body

    def get_upgrade(self):
        path = '/v1/health/upgrade'
        resp, body = self.api.json_request('GET', path)
        return body

    def get_kube_upgrade(self):
        path = '/v1/health/kube-upgrade'
        resp, body = self.api.json_request('GET', path)
        return body
