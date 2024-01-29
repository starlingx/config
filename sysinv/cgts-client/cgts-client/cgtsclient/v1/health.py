# -*- encoding: utf-8 -*-
#
# Copyright (c) 2015-2023 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


from cgtsclient.common import base


class HealthManager(base.Manager):

    def get(self):
        path = '/v1/health/'
        resp, body = self.api.json_request('GET', path)
        return body

    def get_upgrade(self, relaxed=None):
        path = '/v1/health/upgrade'
        if relaxed:
            path += '/relaxed'
        resp, body = self.api.json_request('GET', path)
        return body

    def get_kube_upgrade(self, args=None, relaxed=None):
        path = '/v1/health/kube-upgrade'
        if relaxed:
            path += '/relaxed'
        rootca = None if not args else args.get('rootca')
        if rootca:
            path += f'?rootca={rootca}'
        resp, body = self.api.json_request('GET', path)
        return body
