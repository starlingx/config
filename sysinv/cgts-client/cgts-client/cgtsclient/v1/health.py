# -*- encoding: utf-8 -*-
#
# Copyright (c) 2015-2026 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


from six.moves import urllib

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
        args = args or {}
        params = [(name, args[name])
                  for name in ('rootca', 'alarm_ignore_list',
                               'use_default_ignore_list')
                  if args.get(name)]
        if params:
            path += '?' + urllib.parse.urlencode(params)
        resp, body = self.api.json_request('GET', path)
        return body
