#
# Copyright (c) 2018,2025 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient.v1 import options


class KubernetesLabel(base.Resource):
    def __repr__(self):
        return "<KubernetesLabel %s>" % self._info


class KubernetesLabelManager(base.Manager):
    resource_class = KubernetesLabel

    @staticmethod
    def _path(label_id=None):
        return '/v1/labels/%s' % label_id if label_id else \
            '/v1/labels'

    def list(self, ihost_id):
        path = '/v1/ihosts/%s/labels' % ihost_id
        return self._list(path, "labels")

    def get(self, label_id):
        path = '/v1/labels/%s' % label_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def _assign(self, url, body):
        _, body = self.api.json_request('POST', url, body=body)

        if not body:
            return None

        body = body.get('labels', body)
        if not isinstance(body, list):
            return self.resource_class(self, body)  # noqa pylint: disable=not-callable

        resources = []
        for item in body:
            resources.append(self.resource_class(self, item))  # noqa pylint: disable=not-callable

        return resources

    def assign(self, host_uuid, label, parameters=None):
        url = options.build_url(
            self._path(host_uuid),
            q=None,
            params=parameters)
        return self._assign(url, label)

    def remove(self, uuid):
        return self._delete(self._path(uuid))
