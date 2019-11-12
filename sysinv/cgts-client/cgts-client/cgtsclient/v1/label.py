#
# Copyright (c) 2018 Wind River Systems, Inc.
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

    def assign(self, host_uuid, label, parameters=None):
        return self._create(options.build_url(self._path(host_uuid), q=None, params=parameters), label)

    def remove(self, uuid):
        return self._delete(self._path(uuid))
