#
# Copyright (c) 2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import base


class KubeConfigKubelet(base.Resource):
    def __repr__(self):
        return "<kube_config_kubelet %s>" % self._info


class KubeConfigKubeletManager(base.Manager):
    resource_class = KubeConfigKubelet

    @staticmethod
    def _path(id=None):
        return '/v1/kube_config_kubelet/%s' % id if id \
            else '/v1/kube_config_kubelet'

    def apply(self):
        path = self._path("apply")
        _, body = self.api.json_request('POST', path)
        return body
