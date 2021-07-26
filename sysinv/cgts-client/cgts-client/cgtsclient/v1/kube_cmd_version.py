#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import base


class KubeCmdVersion(base.Resource):
    def __repr__(self):
        return "<kube_cmd_version %s>" % self._info


class KubeCmdVersionManager(base.Manager):
    resource_class = KubeCmdVersion

    @staticmethod
    def _path():
        return '/v1/kube_cmd_versions'

    def get(self):
        try:
            return self._list(self._path())[0]
        except IndexError:
            return None

    def update(self, patch):
        return self._update(self._path(), patch)
