#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import base


class KubeVersion(base.Resource):
    def __repr__(self):
        return "<kube_version %s>" % self._info


class KubeVersionManager(base.Manager):
    resource_class = KubeVersion

    @staticmethod
    def _path(name=None):
        return '/v1/kube_versions/%s' % name if name else '/v1/kube_versions'

    def list(self):
        """Retrieve the list of kubernetes versions known to the system."""

        return self._list(self._path(), 'kube_versions')

    def get(self, version):
        """Retrieve the details of a given kubernetes version

        :param version: kubernetes version
        """
        try:
            return self._list(self._path(version))[0]
        except IndexError:
            return None
