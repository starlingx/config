#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import base


class KubeUpgrade(base.Resource):
    def __repr__(self):
        return "<kube_upgrade %s>" % self._info


class KubeUpgradeManager(base.Manager):
    resource_class = KubeUpgrade

    @staticmethod
    def _path(uuid=None):
        return '/v1/kube_upgrade/%s' % uuid if uuid else '/v1/kube_upgrade'

    def list(self):
        """Retrieve the list of kubernetes upgrades known to the system."""

        return self._list(self._path(), "kube_upgrades")

    def get(self, uuid):
        """Retrieve the details of a given kubernetes upgrade.

        :param uuid: uuid of upgrade
        """

        try:
            return self._list(self._path(uuid))[0]
        except IndexError:
            return None

    def create(self, to_version, force):
        """Create a new kubernetes upgrade.

        :param to_version: target kubernetes version
        :param force: ignore non management-affecting alarms
        """
        new = {}
        new['to_version'] = to_version
        new['force'] = force
        return self._create(self._path(), new)

    def delete(self):
        """Delete a kubernetes upgrade."""

        return self.api.json_request('DELETE', self._path())

    def update(self, patch):
        """Update a kubernetes upgrade."""

        return self._update(self._path(), patch)
