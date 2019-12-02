#
# Copyright (c) 2019 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

from cgtsclient.common import base


class KubeHostUpgrade(base.Resource):
    def __repr__(self):
        return "<kube_host_upgrade %s>" % self._info


class KubeHostUpgradeManager(base.Manager):
    resource_class = KubeHostUpgrade

    @staticmethod
    def _path(uuid=None):
        return '/v1/kube_host_upgrades/%s' % uuid if uuid \
            else '/v1/kube_host_upgrades'

    def list(self):
        """Retrieve the list of kubernetes host upgrades known to the system."""

        return self._list(self._path(), "kube_host_upgrades")

    def get(self, uuid):
        """Retrieve the details of a given kubernetes host upgrade.

        :param uuid: uuid of kubernetes host upgrade
        """

        try:
            return self._list(self._path(uuid))[0]
        except IndexError:
            return None
