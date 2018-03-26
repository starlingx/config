#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base

CREATION_ATTRIBUTES = ['state', 'from_load', 'to_load']


class Upgrade(base.Resource):
    def __repr__(self):
        return "<upgrade %s>" % self._info


class UpgradeManager(base.Manager):
    resource_class = Upgrade

    @staticmethod
    def _path(upgrade_id=None):
        return '/v1/upgrade/%s' % upgrade_id if upgrade_id else '/v1/upgrade'

    def list(self):
        return self._list(self._path(), "upgrades")

    def get(self, upgrade_id):
        try:
            return self._list(self._path(upgrade_id))[0]
        except IndexError:
            return None

    def check_reinstall(self):
        path = self._path() + '/check_reinstall'
        return self._json_get(path)

    def create(self, force):
        new = {}
        new['force'] = force
        return self._create(self._path(), new)

    def delete(self):
        res, body = self.api.json_request('DELETE', self._path())
        if body:
            return self.resource_class(self, body)

    def update(self, patch):
        return self._update(self._path(), patch)
