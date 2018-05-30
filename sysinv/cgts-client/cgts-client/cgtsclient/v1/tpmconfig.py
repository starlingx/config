#
# Copyright (c) 2017 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc

CREATION_ATTRIBUTES = ['cert_path', 'public_path', 'tpm_path']


class TpmConfig(base.Resource):
    def __repr__(self):
        return "<tpmconfig %s>" % self._info


class TpmConfigManager(base.Manager):
    resource_class = TpmConfig

    @staticmethod
    def _path(id=None):
        return '/v1/tpmconfig/%s' % id if id else '/v1/tpmconfig'

    def list(self):
        return self._list(self._path(), "tpmconfigs")

    def get(self, tpmconfig_id):
        try:
            return self._list(self._path(tpmconfig_id))[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(self._path(), new)

    def delete(self, tpmconfig_id):
        return self._delete(self._path(tpmconfig_id))

    def update(self, tpmconfig_id, patch):
        return self._update(self._path(tpmconfig_id), patch)
