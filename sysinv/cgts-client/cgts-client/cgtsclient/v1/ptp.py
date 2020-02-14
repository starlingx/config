########################################################################
#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = []


class ptp(base.Resource):
    def __repr__(self):
        return "<ptp %s>" % self._info


class ptpManager(base.Manager):
    resource_class = ptp

    @staticmethod
    def _path(id=None):
        return '/v1/ptp/%s' % id if id else '/v1/ptp'

    def list(self):
        return self._list(self._path(), "ptps")

    def get(self, ptp_id):
        try:
            return self._list(self._path(ptp_id))[0]
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

    def delete(self, ptp_id):
        return self._delete(self._path(ptp_id))

    def update(self, ptp_id, patch):
        return self._update(self._path(ptp_id), patch)

    def apply(self):
        return self.api.json_request('POST', self._path() + "/apply")
