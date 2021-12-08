########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['host_id', 'ptp_instance_id']


class PtpInstanceMap(base.Resource):
    def __repr__(self):
        return "<PtpInstanceMap %s>" % self._info


class PtpInstanceMapManager(base.Manager):
    resource_class = PtpInstanceMap

    def _path(self, ptp_instance_map_id=None):
        return '/v1/ptp_instance_maps/%s' % ptp_instance_map_id \
            if ptp_instance_map_id else '/v1/ptp_instance_maps'

    def get(self, ptp_instance_map_id):
        try:
            return self._list(self._path(ptp_instance_map_id))[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        data = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                data[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(self._path(), data)

    def delete(self, ptp_instance_map_id):
        return self._delete(self._path(ptp_instance_map_id))
