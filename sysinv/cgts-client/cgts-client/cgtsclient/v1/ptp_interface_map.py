########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['interface_id', 'ptp_interface_id']


class PtpInterfaceMap(base.Resource):
    def __repr__(self):
        return "<PtpInterfaceMap %s>" % self._info


class PtpInterfaceMapManager(base.Manager):
    resource_class = PtpInterfaceMap

    def _path(self, ptp_interface_map_id=None):
        return '/v1/ptp_interface_maps/%s' % ptp_interface_map_id \
            if ptp_interface_map_id else '/v1/ptp_interface_maps'

    def get(self, ptp_interface_map_id):
        try:
            return self._list(self._path(ptp_interface_map_id))[0]
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

    def delete(self, ptp_interface_map_id):
        return self._delete(self._path(ptp_interface_map_id))
