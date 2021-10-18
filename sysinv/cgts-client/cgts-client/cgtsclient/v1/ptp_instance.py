########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from cgtsclient.common import base
from cgtsclient.common import utils
from cgtsclient import exc
from cgtsclient.v1 import options


CREATION_ATTRIBUTES = ['name', 'service', 'host_uuid']


class PtpInstance(base.Resource):
    def __repr__(self):
        return "<PtpInstance %s>" % self._info


class PtpInstanceManager(base.Manager):
    resource_class = PtpInstance

    @staticmethod
    def _path(ptp_instance_id=None):
        return '/v1/ptp_instances/%s' % ptp_instance_id if ptp_instance_id \
            else '/v1/ptp_instances'

    def list(self, q=None):
        return self._list(options.build_url(self._path(), q), "ptp_instances")

    def list_by_host(self, ihost_uuid):
        path = '/v1/ihosts/%s/ptp_instances' % ihost_uuid
        return self._list(path, "ptp_instances")

    def get(self, ptp_instance_id):
        try:
            return self._list(self._path(ptp_instance_id))[0]
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

    def delete(self, ptp_instance_id):
        return self._delete(self._path(ptp_instance_id))


def _find_ptp_instance(cc, key):
    if key.isdigit() or utils.is_uuid_like(key):
        try:
            instance = cc.ptp_instance.get(key)
        except exc.HTTPNotFound:
            raise exc.CommandError('PTP instance not found: %s' % key)
        else:
            return instance
    else:
        ptp_instances = cc.ptp_instance.list()
        for instance in ptp_instances[:]:
            if instance.name == key:
                return instance
        else:
            raise exc.CommandError('PTP instance not found: %s' % key)
