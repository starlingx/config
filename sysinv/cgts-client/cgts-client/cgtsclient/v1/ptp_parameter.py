########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from cgtsclient.common import base
from cgtsclient import exc
from cgtsclient.v1 import options


CREATION_ATTRIBUTES = ['name', 'value']


class PtpParameter(base.Resource):
    def __repr__(self):
        return "<PtpParameter %s>" % self._info


class PtpParameterManager(base.Manager):
    resource_class = PtpParameter

    @staticmethod
    def _path(ptp_parameter_id=None):
        return '/v1/ptp_parameters/%s' % ptp_parameter_id if ptp_parameter_id \
            else '/v1/ptp_parameters'

    def list(self, q=None):
        return self._list(options.build_url(self._path(), q), "ptp_parameters")

    def list_by_ptp_instance(self, ptp_instance_uuid):
        path = '/v1/ptp_instances/%s/ptp_parameters' % ptp_instance_uuid
        return self._list(path, "ptp_parameters")

    def list_by_ptp_interface(self, ptp_interface_uuid):
        path = '/v1/ptp_interfaces/%s/ptp_parameters' % ptp_interface_uuid
        return self._list(path, "ptp_parameters")

    def get(self, ptp_parameter_id):
        try:
            return self._list(self._path(ptp_parameter_id))[0]
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

    def update(self, ptp_parameter_id, patch):
        return self._update(self._path(ptp_parameter_id), patch)

    def delete(self, ptp_parameter_id):
        return self._delete(self._path(ptp_parameter_id))


def _find_ptp_parameter(cc, id):
    try:
        parameter = cc.ptp_parameter.get(id)
    except exc.HTTPNotFound:
        raise exc.CommandError('PTP parameter not found: %s' % id)
    else:
        return parameter
