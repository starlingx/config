########################################################################
#
# Copyright (c) 2021 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
########################################################################

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['parameter_uuid', 'owner_uuid']


class PtpParameterOwnership(base.Resource):
    def __repr__(self):
        return "<PtpParameterOwnership %s>" % self._info


class PtpParameterOwnershipManager(base.Manager):
    resource_class = PtpParameterOwnership

    def _path(self, ptp_paramownership_id=None):
        return '/v1/ptp_parameter_ownerships/%s' % ptp_paramownership_id \
            if ptp_paramownership_id else '/v1/ptp_parameter_ownerships'

    def get(self, ptp_paramownership_id):
        try:
            return self._list(self._path(ptp_paramownership_id))[0]
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

    def delete(self, ptp_paramownership_id):
        return self._delete(self._path(ptp_paramownership_id))
