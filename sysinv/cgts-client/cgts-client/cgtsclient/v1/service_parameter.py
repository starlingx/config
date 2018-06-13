#
# Copyright (c) 2015 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#

# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient.v1 import options


class ServiceParameter(base.Resource):
    def __repr__(self):
        return "<ServiceParameter %s>" % self._info


class ServiceParameterManager(base.Manager):
    resource_class = ServiceParameter

    @staticmethod
    def _path(parameter_id=None):
        return '/v1/service_parameter/%s' % parameter_id if parameter_id else \
            '/v1/service_parameter'

    def list(self, q=None):
        return self._list(options.build_url(self._path(), q), "parameters")

    def get(self, parameter_id):
        try:
            return self._list(self._path(parameter_id))[0]
        except IndexError:
            return None

    def create(self, service, section, personality, resource, parameters):
        body = {'service': service,
                'section': section,
                'personality': personality,
                'resource': resource,
                'parameters': parameters}
        return self._create(self._path(), body)

    def delete(self, parameter_id):
        return self._delete(self._path(parameter_id))

    def update(self, parameter_id, patch):
        return self._update(self._path(parameter_id), patch)

    def apply(self, service):
        new = {}
        new['service'] = service
        return self.api.json_request('POST', self._path() + "/apply", body=new)
