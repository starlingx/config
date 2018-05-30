# -*- encoding: utf-8 -*-
# Copyright (c) 2014 Wind River Systems, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['root_sig', 'passwd_expiry_days', 'passwd_hash', 'forisystemid']


class iuser(base.Resource):
    def __repr__(self):
        return "<iuser %s>" % self._info


class iuserManager(base.Manager):
    resource_class = iuser

    @staticmethod
    def _path(id=None):
        return '/v1/iuser/%s' % id if id else '/v1/iuser'

    def list(self):
        return self._list(self._path(), "iusers")

    def get(self, iuser_id):
        try:
            return self._list(self._path(iuser_id))[0]
        except IndexError:
            return None

    def create(self, **kwargs):
        # path = '/v1/iuser'
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)
        return self._create(self._path(), new)

    def delete(self, iuser_id):
        # path = '/v1/iuser/%s' % iuser_id
        return self._delete(self._path(iuser_id))

    def update(self, iuser_id, patch):
        # path = '/v1/iuser/%s' % iuser_id
        return self._update(self._path(iuser_id), patch)
