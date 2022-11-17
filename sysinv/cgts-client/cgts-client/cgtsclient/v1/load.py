# Copyright (c) 2015-2022 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#


from cgtsclient.common import base
from cgtsclient import exc


CREATION_ATTRIBUTES = ['software_version', 'compatible_version',
                       'required_patches']

IMPORT_ATTRIBUTES = ['path_to_iso', 'path_to_sig', 'active', 'local']


class Load(base.Resource):
    def __repr__(self):
        return "<loads %s>" % self._info


class LoadManager(base.Manager):
    resource_class = Load

    def list(self):
        return self._list('/v1/loads/', "loads")

    def get(self, load_id):
        path = '/v1/loads/%s' % load_id
        try:
            return self._list(path)[0]
        except IndexError:
            return None

    def _create_load(self, load, path):
        if set(list(load.keys())) != set(CREATION_ATTRIBUTES):
            raise exc.InvalidAttribute()

        return self._create(path, load)

    def create(self, load):
        path = '/v1/loads/'
        self._create_load(load, path)

    def import_load_metadata(self, load):
        path = '/v1/loads/import_load_metadata'
        return self._create_load(load, path)

    def import_load(self, **kwargs):
        path = '/v1/loads/import_load'

        active = None
        local = False
        load_info = {}
        for (key, value) in kwargs.items():
            if key in IMPORT_ATTRIBUTES:
                if key == 'active':
                    active = value
                elif key == 'local':
                    local = value
                else:
                    load_info[key] = value
            else:
                raise exc.InvalidAttribute(key)

        if local is True:
            load_info['active'] = active
            return self._create(path, body=load_info)

        json_data = self._upload_multipart(
            path, body=load_info, data={'active': active}, check_exceptions=True)
        return self.resource_class(self, json_data)

    def delete(self, load_id):
        path = '/v1/loads/%s' % load_id
        return self._delete(path)

    def update(self, load_id, patch):
        path = '/v1/loads/%s' % load_id
        return self._update(path, patch)
