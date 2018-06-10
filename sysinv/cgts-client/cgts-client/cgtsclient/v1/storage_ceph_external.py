#
# Copyright (c) 2018 Wind River Systems, Inc.
#
# SPDX-License-Identifier: Apache-2.0
#
# -*- encoding: utf-8 -*-
#

from cgtsclient.common import base
from cgtsclient import exc
import os

CREATION_ATTRIBUTES = ['confirmed', 'name', 'services', 'capabilities',
                       'ceph_conf']
DISPLAY_ATTRIBUTES = ['ceph_conf']
PATCH_ATTRIBUTES = ['ceph_conf']


class StorageCephExternal(base.Resource):
    def __repr__(self):
        return "<storage_ceph_external %s>" % self._info


class StorageCephExternalManager(base.Manager):
    resource_class = StorageCephExternal

    @staticmethod
    def _path(id=None):
        return ('/v1/storage_ceph_external/%s' % id
                if id else '/v1/storage_ceph_external')

    def list(self):
        return self._list(self._path(), "storage_ceph_external")

    def get(self, stor_ceph_external_id=None):
        try:
            if stor_ceph_external_id:
                return self._list(self._path(stor_ceph_external_id))[0]
            else:
                return self._list(self._path(), "storage_ceph_external")[0]
        except IndexError:
            return None

    def upload_file(self, parm):
        # Upload the ceph config file
        ceph_conf_file = parm.get('ceph_conf', None)
        if not ceph_conf_file:
            raise exc.CommandError('A Ceph configuration file must be provided '
                                   'for provisioning an external Ceph backend.')
        try:
            c_c_f = open(ceph_conf_file, 'rb')
        except Exception:
            raise exc.CommandError("Error: Could not open file %s." %
                                   ceph_conf_file)

        data = {"ceph_conf_fn": os.path.basename(ceph_conf_file)}
        try:
            resp = self._upload(self._path("ceph_conf_upload"), c_c_f, data=data)
            error = resp.get('error')
            if error:
                raise exc.CommandError("%s" % error)
        except exc.HTTPNotFound:
            raise exc.CommandError('Cannot upload ceph config file. No response.')

    def create(self, **kwargs):
        new = {}
        for (key, value) in kwargs.items():
            if key in CREATION_ATTRIBUTES:
                new[key] = value
            else:
                raise exc.InvalidAttribute('%s' % key)

        self.upload_file(new)

        ceph_conf_file = new.get('ceph_conf', None)
        new.update({'ceph_conf': os.path.basename(ceph_conf_file)})

        return self._create(self._path(), new)

    def delete(self, stor_ceph_external_id):
        return self._delete(self._path(stor_ceph_external_id))

    def update(self, stor_ceph_external_id, patch):
        ceph_config_filename = None
        for item in patch:
            if item.get('path') == '/ceph_conf':
                ceph_config_filename = item.get('value')
                item['value'] = os.path.basename(ceph_config_filename)
                break
        if ceph_config_filename:
            self.upload_file({'ceph_conf': ceph_config_filename})

        return self._update(self._path(stor_ceph_external_id), patch)
